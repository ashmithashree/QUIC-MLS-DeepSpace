use std::{net::SocketAddr, sync::Arc, sync::Mutex};

use mls_rs::{
    identity::{basic::{BasicCredential, BasicIdentityProvider}, SigningIdentity},
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, ExtensionList,
};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;
use quic_mls::{
    MlsClientConfig, MlsServerConfig, ExportSecret, CommitLog, CommitSink, PreambleSocket,
    run_report_sender, run_report_receiver, apply_commit_window, CommitWindowError,
    ControlMessage, write_message,
};
use quinn::{AsyncUdpSocket, ClientConfig, Endpoint, EndpointConfig, ServerConfig};
use std::sync::atomic::AtomicBool;

const CS: CipherSuite = CipherSuite::CURVE25519_AES128;
// Initialize tracing for logging
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
}
// Helper function to create a client with a given name and a new key package.
fn make_client(name: &str) -> Client<impl mls_rs::client_builder::MlsConfig> {
    let crypto = RustCryptoProvider::new();
    let cs_provider = crypto.cipher_suite_provider(CS).unwrap();
    let (secret_key, public_key) = cs_provider.signature_key_generate().unwrap();
    let credential = BasicCredential::new(name.as_bytes().to_vec()).into_credential();
    let signing_identity = SigningIdentity::new(credential, public_key);
    Client::builder()
        .crypto_provider(RustCryptoProvider::new())
        .identity_provider(BasicIdentityProvider::new())
        .signing_identity(signing_identity, secret_key, CS)
        .build()
}
//---------------------------------------Shared test helpers---------------------------------------------

/// Creates a committed two-party MLS session and returns the raw group objects.
/// Alice creates the group; Bob joins via the Welcome.
fn make_mls_groups() -> (impl ExportSecret + 'static, impl ExportSecret + 'static) {
    let alice = make_client("alice");
    let bob   = make_client("bob");
    let mut alice_group = alice.create_group(ExtensionList::new(), ExtensionList::new(), None).unwrap();
    let bob_kp = bob.generate_key_package_message(ExtensionList::new(), ExtensionList::new(), None).unwrap();
    let commit_out = alice_group.commit_builder().add_member(bob_kp).unwrap().build().unwrap();
    alice_group.apply_pending_commit().unwrap();
    let (bob_group, _) = bob.join_group(None, &commit_out.welcome_messages[0], None).unwrap();
    (alice_group, bob_group)
}

/// Builds the QUIC server endpoint and client config from already-wrapped MLS groups.
/// The caller retains the Arc handles; this function clones them into the crypto configs.
fn make_quic_pair<A, B>(
    alice_group: &Arc<Mutex<A>>,
    bob_group: &Arc<Mutex<B>>,
) -> (Endpoint, SocketAddr, ClientConfig)
where
    A: ExportSecret + 'static,
    B: ExportSecret + 'static,
{
    let server_config = ServerConfig::with_crypto(Arc::new(MlsServerConfig::new(
        Box::new(Arc::clone(bob_group)),
    )));
    let client_config = ClientConfig::new(Arc::new(MlsClientConfig::new(Box::new(Arc::clone(alice_group)))));
    let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_addr = server.local_addr().unwrap();
    (server, server_addr, client_config)
}

fn make_commit_For_Alice(alice_group: &Arc<Mutex<CommitLog<impl ExportSecret + 'static>>>, commit_count: usize)
{
    for _ in 0..commit_count {
        alice_group.lock().unwrap().create_commit().unwrap();
    }
}

// `PreambleSocket`'s marker relies on the QUIC fixed bit never being greased
// off -- see preamble.rs's module docs. Required on both endpoints wherever
// a PreambleSocket is used, mirroring testbed-runner's own helper.
fn endpoint_config_without_quic_bit_greasing() -> EndpointConfig {
    let mut cfg = EndpointConfig::default();
    cfg.grease_quic_bit(false);
    cfg
}

/// Builds a preamble-capable QUIC pair: Bob's endpoint wraps a real UDP
/// socket in a `PreambleSocket` whose sink applies an incoming commit window
/// directly to `bob_group` and republishes `local_epoch` on the returned
/// watch channel (mirroring run_bob's `epoch_tx`/`sink` wiring in
/// testbed-runner). Alice's endpoint gets the concrete `PreambleSocket`
/// handle back so tests can call `send_preamble` directly, exactly as
/// run_alice does for every commit window now (steady state and blackout
/// recovery alike -- there is no other path in the unified design).
async fn make_preamble_pair<A, B>(
    alice_group: &Arc<Mutex<CommitLog<A>>>,
    bob_group: &Arc<Mutex<B>>,
) -> (
    Endpoint,
    Arc<PreambleSocket>,
    ClientConfig,
    Endpoint,
    SocketAddr,
    Arc<Mutex<u64>>,
    tokio::sync::watch::Receiver<u64>,
)
where
    A: ExportSecret + 'static,
    B: ExportSecret + 'static,
{
    let local_epoch = Arc::new(Mutex::new(0u64));
    let (epoch_tx, epoch_rx) = tokio::sync::watch::channel(0u64);

    let sink: CommitSink = {
        let bob_group = Arc::clone(bob_group);
        let local_epoch = Arc::clone(&local_epoch);
        let epoch_tx = epoch_tx.clone();
        Arc::new(move |window: &[(u64, Vec<u8>)]| {
            let (new_epoch, changed) = {
                let mut group = bob_group.lock().unwrap();
                let mut epoch = local_epoch.lock().unwrap();
                let before = *epoch;
                let _ = apply_commit_window(&mut *group, window, &mut epoch);
                (*epoch, *epoch != before)
            };
            if changed {
                epoch_tx.send_replace(new_epoch);
            }
        })
    };

    let server_config = ServerConfig::with_crypto(Arc::new(MlsServerConfig::new(
        Box::new(Arc::clone(bob_group)),
    )));
    let client_config = ClientConfig::new(Arc::new(MlsClientConfig::new(Box::new(Arc::clone(alice_group)))));

    let bob_io = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let bob_preamble: Arc<dyn AsyncUdpSocket> = Arc::new(PreambleSocket::new(bob_io, Some(sink)));
    let bob_endpoint = Endpoint::new_with_abstract_socket(
        endpoint_config_without_quic_bit_greasing(),
        Some(server_config),
        bob_preamble,
        quinn::default_runtime().expect("tokio runtime available"),
    ).unwrap();
    let bob_addr = bob_endpoint.local_addr().unwrap();

    let alice_io = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let alice_preamble = Arc::new(PreambleSocket::new(alice_io, None));
    let alice_endpoint = Endpoint::new_with_abstract_socket(
        endpoint_config_without_quic_bit_greasing(),
        None,
        Arc::clone(&alice_preamble) as Arc<dyn AsyncUdpSocket>,
        quinn::default_runtime().expect("tokio runtime available"),
    ).unwrap();

    (alice_endpoint, alice_preamble, client_config, bob_endpoint, bob_addr, local_epoch, epoch_rx)
}

/// Polls `commit_log`'s checkpoint until it reaches `target` or `timeout`
/// elapses. Report is picked up opportunistically now (never awaited
/// synchronously -- see run_report_receiver), so tests observe its effect
/// by polling rather than by a single blocking call.
async fn wait_until_checkpoint<G: ExportSecret>(
    commit_log: &Arc<Mutex<CommitLog<G>>>,
    target: u64,
    timeout: std::time::Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if commit_log.lock().unwrap().checkpoint() >= target {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

//---------------------------------------Integration tests for QUIC-MLS---------------------------------------------

// This test demonstrates a full QUIC-MLS connection. The client sends a message, and the server echoes it back to the client.
#[tokio::test]
async fn quic_mls_loopback_echo() {
    init_tracing();
    let alice = make_client("alice");
    let bob = make_client("bob");

    let mut alice_group = alice.create_group(ExtensionList::new(), ExtensionList::new(), None).unwrap();
    let bob_kp = bob.generate_key_package_message(ExtensionList::new(), ExtensionList::new(), None).unwrap();
    let commit_out = alice_group.commit_builder().add_member(bob_kp).unwrap().build().unwrap();
    alice_group.apply_pending_commit().unwrap();
    let (bob_group, _) = bob.join_group(None, &commit_out.welcome_messages[0], None).unwrap();

    let server_config = ServerConfig::with_crypto(Arc::new(MlsServerConfig::new(
        Box::new(bob_group),
    )));
    let client_config = ClientConfig::new(Arc::new(MlsClientConfig::new(Box::new(alice_group))));

    let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_addr = server.local_addr().unwrap();

    tokio::spawn(async move {
        let incoming = server.accept().await.expect("client connected");
        let conn = incoming.await.expect("handshake completed");
        let (mut send, mut recv) = conn.accept_bi().await.expect("client opened a stream");
        let data = recv.read_to_end(1 << 16).await.expect("read request");
        send.write_all(&data).await.expect("write response");
        send.finish().expect("finish response stream");
        conn.closed().await;
    });

    let mut endpoint = Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    endpoint.set_default_client_config(client_config);

    let conn = endpoint.connect(server_addr, "localhost").unwrap().await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(b"Hello, QUIC-MLS!").await.unwrap();
    send.finish().unwrap();

    let response = recv.read_to_end(64).await.unwrap();
    println!("Echo: {}", String::from_utf8_lossy(&response));
    assert_eq!(response, b"Hello, QUIC-MLS!");
}

// This test demonstrates a full QUIC-MLS connection with a rekey operation. 
//The client sends a message, then performs a rekey, and sends another message. 
//The server echoes both messages back to the client. With control stream, the client can send a commit window to the server, and the server can apply it to its group state and send back a report. 
//The client can then trim its commit log based on the report. This ensures that both sides are in sync after the rekey operation.
#[tokio::test]
async fn quic_mls_loopback_echo_with_rekey() {
    init_tracing();
    let (alice_raw, bob_raw) = make_mls_groups();
    let alice_group = Arc::new(Mutex::new(CommitLog::new(alice_raw)));
    let bob_group   = Arc::new(Mutex::new(bob_raw));
    let (alice_endpoint, alice_preamble, client_config, bob_endpoint, bob_addr, _bob_local_epoch, bob_epoch_rx) =
        make_preamble_pair(&alice_group, &bob_group).await;

    tokio::spawn(async move {
        let incoming = bob_endpoint.accept().await.expect("client connected");
        let conn = incoming.await.expect("handshake completed");
        //First bi stream is always the control stream -- Report only now,
        //the commit window itself arrives as a preamble datagram.
        let (ctrl_send, _ctrl_recv) = conn.accept_bi().await.expect("control stream");
        let always_report = Arc::new(AtomicBool::new(true));
        tokio::spawn(run_report_sender(ctrl_send, bob_epoch_rx, always_report));
        //echo loop for all application data stream.
        while let Ok((mut send, mut recv)) = conn.accept_bi().await {
            let data = recv.read_to_end(1 << 16).await.expect("read request");
            send.write_all(&data).await.expect("write response");
            send.finish().expect("finish response stream");
        }
    });
    // client connection endpoint
    let conn = alice_endpoint.connect_with(client_config, bob_addr, "localhost").unwrap().await.unwrap();
    let (mut ctrl_send, ctrl_recv) = conn.open_bi().await.unwrap();
    write_message(&mut ctrl_send, &ControlMessage::Hello).await.unwrap();
    tokio::spawn(run_report_receiver(Arc::clone(&alice_group), ctrl_recv));

    //pre-rekey echo
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(b"Hello, QUIC-MLS!").await.unwrap();
    send.finish().unwrap();
    //check that the echo response matches the sent message
    let response = recv.read_to_end(64).await.unwrap();
    println!("Echo: {}", String::from_utf8_lossy(&response));
    assert_eq!(response, b"Hello, QUIC-MLS!");
    // Create a commit and fire the window as a preamble datagram -- never
    // awaited, per the unified send-never-blocks invariant. force_key_update
    // proceeds immediately; Report (and the resulting trim) lands whenever
    // Bob's run_report_sender gets to it, asserted separately below.
    make_commit_For_Alice(&alice_group, 1);
    let window = alice_group.lock().unwrap().window_bytes();
    alice_preamble.send_preamble(bob_addr, &window, usize::MAX).await.unwrap();
    //update the keys in connection
    conn.force_key_update();
    //post-rekey echo
    let (mut send2, mut recv2) = conn.open_bi().await.unwrap();
    send2.write_all(b"Hello again, QUIC-MLS!").await.unwrap();
    send2.finish().unwrap();
    let response2 = recv2.read_to_end(64).await.unwrap();
    println!("Echo after rekey: {}", String::from_utf8_lossy(&response2));
    assert_eq!(response2, b"Hello again, QUIC-MLS!");

    assert!(
        wait_until_checkpoint(&alice_group, 1, std::time::Duration::from_secs(5)).await,
        "Bob's Report must eventually trim Alice's commit log"
    );
}
use tokio::time::Duration;
#[tokio::test]
async fn quic_mls_loopback_echo_rekey_multiple_times()
{
    init_tracing();
    let (alice_raw, bob_raw) = make_mls_groups();
    let alice_group = Arc::new(Mutex::new(CommitLog::new(alice_raw)));
    let bob_group   = Arc::new(Mutex::new(bob_raw));
    let (server, server_addr, client_config) = make_quic_pair(&alice_group, &bob_group);

     tokio::spawn(async move {
        let incoming = server.accept().await.expect("client connected");
        let conn = incoming.await.expect("handshake completed");
        while let Ok((mut send, mut recv)) = conn.accept_bi().await {
            let data = recv.read_to_end(1 << 16).await.expect("read request");
            send.write_all(&data).await.expect("write response");
            send.finish().expect("finish response stream");
        }
        conn.closed().await;
    });


    let mut endpoint = Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    endpoint.set_default_client_config(client_config);

    let conn = endpoint.connect(server_addr, "localhost").unwrap().await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(b"Hello, QUIC-MLS!").await.unwrap();
    send.finish().unwrap();
    let response1 = recv.read_to_end(64).await.unwrap();
    println!("Echo: before force key update: {}", String::from_utf8_lossy(&response1));
    assert_eq!(response1, b"Hello, QUIC-MLS!");
    conn.force_key_update();
    tokio::time::sleep(Duration::from_millis(500)).await;

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(b"Hello, QUIC-MLS!").await.unwrap();
    send.finish().unwrap();
    let response2 = recv.read_to_end(64).await.unwrap();
    println!("Echo after force key update 2nd time: {}", String::from_utf8_lossy(&response2));
    assert_eq!(response2, b"Hello, QUIC-MLS!");
    conn.force_key_update();
    tokio::time::sleep(Duration::from_millis(500)).await;

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(b"Hello, QUIC-MLS!").await.unwrap();
    send.finish().unwrap();
    let response3 = recv.read_to_end(64).await.unwrap();
    println!("Echo after force key update 3rd time: {}", String::from_utf8_lossy(&response3));
    assert_eq!(response3, b"Hello, QUIC-MLS!");
    conn.force_key_update();
    tokio::time::sleep(Duration::from_millis(500)).await;
}

// this is 0 RTT test for the quic-mls connection. it uses the same group state on both sides of the connection so that the client can derive 0-RTT keys without ever having connected to the server before.
#[tokio::test]
async fn quic_mls_loopback_0rtt_echo() {
    init_tracing();
    let alice = make_client("alice");
    let bob = make_client("bob");

    // Alice and Bob already share this epoch's group state  the MLS
    // analogue of a cached TLS session ticket  so the client can derive
    // 0-RTT keys without ever having connected to the server before.
    let mut alice_group = alice.create_group(ExtensionList::new(), ExtensionList::new(), None).unwrap();
    let bob_kp = bob.generate_key_package_message(ExtensionList::new(), ExtensionList::new(), None).unwrap();
    let commit_out = alice_group.commit_builder().add_member(bob_kp).unwrap().build().unwrap();
    alice_group.apply_pending_commit().unwrap();
    let (bob_group, _) = bob.join_group(None, &commit_out.welcome_messages[0], None).unwrap();

    let server_config = ServerConfig::with_crypto(Arc::new(MlsServerConfig::new(
        Box::new(bob_group),
    )));
    let client_config = ClientConfig::new(Arc::new(MlsClientConfig::new(Box::new(alice_group))));

    let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_addr = server.local_addr().unwrap();

    // A panic inside tokio::spawn is swallowed unless the JoinHandle is
    // awaited, so the real 0-RTT proof is reported back over a channel
    // and asserted on the main test task below.
    let (server_saw_0rtt_tx, server_saw_0rtt_rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let incoming = server.accept().await.expect("client connected").accept().expect("accept");
        let (conn, _established) = incoming.into_0rtt().unwrap_or_else(|_| unreachable!());
        let (mut send, mut recv) = conn.accept_bi().await.expect("client opened a 0-RTT stream");
        let _ = server_saw_0rtt_tx.send(recv.is_0rtt());
        let data = recv.read_to_end(1 << 16).await.expect("read request");
        send.write_all(&data).await.expect("write response");
        send.finish().expect("finish response stream");
        conn.closed().await;
    });

    let mut endpoint = Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    endpoint.set_default_client_config(client_config);


    let (conn, zero_rtt_accepted) = endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .into_0rtt()
        .unwrap_or_else(|_| panic!("0-RTT keys must be available from the shared MLS epoch"));

    // Sent as the client's first flight  no round trip has happened yet.
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(b"Hello, 0-RTT QUIC-MLS!").await.unwrap();
    send.finish().unwrap();

    let response = recv.read_to_end(64).await.unwrap();
    println!("0-RTT echo: {}", String::from_utf8_lossy(&response));
    assert_eq!(response, b"Hello, 0-RTT QUIC-MLS!");

  
    let server_saw_0rtt = server_saw_0rtt_rx.await.expect("server task dropped without reporting");
    assert!(
        server_saw_0rtt,
        "server only received this stream after the handshake completed -- \
         0-RTT decryption failed and the data silently fell back to 1-RTT retransmission"
    );

   
    assert!(zero_rtt_accepted.await, "server must accept the 0-RTT data");
}


#[tokio::test]
async fn quic_mls_0rtt_create_commit_race_before_handshake_confirms() {
    init_tracing();
    let alice = make_client("alice");
    let bob = make_client("bob");

    let mut alice_group = alice.create_group(ExtensionList::new(), ExtensionList::new(), None).unwrap();
    let bob_kp = bob.generate_key_package_message(ExtensionList::new(), ExtensionList::new(), None).unwrap();
    let commit_out = alice_group.commit_builder().add_member(bob_kp).unwrap().build().unwrap();
    alice_group.apply_pending_commit().unwrap();
    let (bob_group, _) = bob.join_group(None, &commit_out.welcome_messages[0], None).unwrap();

    
    let alice_group = Arc::new(Mutex::new(alice_group));

    let server_config = ServerConfig::with_crypto(Arc::new(MlsServerConfig::new(
        Box::new(bob_group),
    )));
    let client_config = ClientConfig::new(Arc::new(MlsClientConfig::new(Box::new(Arc::clone(&alice_group)))));

    let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_addr = server.local_addr().unwrap();

    tokio::spawn(async move {
        let incoming = server.accept().await.expect("client connected").accept().expect("accept");
        let (conn, _established) = incoming.into_0rtt().unwrap_or_else(|_| unreachable!());
        let (mut send, mut recv) = conn.accept_bi().await.expect("client opened a stream");
        let data = recv.read_to_end(1 << 16).await.expect("read request");
        send.write_all(&data).await.expect("write response");
        send.finish().expect("finish response stream");
        conn.closed().await;
    });

    let mut endpoint = Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    endpoint.set_default_client_config(client_config);

    let (conn, zero_rtt_accepted) = endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .into_0rtt()
        .unwrap_or_else(|_| panic!("0-RTT keys must be available from the shared MLS epoch"));

  
    alice_group.lock().unwrap().create_commit().unwrap();

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(b"Hello after a racing commit!").await.unwrap();
    send.finish().unwrap();

    let response = recv.read_to_end(64).await.unwrap();
    assert_eq!(response, b"Hello after a racing commit!");

    assert!(zero_rtt_accepted.await, "connection must still complete despite the racing commit");
}
//---------------------------------------Acceptance tests for Quic MLS-------------------------------------------------------------------
// this is a bidirectional stream that is opened first on both sides of the connection and is used to send commit windows and reports between the client and server.

#[tokio::test]
async fn quic_mls_single_blackout_no_report(){
    let (alice_raw, bob_raw) = make_mls_groups();
    let alice_group = Arc::new(Mutex::new(CommitLog::new(alice_raw)));
    let bob_group   = Arc::new(Mutex::new(bob_raw));
    let (alice_endpoint, alice_preamble, client_config, bob_endpoint, bob_addr, _bob_local_epoch, bob_epoch_rx) =
        make_preamble_pair(&alice_group, &bob_group).await;
    tokio::spawn(async move {
        let incoming = bob_endpoint.accept().await.expect("client connected");
        let conn = incoming.await.expect("handshake completed");
        let (ctrl_send, _ctrl_recv) = conn.accept_bi().await.expect("control stream");
        let no_report = Arc::new(AtomicBool::new(false));
        tokio::spawn(run_report_sender(ctrl_send, bob_epoch_rx, no_report));
        while let Ok((mut send, mut recv)) = conn.accept_bi().await {
            let data = recv.read_to_end(1 << 16).await.expect("read request");
            send.write_all(&data).await.expect("write response");
            send.finish().expect("finish response stream");
        }
    });
    let conn = alice_endpoint.connect_with(client_config, bob_addr, "localhost").unwrap().await.unwrap();
    let (mut ctrl_send, ctrl_recv) = conn.open_bi().await.unwrap();
    write_message(&mut ctrl_send, &ControlMessage::Hello).await.unwrap();
    tokio::spawn(run_report_receiver(Arc::clone(&alice_group), ctrl_recv));

    // Blackout: Alice creates 3 commits while Bob is not reporting back.
    make_commit_For_Alice(&alice_group, 3);
    // Window contains all 3 commits since checkpoint is still 0.
    assert_eq!(alice_group.lock().unwrap().window_bytes().len(), 3);
    // Send the full window as a fire-and-forget preamble datagram -- Bob
    // applies it (his epoch does advance) but never reports back.
    let window = alice_group.lock().unwrap().window_bytes();
    alice_preamble.send_preamble(bob_addr, &window, usize::MAX).await.unwrap();
    // Give Bob's sink + (suppressed) report path a moment to run, then
    // confirm nothing was ever trimmed -- there is no Report to wait for.
    assert!(
        !wait_until_checkpoint(&alice_group, 1, std::time::Duration::from_millis(300)).await,
        "checkpoint must never advance when Bob never reports"
    );
    assert_eq!(alice_group.lock().unwrap().checkpoint(), 0);
    // Window must still be 3 — nothing pruned.
    assert_eq!(alice_group.lock().unwrap().window_bytes().len(), 3);
}

#[tokio::test]
async fn quic_mls_single_blackout_with_report(){
    let (alice_raw, bob_raw) = make_mls_groups();
    let alice_group = Arc::new(Mutex::new(CommitLog::new(alice_raw)));
    let bob_group   = Arc::new(Mutex::new(bob_raw));
    let (alice_endpoint, alice_preamble, client_config, bob_endpoint, bob_addr, _bob_local_epoch, bob_epoch_rx) =
        make_preamble_pair(&alice_group, &bob_group).await;
    tokio::spawn(async move {
        let incoming = bob_endpoint.accept().await.expect("client connected");
        let conn = incoming.await.expect("handshake completed");
        let (ctrl_send, _ctrl_recv) = conn.accept_bi().await.expect("control stream");
        let always_report = Arc::new(AtomicBool::new(true));
        tokio::spawn(run_report_sender(ctrl_send, bob_epoch_rx, always_report));
    });
    let conn = alice_endpoint.connect_with(client_config, bob_addr, "localhost").unwrap().await.unwrap();
    let (mut ctrl_send, ctrl_recv) = conn.open_bi().await.unwrap();
    write_message(&mut ctrl_send, &ControlMessage::Hello).await.unwrap();
    tokio::spawn(run_report_receiver(Arc::clone(&alice_group), ctrl_recv));

    // Blackout: Alice creates 3 commits.
    make_commit_For_Alice(&alice_group, 3);
    assert_eq!(alice_group.lock().unwrap().window_bytes().len(), 3);
    // Send the window as a preamble datagram — Bob applies all 3 and
    // reports back reactively; Alice's background receiver trims whenever
    // that lands.
    let window = alice_group.lock().unwrap().window_bytes();
    alice_preamble.send_preamble(bob_addr, &window, usize::MAX).await.unwrap();
    assert!(
        wait_until_checkpoint(&alice_group, 3, std::time::Duration::from_secs(5)).await,
        "checkpoint must reach 3 once Bob's Report is picked up"
    );
    // Window must be empty — all commits pruned below checkpoint.
    assert_eq!(alice_group.lock().unwrap().window_bytes().len(), 0);
}

#[tokio::test]
async fn quic_mls_two_blackouts(){
    let (alice_raw, bob_raw) = make_mls_groups();
    let alice_group = Arc::new(Mutex::new(CommitLog::new(alice_raw)));
    let bob_group   = Arc::new(Mutex::new(bob_raw));
    let (alice_endpoint, alice_preamble, client_config, bob_endpoint, bob_addr, _bob_local_epoch, bob_epoch_rx) =
        make_preamble_pair(&alice_group, &bob_group).await;
    // Shared flag: true = Bob sends Report, false = Bob stays silent (simulates return link down).
    let should_report = Arc::new(AtomicBool::new(true));
    let should_report_ctrl = Arc::clone(&should_report);
    tokio::spawn(async move {
        let incoming = bob_endpoint.accept().await.expect("client connected");
        let conn = incoming.await.expect("handshake completed");
        let (ctrl_send, _ctrl_recv) = conn.accept_bi().await.expect("control stream");
        tokio::spawn(run_report_sender(ctrl_send, bob_epoch_rx, should_report_ctrl));
    });
    let conn = alice_endpoint.connect_with(client_config, bob_addr, "localhost").unwrap().await.unwrap();
    let (mut ctrl_send, ctrl_recv) = conn.open_bi().await.unwrap();
    write_message(&mut ctrl_send, &ControlMessage::Hello).await.unwrap();
    tokio::spawn(run_report_receiver(Arc::clone(&alice_group), ctrl_recv));

    // blackout 1: Alice creates 2 commits and sends them to Bob, who applies them and reports back.
    make_commit_For_Alice(&alice_group, 2);
    assert_eq!(alice_group.lock().unwrap().window_bytes().len(), 2);
    let window = alice_group.lock().unwrap().window_bytes();
    alice_preamble.send_preamble(bob_addr, &window, usize::MAX).await.unwrap();
    assert!(
        wait_until_checkpoint(&alice_group, 2, std::time::Duration::from_secs(5)).await,
        "checkpoint must reach 2 after blackout 1's Report"
    );
    // Window must be empty — all commits pruned below checkpoint.
    assert_eq!(alice_group.lock().unwrap().window_bytes().len(), 0);
    // Disable reporting before blackout 2.
    should_report.store(false, std::sync::atomic::Ordering::SeqCst);
    make_commit_For_Alice(&alice_group, 3); // epoch 3, 4, 5
    assert_eq!(alice_group.lock().unwrap().window_bytes().len(), 3); // epochs 3,4,5 — checkpoint is still 2
    // Send window as a preamble datagram again; no Report arrives this time.
    let window = alice_group.lock().unwrap().window_bytes();
    alice_preamble.send_preamble(bob_addr, &window, usize::MAX).await.unwrap();
    assert!(
        !wait_until_checkpoint(&alice_group, 3, std::time::Duration::from_millis(300)).await,
        "checkpoint must not advance past 2 while reporting is disabled"
    );
    // Checkpoint unchanged, window grew.
    assert_eq!(alice_group.lock().unwrap().checkpoint(), 2);
    assert_eq!(alice_group.lock().unwrap().window_bytes().len(), 3);
}




//----------------------------------------------unit test for group.rs-------------------------------------
#[test]
//Build a window that includes an already-applied commit 
//this should be rejected by the server and not applied to the group state. because if bob has already applied a commit,
//he should not apply it again. this is a safety check to ensure that the server does not apply stale commits that have already been applied to the group state.
fn quic_mls_stale_commit_rejection(){
    let (alice_raw, mut bob_raw) = make_mls_groups();
    let mut alice_group = CommitLog::new(alice_raw);
    // Alice creates commits 1 and 2.
    alice_group.create_commit().unwrap();
    alice_group.create_commit().unwrap();
    // Bob applies both via apply_commit_window, landing at local_epoch == 2.
    let mut local_epoch = 0u64;
    let window_1_2 = alice_group.window_bytes(); // checkpoint is still 0, so [(1,_),(2,_)]
    apply_commit_window(&mut bob_raw, &window_1_2, &mut local_epoch).unwrap();
    assert_eq!(local_epoch, 2);
     // Alice creates commit 3.
    alice_group.create_commit().unwrap();
    // Nothing has been trimmed, so the window Alice would resend still
    // starts at epoch 1: it now contains 1, 2 (stale for Bob) and 3 (new).
    let window_1_2_3 = alice_group.window_bytes();
    assert_eq!(window_1_2_3.len(), 3);
    let result = apply_commit_window(&mut bob_raw, &window_1_2_3, &mut local_epoch);
    // The stale commits should be rejected.
    assert!(result.is_ok());
    assert_eq!(local_epoch, 3);
}


#[test]
//this is test where bob has fallen behind and alice has trimmed her commit log, so bob cannot catch up without a resync. this should be rejected by the server and not applied to the group state.
//because if bob has fallen behind and alice has trimmed her commit log, he cannot catch up without a resync. 
//this is a safety check to ensure that the server should apply commit in order and not skip any commits, and if it cannot apply a commit because it has fallen behind,
//it should return an error indicating that a resync is needed.
fn quic_mls_fell_off_back() {
    let (alice_raw, mut bob_raw) = make_mls_groups();
    let mut alice_group = CommitLog::new(alice_raw);

    // Alice creates 6 commits: epochs 1..=6.
    for _ in 0..6 {
        alice_group.create_commit().unwrap();
    }

    
    alice_group.trim(5);
    assert_eq!(alice_group.checkpoint(), 5);
    let window = alice_group.window_bytes();
    assert_eq!(window, vec![window[0].clone()]); // sanity: only one entry
    assert_eq!(window[0].0, 6);


    let mut local_epoch = 3u64;

    let result = apply_commit_window(&mut bob_raw, &window, &mut local_epoch);

    assert!(matches!(result, Err(CommitWindowError::ResyncNeeded)));
    assert_eq!(local_epoch, 3); // untouched -- the function bails on the gap
}

