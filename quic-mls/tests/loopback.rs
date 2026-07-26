use std::{net::SocketAddr, sync::Arc, sync::Mutex};

use mls_rs::{
    identity::{basic::{BasicCredential, BasicIdentityProvider}, SigningIdentity},
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, ExtensionList,
};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;
use quic_mls::{MlsClientConfig, MlsServerConfig, ExportSecret, CommitLog, send_window_and_trim, run_commit_receiver,apply_commit_window, CommitWindowError};
use quinn::{ClientConfig, Endpoint, ServerConfig};

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
        Box::new(Arc::clone(bob_group)), Arc::new(Mutex::new(0u64)), usize::MAX,
    )));
    let client_config = ClientConfig::new(Arc::new(MlsClientConfig::new(Box::new(Arc::clone(alice_group)), usize::MAX)));
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

async fn connect_with_control(
    client_config: ClientConfig,
    server_addr: SocketAddr,
) -> (quinn::Connection, quinn::SendStream, quinn::RecvStream) {
    let mut endpoint = Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    endpoint.set_default_client_config(client_config);
    let conn = endpoint.connect(server_addr, "localhost").unwrap().await.unwrap();
    let (ctrl_send, ctrl_recv) = conn.open_bi().await.unwrap();
    (conn, ctrl_send, ctrl_recv)
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
        Box::new(bob_group), Arc::new(Mutex::new(0u64)), usize::MAX,
    )));
    let client_config = ClientConfig::new(Arc::new(MlsClientConfig::new(Box::new(alice_group), usize::MAX)));

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
    let (server, server_addr, client_config) = make_quic_pair(&alice_group, &bob_group);

    tokio::spawn(async move {
        let incoming = server.accept().await.expect("client connected");
        let conn = incoming.await.expect("handshake completed");
        //First bi stream is alwaya the control stream.
        let (ctrl_send, ctrl_recv) = conn.accept_bi().await.expect("control stream");

        //handle commit window and send report in seperate task
        let bob_group_ctrl = Arc::clone(&bob_group);
        let always_report = Arc::new(std::sync::atomic::AtomicBool::new(true));
        tokio::spawn(run_commit_receiver(bob_group_ctrl, ctrl_send, ctrl_recv, always_report, Arc::new(Mutex::new(0u64))));
        //echo loop for all application data stream.
        while let Ok((mut send, mut recv)) = conn.accept_bi().await {
            let data = recv.read_to_end(1 << 16).await.expect("read request");
            send.write_all(&data).await.expect("write response");
            send.finish().expect("finish response stream");
        }
    });
    // client connection endpoint
    
    let (conn, mut ctrl_send, mut ctrl_recv) = connect_with_control(client_config, server_addr).await;

    //pre-rekey echo
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(b"Hello, QUIC-MLS!").await.unwrap();
    send.finish().unwrap();
    //check that the echo response matches the sent message
    let response = recv.read_to_end(64).await.unwrap();
    println!("Echo: {}", String::from_utf8_lossy(&response));
    assert_eq!(response, b"Hello, QUIC-MLS!");
    // Create commit, send the window to Bob, wait for his Report (with timeout) before flipping keys.
    make_commit_For_Alice(&alice_group, 1);
    send_window_and_trim(&alice_group, &mut ctrl_send, &mut ctrl_recv, std::time::Duration::from_secs(5)).await.unwrap();
    //update the keysin connection
    conn.force_key_update();
    //post-rekey echo
    let (mut send2, mut recv2) = conn.open_bi().await.unwrap();
    send2.write_all(b"Hello again, QUIC-MLS!").await.unwrap();
    send2.finish().unwrap();
    let response2 = recv2.read_to_end(64).await.unwrap();
    println!("Echo after rekey: {}", String::from_utf8_lossy(&response2));
    assert_eq!(response2, b"Hello again, QUIC-MLS!");
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
        Box::new(bob_group), Arc::new(Mutex::new(0u64)), usize::MAX,
    )));
    let client_config = ClientConfig::new(Arc::new(MlsClientConfig::new(Box::new(alice_group), usize::MAX)));

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
        Box::new(bob_group), Arc::new(Mutex::new(0u64)), usize::MAX,
    )));
    let client_config = ClientConfig::new(Arc::new(MlsClientConfig::new(Box::new(Arc::clone(&alice_group)), usize::MAX)));

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
    let (server, server_addr, client_config) = make_quic_pair(&alice_group, &bob_group);  
    // make handshake and open a bidirectional stream
    tokio::spawn(async move {
        let incoming = server.accept().await.expect("client connected");
        let conn = incoming.await.expect("handshake completed");
        // First bi stream is the control stream.
        let (ctrl_send, ctrl_recv) = conn.accept_bi().await.expect("control stream");
        let bob_group_ctrl = Arc::clone(&bob_group);
        let no_report = Arc::new(std::sync::atomic::AtomicBool::new(false));
        tokio::spawn(run_commit_receiver(bob_group_ctrl, ctrl_send, ctrl_recv, no_report, Arc::new(Mutex::new(0u64))));
        while let Ok((mut send, mut recv)) = conn.accept_bi().await {
            let data = recv.read_to_end(1 << 16).await.expect("read request");
            send.write_all(&data).await.expect("write response");
            send.finish().expect("finish response stream");
        }
    });
    let (conn, mut ctrl_send, mut ctrl_recv) = connect_with_control(client_config, server_addr).await;
    // Blackout: Alice creates 3 commits while Bob is not reporting back.
    make_commit_For_Alice(&alice_group, 3);
    // Window contains all 3 commits since checkpoint is still 0.
    assert_eq!(alice_group.lock().unwrap().window_bytes().len(), 3);
    // Send the full window; timeout when no Report comes back (return link down).
    send_window_and_trim(&alice_group, &mut ctrl_send, &mut ctrl_recv, std::time::Duration::from_millis(100)).await.unwrap();
    // Checkpoint must still be 0 — nothing trimmed because no Report arrived.
    assert_eq!(alice_group.lock().unwrap().checkpoint(), 0);
    // Window must still be 3 — nothing pruned.
    assert_eq!(alice_group.lock().unwrap().window_bytes().len(), 3);
}

#[tokio::test]
async fn quic_mls_single_blackout_with_report(){
    let (alice_raw, bob_raw) = make_mls_groups();
    let alice_group = Arc::new(Mutex::new(CommitLog::new(alice_raw)));
    let bob_group   = Arc::new(Mutex::new(bob_raw));
    let (server, server_addr, client_config) = make_quic_pair(&alice_group, &bob_group);  
    // make handshake and open a bidirectional stream
    tokio::spawn(async move {
        let incoming = server.accept().await.expect("client connected");
        let conn = incoming.await.expect("handshake completed");
        // First bi stream is the control stream.
        let (ctrl_send, ctrl_recv) = conn.accept_bi().await.expect("control stream");
        let bob_group_ctrl = Arc::clone(&bob_group);
        let always_report = Arc::new(std::sync::atomic::AtomicBool::new(true));
        tokio::spawn(run_commit_receiver(bob_group_ctrl, ctrl_send, ctrl_recv, always_report, Arc::new(Mutex::new(0u64))));
    });
    let (conn, mut ctrl_send, mut ctrl_recv) = connect_with_control(client_config, server_addr).await;
    // Blackout: Alice creates 3 commits.
    make_commit_For_Alice(&alice_group, 3);
    assert_eq!(alice_group.lock().unwrap().window_bytes().len(), 3);
    // Send the window — Bob applies all 3 and sends a Report back; Alice trims.
    send_window_and_trim(&alice_group, &mut ctrl_send, &mut ctrl_recv, std::time::Duration::from_secs(5)).await.unwrap();
    // Checkpoint must now be 3 — Bob confirmed he reached epoch 3.
    assert_eq!(alice_group.lock().unwrap().checkpoint(), 3);
    // Window must be empty — all commits pruned below checkpoint.
    assert_eq!(alice_group.lock().unwrap().window_bytes().len(), 0);               
}

#[tokio::test]
async fn quic_mls_two_blackouts(){
    let (alice_raw, bob_raw) = make_mls_groups();
    let alice_group = Arc::new(Mutex::new(CommitLog::new(alice_raw)));
    let bob_group   = Arc::new(Mutex::new(bob_raw));
    let (server, server_addr, client_config) = make_quic_pair(&alice_group, &bob_group);
    // Shared flag: true = Bob sends Report, false = Bob stays silent (simulates return link down).
    let should_report = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let should_report_ctrl = Arc::clone(&should_report);
    // make handshake and open a bidirectional stream
    tokio::spawn(async move {
        let incoming = server.accept().await.expect("client connected");
        let conn = incoming.await.expect("handshake completed");
        // First bi stream is the control stream.
        let (ctrl_send, ctrl_recv) = conn.accept_bi().await.expect("control stream");
        let bob_group_ctrl = Arc::clone(&bob_group);
        tokio::spawn(run_commit_receiver(bob_group_ctrl, ctrl_send, ctrl_recv, should_report_ctrl, Arc::new(Mutex::new(0u64))));
    });
    let (conn, mut ctrl_send, mut ctrl_recv) = connect_with_control(client_config, server_addr).await;
    // black out 1: Alice creates 2 commits and sends them to Bob, who applies them and sends a Report back.
    make_commit_For_Alice(&alice_group, 2);
    //assert that the window contains 2 commits
    assert_eq!(alice_group.lock().unwrap().window_bytes().len(), 2);
    // Send the window — Bob applies all 2 and sends a Report back; Alice trims.
    send_window_and_trim(&alice_group, &mut ctrl_send, &mut ctrl_recv, std::time::Duration::from_secs(5)).await.unwrap();
    // After blackout 1: window trimmed, checkpoint advanced.
    assert_eq!(alice_group.lock().unwrap().checkpoint(), 2);
    // Window must be empty — all commits pruned below checkpoint.
    assert_eq!(alice_group.lock().unwrap().window_bytes().len(), 0);
    // Disable reporting before blackout 2.
    should_report.store(false, std::sync::atomic::Ordering::SeqCst);
    make_commit_For_Alice(&alice_group, 3); // epoch 3, 4, 5
    assert_eq!(alice_group.lock().unwrap().window_bytes().len(), 3); // epochs 3,4,5 — checkpoint is still 2
    // Send window; timeout when no Report arrives (return link down).
    send_window_and_trim(&alice_group, &mut ctrl_send, &mut ctrl_recv, std::time::Duration::from_millis(100)).await.unwrap();
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

