use std::{net::SocketAddr, sync::Arc, sync::Mutex};

use mls_rs::{
    identity::{basic::{BasicCredential, BasicIdentityProvider}, SigningIdentity},
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, ExtensionList,
};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;
use quic_mls::{MlsClientConfig, MlsServerConfig, ExportSecret};
use quinn::{ClientConfig, Endpoint, ServerConfig};

const CS: CipherSuite = CipherSuite::CURVE25519_AES128;
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
}
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

    let server_config = ServerConfig::with_crypto(Arc::new(MlsServerConfig::new(Box::new(bob_group))));
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

#[tokio::test]
async fn quic_mls_loopback_echo_with_rekey() {
    init_tracing();
    let alice = make_client("alice");
    let bob = make_client("bob");
    //original
    let mut alice_group = alice.create_group(ExtensionList::new(), ExtensionList::new(), None).unwrap();
    let bob_kp = bob.generate_key_package_message(ExtensionList::new(), ExtensionList::new(), None).unwrap();
    let commit_out = alice_group.commit_builder().add_member(bob_kp).unwrap().build().unwrap();
    alice_group.apply_pending_commit().unwrap();
    let (bob_group, _) = bob.join_group(None, &commit_out.welcome_messages[0], None).unwrap();
    
    //clone the group so we can keep a handle to it for rekeying after it has been moved into the MlsClientConfig
    let alice_group = Arc::new(Mutex::new(alice_group));
    let bob_group = Arc::new(Mutex::new(bob_group));

    let server_config = ServerConfig::with_crypto(Arc::new(MlsServerConfig::new(Box::new(Arc::clone(&bob_group)))));
    let client_config = ClientConfig::new(Arc::new(MlsClientConfig::new(Box::new(Arc::clone(&alice_group)))));
    // server connection
    let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_addr = server.local_addr().unwrap();
    
    // make handshake and open a bidirectional stream
    tokio::spawn(async move {
        let incoming = server.accept().await.expect("client connected");
        let conn = incoming.await.expect("handshake completed");

        while let Ok((mut send, mut recv)) = conn.accept_bi().await {
            let data = recv.read_to_end(1 << 16).await.expect("read request");
            send.write_all(&data).await.expect("write response");
            send.finish().expect("finish response stream");
        }
    });
    // client connection endpoint
    let mut endpoint = Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    endpoint.set_default_client_config(client_config);

    let conn = endpoint.connect(server_addr, "localhost").unwrap().await.unwrap();
    //open a bidirectional stream and send a message
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(b"Hello, QUIC-MLS!").await.unwrap();
    send.finish().unwrap();
    //check that the echo response matches the sent message
    let response = recv.read_to_end(64).await.unwrap();
    println!("Echo: {}", String::from_utf8_lossy(&response));
    assert_eq!(response, b"Hello, QUIC-MLS!");
    //advance the epoch
    let commit = alice_group.lock().unwrap().create_commit().unwrap();
    bob_group.lock().unwrap().apply_commit(&commit).unwrap();
    //force a key update on the connection
    conn.force_key_update();
    //open stream and send a message after rekey
    let (mut send2, mut recv2) = conn.open_bi().await.unwrap();
    send2.write_all(b"Hello again, QUIC-MLS!").await.unwrap();
    send2.finish().unwrap();

    let response2 = recv2.read_to_end(64).await.unwrap();
    println!("Echo after rekey: {}", String::from_utf8_lossy(&response2));
    assert_eq!(response2, b"Hello again, QUIC-MLS!");
}

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

    let server_config = ServerConfig::with_crypto(Arc::new(MlsServerConfig::new_with_early_data(Box::new(bob_group))));
    let client_config = ClientConfig::new(Arc::new(MlsClientConfig::new_with_early_data(Box::new(alice_group))));

    let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_addr = server.local_addr().unwrap();

    // A panic inside tokio::spawn is swallowed unless the JoinHandle is
    // awaited, so the real 0-RTT proof is reported back over a channel
    // and asserted on the main test task below.
    let (server_saw_0rtt_tx, server_saw_0rtt_rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let incoming = server.accept().await.expect("client connected").accept().expect("accept");
        // Server-side into_0rtt() always succeeds for incoming connections
        // (it's how the server gets a usable Connection for 0.5-RTT
        // responses too) the real question is whether the client's
        // 0-RTT flight decrypts, which accept_bi below proves.
        let (conn, _established) = incoming.into_0rtt().unwrap_or_else(|_| unreachable!());
        let (mut send, mut recv) = conn.accept_bi().await.expect("client opened a 0-RTT stream");
        // RecvStream::is_0rtt() reports whether this stream was handed to
        // the application while the QUIC connection was still mid-
        // handshake -- i.e. before any round trip could have completed.
        // If the server's 0-RTT decryption is broken, quinn-proto silently
        // drops the undecryptable 0-RTT packet and the data only shows up
        // once it's retransmitted under 1-RTT after the handshake
        // finishes, at which point is_0rtt() is false. quinn-proto 0.11.14
        // has no decrypted-0-RTT-packet counter in ConnectionStats, so
        // this per-stream flag is the real proof available.
        let _ = server_saw_0rtt_tx.send(recv.is_0rtt());
        let data = recv.read_to_end(1 << 16).await.expect("read request");
        send.write_all(&data).await.expect("write response");
        send.finish().expect("finish response stream");
        conn.closed().await;
    });

    let mut endpoint = Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    endpoint.set_default_client_config(client_config);

    // into_0rtt() hands back a Connection usable immediately, before the
    // handshake round trip completes, plus a future that resolves once we
    // know whether the server accepted the early data.
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

    // Primary proof: the SERVER actually decrypted this stream's data
    // during 0-RTT, not via a 1-RTT fallback retransmission after the
    // handshake completed.
    let server_saw_0rtt = server_saw_0rtt_rx.await.expect("server task dropped without reporting");
    assert!(
        server_saw_0rtt,
        "server only received this stream after the handshake completed -- \
         0-RTT decryption failed and the data silently fell back to 1-RTT retransmission"
    );

    // Secondary: quinn-proto's own accepted_0rtt flag. Note this is driven
    // entirely by the CLIENT's early_data_accepted(), which in this Session
    // is a static `Some(self.early_data)` policy flag -- it does not by
    // itself prove the server decrypted anything (see early_data_accepted
    // in session.rs). The assertion above is the one that actually catches
    // a broken server-side key.
    assert!(zero_rtt_accepted.await, "server must accept the 0-RTT data");
}
