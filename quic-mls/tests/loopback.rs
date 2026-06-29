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
