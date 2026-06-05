use quinn::Endpoint;

/// Spin up an echo-server on a random loopback port, connect the echo-client
/// library to it, send a message, and assert the echo matches.
#[tokio::test]
async fn loopback_echo() {
    let ck = echo_server::make_self_signed().unwrap();
    let (server_config, cert_der) = echo_server::make_server_config(&ck).unwrap();

    let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_addr = server.local_addr().unwrap();

    tokio::spawn(echo_server::serve(server));

    let reply = echo_client::echo(server_addr, cert_der, b"Hello, QUIC!")
        .await
        .unwrap();

    assert_eq!(reply, b"Hello, QUIC!");
}
