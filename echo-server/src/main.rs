use std::net::SocketAddr;

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error(transparent)]
    Server(#[from] echo_server::Error),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt::init();

    let ck = echo_server::make_self_signed()?;

    // Write the DER-encoded certificate to disk so the client process can
    // load it as the sole trusted root (no system CA involvement).
    std::fs::write("cert.der", ck.cert.der().as_ref())?;
    println!("cert.der written");

    let (server_config, _) = echo_server::make_server_config(&ck)?;

    let addr: SocketAddr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:4433".to_string())
        .parse()
        .expect("invalid bind address, expected form IP:PORT");

    let endpoint = quinn::Endpoint::server(server_config, addr)?;
    println!("listening on {addr}");

    echo_server::serve(endpoint).await;
    Ok(())
}
