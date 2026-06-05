use std::net::SocketAddr;

use rustls::pki_types::CertificateDer;
#[derive(Debug, thiserror::Error)]
enum Error {
    #[error(transparent)]
    Client(#[from] echo_client::Error),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt::init();

    let cert_bytes = std::fs::read("cert.der")?;
    let cert_der = CertificateDer::from(cert_bytes);

    let server_addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
    let response = echo_client::echo(server_addr, cert_der, b"Hello, QUIC!").await?;

    println!("Echo: {}", String::from_utf8_lossy(&response));
    assert_eq!(response, b"Hello, QUIC!", "echo payload mismatch");
    Ok(())
}
