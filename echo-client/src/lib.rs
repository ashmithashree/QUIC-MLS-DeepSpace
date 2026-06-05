use std::{net::SocketAddr, sync::Arc};

use quinn::{ClientConfig, Endpoint};
use rustls::pki_types::CertificateDer;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("TLS client config: {0}")]
    ClientConfig(String),
    #[error("endpoint I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("connect: {0}")]
    Connect(#[from] quinn::ConnectError),
    #[error("connection: {0}")]
    Connection(#[from] quinn::ConnectionError),
    #[error("write: {0}")]
    Write(#[from] quinn::WriteError),
    #[error("read: {0}")]
    Read(#[from] quinn::ReadToEndError),
    #[error("finish stream: {0}")]
    Finish(String),
}

/// Connect to `server_addr` over QUIC, open one bidirectional stream, send
/// `message`, and return the echoed bytes.
///
/// `cert_der` must be the DER-encoded certificate of the server — it is added
/// as the sole trusted root so no system CAs are involved.
pub async fn echo(
    server_addr: SocketAddr,
    cert_der: CertificateDer<'static>,
    message: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(cert_der)
        .map_err(|e| Error::ClientConfig(e.to_string()))?;

    let client_config = ClientConfig::with_root_certificates(Arc::new(roots))
        .map_err(|e| Error::ClientConfig(e.to_string()))?;

    let mut endpoint = Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))?;
    endpoint.set_default_client_config(client_config);

    let conn = endpoint.connect(server_addr, "localhost")?.await?;
    let (mut send, mut recv) = conn.open_bi().await?;

    send.write_all(message).await?;
    send.finish().map_err(|e| Error::Finish(e.to_string()))?;

    let response = recv.read_to_end(message.len() + 64).await?;
    conn.close(0u32.into(), b"done");
    Ok(response)
}
