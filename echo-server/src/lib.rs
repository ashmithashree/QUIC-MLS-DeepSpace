use quinn::{Endpoint, ServerConfig};
use rcgen::{CertifiedKey, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tracing::{info, warn};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("certificate generation: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("TLS setup: {0}")]
    Tls(#[from] rustls::Error),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("no private key found in PEM output")]
    NoPrivateKey,
}

/// Generate a self-signed certificate for `localhost`.
pub fn make_self_signed() -> Result<CertifiedKey<KeyPair>, Error> {
    Ok(rcgen::generate_simple_self_signed(vec![
        "localhost".to_string()
    ])?)
}

/// Build a `ServerConfig` from a certified key pair.
/// Also returns the DER-encoded certificate so callers can hand it to clients
/// as a trusted root without writing it to disk.
pub fn make_server_config(
    ck: &CertifiedKey<KeyPair>,
) -> Result<(ServerConfig, CertificateDer<'static>), Error> {
    let cert_der: CertificateDer<'static> = ck.cert.der().clone();
    // rcgen gives us the key in PEM; rustls-pemfile converts it to the DER
    // PrivateKeyDer that quinn expects.
    let key_pem = ck.signing_key.serialize_pem();
    let key_der: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut key_pem.as_bytes())?.ok_or(Error::NoPrivateKey)?;
    let server_config = ServerConfig::with_single_cert(vec![cert_der.clone()], key_der)?;
    Ok((server_config, cert_der))
}

/// Accept connections on `endpoint` and echo every bidirectional stream back to
/// the sender.  Returns when the endpoint is closed or drops out of scope.
pub async fn serve(endpoint: Endpoint) {
    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            let conn = match incoming.await {
                Ok(c) => c,
                Err(e) => {
                    warn!("incoming connection failed: {e}");
                    return;
                }
            };
            info!("accepted connection from {}", conn.remote_address());
            echo_streams(conn).await;
        });
    }
}

async fn echo_streams(conn: quinn::Connection) {
    loop {
        let (mut send, mut recv) = match conn.accept_bi().await {
            Ok(pair) => pair,
            Err(quinn::ConnectionError::ApplicationClosed(_)) => break,
            Err(e) => {
                warn!("accept_bi: {e}");
                break;
            }
        };
        tokio::spawn(async move {
            let data = match recv.read_to_end(1 << 20).await {
                Ok(d) => d,
                Err(e) => {
                    warn!("recv read_to_end: {e}");
                    return;
                }
            };
            if let Err(e) = send.write_all(&data).await {
                warn!("send write_all: {e}");
                return;
            }
            // finish() signals end-of-stream; the only failure case is the
            // stream already being reset, which is harmless here.
            if let Err(e) = send.finish() {
                warn!("send finish: {e}");
            }
        });
    }
}
