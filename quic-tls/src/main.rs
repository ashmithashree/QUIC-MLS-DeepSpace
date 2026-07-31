use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Endpoint, IdleTimeout, ServerConfig, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::Serialize;

const ALPN: &[u8] = b"quic-mls-baseline";

#[derive(Parser)]
#[command(name = "tls-baseline", about = "QUIC + TLS 1.3 baseline runner")]
struct Cli {
    #[command(subcommand)]
    role: Role,
}

#[derive(Subcommand)]
enum Role {
    Server {
        #[arg(long)]
        listen: SocketAddr,
        #[arg(long, default_value_t = 30)]
        idle_timeout_secs: u64,
    },
    Client {
        #[arg(long)]
        server: SocketAddr,
        #[arg(long, default_value = "10.200.1.1:0")]
        bind: SocketAddr,
        #[arg(long, default_value = "unspecified")]
        channel: String,
        #[arg(long, default_value_t = 0)]
        rtt_ms: u64,
        #[arg(long, default_value_t = 16)]
        reconnects: u32,
        #[arg(long, default_value_t = 0)]
        blackout_ms: u64,
        #[arg(long, default_value_t = false)]
        no_resumption: bool,
        #[arg(long, default_value_t = 30)]
        idle_timeout_secs: u64,
    },
}

#[derive(Serialize)]
struct Record {
    role: &'static str,
    phase: &'static str,
    channel: String,
    rtt_ms: u64,
    iteration: u32,
    handshake_ms: f64,
    setup_tx_bytes: u64,
    setup_rx_bytes: u64,
    crypto_frames_tx: u64,
    crypto_frames_rx: u64,
    mode: &'static str,
    zero_rtt_accepted: bool,
}

impl Record {
    fn emit(&self) {
        println!("{}", serde_json::to_string(self).expect("serialise record"));
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    match Cli::parse().role {
        Role::Server { listen, idle_timeout_secs } => run_server(listen, idle_timeout_secs).await,
        Role::Client {
            server, bind, channel, rtt_ms, reconnects, blackout_ms, no_resumption, idle_timeout_secs,
        } => run_client(server, bind, channel, rtt_ms, reconnects, blackout_ms, no_resumption, idle_timeout_secs).await,
    }
}

fn transport(idle_secs: u64) -> Arc<TransportConfig> {
    let mut cfg = TransportConfig::default();
    cfg.enable_segmentation_offload(false);
    cfg.max_idle_timeout(Some(IdleTimeout::try_from(Duration::from_secs(idle_secs)).unwrap()));
    Arc::new(cfg)
}

fn build_server_config(idle_secs: u64) -> Result<ServerConfig> {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .context("generate self-signed cert")?;
    let cert_der: CertificateDer<'static> = ck.cert.der().clone();
    let key_pem = ck.signing_key.serialize_pem();
    let key_der: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .context("parse key PEM")?
        .context("no private key found in PEM")?;

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .context("rustls server config")?;
    server_crypto.alpn_protocols = vec![ALPN.to_vec()];
    server_crypto.max_early_data_size = u32::MAX;

    let mut server_config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));
    server_config.transport = transport(idle_secs);
    Ok(server_config)
}

async fn run_server(listen: SocketAddr, idle_secs: u64) -> Result<()> {
    let endpoint = Endpoint::server(build_server_config(idle_secs)?, listen)?;
    eprintln!("[server] listening on {listen} (idle={idle_secs}s)");
    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            if let Err(e) = handle_connection(incoming).await {
                eprintln!("[server] connection error: {e:#}");
            }
        });
    }
    Ok(())
}

async fn handle_connection(incoming: quinn::Incoming) -> Result<()> {
    let connecting = incoming.accept()?;
    let conn = match connecting.into_0rtt() {
        Ok((conn, _accepted)) => conn,
        Err(connecting) => connecting.await?,
    };
    loop {
        match conn.accept_bi().await {
            Ok((mut send, mut recv)) => {
                let data = recv.read_to_end(64 * 1024).await.unwrap_or_default();
                let _ = send.write_all(&data).await;
                let _ = send.finish();
            }
            Err(quinn::ConnectionError::ApplicationClosed(_))
            | Err(quinn::ConnectionError::ConnectionClosed(_))
            | Err(quinn::ConnectionError::LocallyClosed) => break,
            Err(_) => break,
        }
    }
    Ok(())
}

fn build_client_config(no_resumption: bool, idle_secs: u64) -> Result<ClientConfig> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification(provider)))
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![ALPN.to_vec()];

    if no_resumption {
        client_crypto.resumption = rustls::client::Resumption::disabled();
        client_crypto.enable_early_data = false;
    } else {
        client_crypto.enable_early_data = true;
    }

    let mut client_config =
        ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto)?));
    client_config.transport_config(transport(idle_secs));
    Ok(client_config)
}

async fn run_client(
    server: SocketAddr, bind: SocketAddr, channel: String, rtt_ms: u64,
    reconnects: u32, blackout_ms: u64, no_resumption: bool, idle_secs: u64,
) -> Result<()> {
    let mut endpoint = Endpoint::client(bind)?;
    endpoint.set_default_client_config(build_client_config(no_resumption, idle_secs)?);

    let (conn, ms, tx, rx, ctx, crx) = full_handshake(&endpoint, server).await?;
    Record {
        role: "client", phase: "initial_handshake", channel: channel.clone(), rtt_ms,
        iteration: 0, handshake_ms: ms, setup_tx_bytes: tx, setup_rx_bytes: rx,
        crypto_frames_tx: ctx, crypto_frames_rx: crx, mode: "full-1rtt", zero_rtt_accepted: false,
    }.emit();
    if !no_resumption { tokio::time::sleep(Duration::from_millis(2 * rtt_ms + 2000)).await; }
    conn.close(0u32.into(), b"initial-done");

    for i in 1..=reconnects {
        if blackout_ms > 0 {
            tokio::time::sleep(Duration::from_millis(blackout_ms)).await;
        }
        let (conn, ms, tx, rx, ctx, crx, mode, zrtt) =
            reconnect(&endpoint, server, no_resumption).await?;
        Record {
            role: "client", phase: "reconnect", channel: channel.clone(), rtt_ms,
            iteration: i, handshake_ms: ms, setup_tx_bytes: tx, setup_rx_bytes: rx,
            crypto_frames_tx: ctx, crypto_frames_rx: crx, mode, zero_rtt_accepted: zrtt,
        }.emit();
         if !no_resumption {
            tokio::time::sleep(Duration::from_millis(2 * rtt_ms + 2000)).await;
        }
        conn.close(0u32.into(), b"reconnect-done");
    }

    endpoint.wait_idle().await;
    Ok(())
}

async fn full_handshake(
    endpoint: &Endpoint, server: SocketAddr,
) -> Result<(quinn::Connection, f64, u64, u64, u64, u64)> {
    let t0 = Instant::now();
    let conn = endpoint.connect(server, "localhost")?.await?;
    let ms = t0.elapsed().as_secs_f64() * 1000.0;
    let (tx, rx, ctx, crx) = setup_bytes(&conn);
    Ok((conn, ms, tx, rx, ctx, crx))
}

async fn reconnect(
    endpoint: &Endpoint, server: SocketAddr, no_resumption: bool,
) -> Result<(quinn::Connection, f64, u64, u64, u64, u64, &'static str, bool)> {
    if no_resumption {
        let (conn, ms, tx, rx, ctx, crx) = full_handshake(endpoint, server).await?;
        return Ok((conn, ms, tx, rx, ctx, crx, "full-1rtt", false));
    }
    let connecting = endpoint.connect(server, "localhost")?;
    let t0 = Instant::now();
    match connecting.into_0rtt() {
        Ok((conn, accepted)) => {
            let ms = t0.elapsed().as_secs_f64() * 1000.0;
            let zrtt = accepted.await;
            let (tx, rx, ctx, crx) = setup_bytes(&conn);
            Ok((conn, ms, tx, rx, ctx, crx, "0rtt", zrtt))
        }
        Err(connecting) => {
            let conn = connecting.await?;
            let ms = t0.elapsed().as_secs_f64() * 1000.0;
            let (tx, rx, ctx, crx) = setup_bytes(&conn);
            Ok((conn, ms, tx, rx, ctx, crx, "full-1rtt", false))
        }
    }
}

fn setup_bytes(conn: &quinn::Connection) -> (u64, u64, u64, u64) {
    let s = conn.stats();
    (s.udp_tx.bytes, s.udp_rx.bytes, s.frame_tx.crypto, s.frame_rx.crypto)
}

async fn app_ping(conn: &quinn::Connection) -> Result<()> {
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(b"ping").await?;
    send.finish()?;
    let _ = recv.read_to_end(64).await?;
    Ok(())
}

#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self, _end_entity: &CertificateDer<'_>, _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>, _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self, message: &[u8], cert: &CertificateDer<'_>, dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss,
            &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self, message: &[u8], cert: &CertificateDer<'_>, dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss,
            &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
