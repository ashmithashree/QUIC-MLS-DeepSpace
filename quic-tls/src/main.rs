//! tls-baseline: QUIC + TLS 1.3 baseline runner for the QUIC-MLS deep-space evaluation.
//!
//! Control condition against which QUIC-MLS is compared. Uses Quinn's *default* rustls
//! TLS 1.3 session, so — unlike the MLS path — every reconnection pays a real handshake.
//! It optionally attempts 0-RTT resumption (RFC 8446); `--no-resumption` disables it to
//! model the ticket-expiry case a long blackout forces.
//!
//! Measures, per connection, on the CLIENT side:
//!   * handshake / reconnection latency (Instant-based, over the emulated link)
//!   * on-wire setup bytes (udp tx/rx snapshot the moment the connection is established,
//!     before any application payload flows)
//!   * whether a reconnection used 0-RTT or fell back to a full 1-RTT handshake
//!
//! Output: one JSON object per line (JSONL) on stdout, tagged with channel + rtt label,
//! so securityBudget.py can ingest it the same way it ingests the MLS runs. Netem is
//! applied EXTERNALLY by apply_channel.sh; the runner only records and labels.
//!
//! Mirrors echo-server's proven cert/GSO handling so it builds and transmits on the WSL2
//! veth testbed unchanged.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig};
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
    /// Echo server. Start this in ns-bob before the client.
    Server {
        /// Address to bind, e.g. 10.200.1.2:4443
        #[arg(long)]
        listen: SocketAddr,
    },
    /// Measurement client. Start this in ns-alice.
    Client {
        /// Server address to connect to, e.g. 10.200.1.2:4443
        #[arg(long)]
        server: SocketAddr,
        /// Local bind address inside ns-alice, e.g. 10.200.1.1:0
        #[arg(long, default_value = "10.200.1.1:0")]
        bind: SocketAddr,
        /// Channel label, tag only (leo | geo | lunar | mars).
        #[arg(long, default_value = "unspecified")]
        channel: String,
        /// One-way delay hint in ms — tag only, echoed into each record so analysis can
        /// correlate latency with the emulated link. Use the same convention as the MLS runs.
        #[arg(long, default_value_t = 0)]
        rtt_ms: u64,
        /// Number of reconnections to perform after the initial handshake.
        #[arg(long, default_value_t = 16)]
        reconnects: u32,
        /// Simulated offline gap between closing a connection and reconnecting (ms).
        #[arg(long, default_value_t = 0)]
        blackout_ms: u64,
        /// Disable TLS resumption / 0-RTT, forcing a full 1-RTT handshake on every
        /// reconnection — the RFC 8446 ticket-expiry case after a long blackout.
        #[arg(long, default_value_t = false)]
        no_resumption: bool,
    },
}

/// One measurement record. Serialised as a JSON line.
#[derive(Serialize)]
struct Record {
    role: &'static str,
    phase: &'static str, // "initial_handshake" | "reconnect"
    channel: String,
    rtt_ms: u64,
    iteration: u32, // 0 for the initial handshake
    handshake_ms: f64,
    setup_tx_bytes: u64,
    setup_rx_bytes: u64,
    crypto_frames_tx: u64,
    crypto_frames_rx: u64,
    mode: &'static str, // "full-1rtt" | "0rtt"
    zero_rtt_accepted: bool,
}

impl Record {
    fn emit(&self) {
        println!("{}", serde_json::to_string(self).expect("serialise record"));
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // rustls 0.23 needs a process-default crypto provider before any builder runs.
    // aws-lc-rs is the workspace default (same one echo-server/quic-mls compile against).
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    match Cli::parse().role {
        Role::Server { listen } => run_server(listen).await,
        Role::Client {
            server,
            bind,
            channel,
            rtt_ms,
            reconnects,
            blackout_ms,
            no_resumption,
        } => {
            run_client(
                server,
                bind,
                channel,
                rtt_ms,
                reconnects,
                blackout_ms,
                no_resumption,
            )
            .await
        }
    }
}

/// TransportConfig with GSO disabled. WSL2's veth driver falsely reports GSO support,
/// making quinn-udp's sendmsg fail silently (zero bytes). Same fix as echo-server.
/// (quinn issue #2399). Applied to BOTH endpoints.
fn wsl2_safe_transport() -> Arc<TransportConfig> {
    let mut transport = TransportConfig::default();
    transport.enable_segmentation_offload(false);
    Arc::new(transport)
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

fn build_server_config() -> Result<ServerConfig> {
    // Self-signed cert (benchmark only). rcgen 0.14 API, PEM->DER via rustls-pemfile,
    // copied from echo-server so it is known to compile in this workspace.
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
    server_crypto.max_early_data_size = u32::MAX; // accept 0-RTT early data

    let mut server_config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));
    server_config.transport = wsl2_safe_transport();
    Ok(server_config)
}

async fn run_server(listen: SocketAddr) -> Result<()> {
    let endpoint = Endpoint::server(build_server_config()?, listen)?;
    eprintln!("[server] listening on {listen}");

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
    // Accept 0-RTT early data when available; otherwise complete the handshake normally.
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

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

fn build_client_config(no_resumption: bool) -> Result<ClientConfig> {
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
    client_config.transport_config(wsl2_safe_transport());
    Ok(client_config)
}

async fn run_client(
    server: SocketAddr,
    bind: SocketAddr,
    channel: String,
    rtt_ms: u64,
    reconnects: u32,
    blackout_ms: u64,
    no_resumption: bool,
) -> Result<()> {
    let mut endpoint = Endpoint::client(bind)?;
    endpoint.set_default_client_config(build_client_config(no_resumption)?);

    // --- Initial handshake (always full 1-RTT: no ticket exists yet) ---
    let (conn, ms, tx, rx, ctx, crx) = full_handshake(&endpoint, server).await?;
    Record {
        role: "client",
        phase: "initial_handshake",
        channel: channel.clone(),
        rtt_ms,
        iteration: 0,
        handshake_ms: ms,
        setup_tx_bytes: tx,
        setup_rx_bytes: rx,
        crypto_frames_tx: ctx,
        crypto_frames_rx: crx,
        mode: "full-1rtt",
        zero_rtt_accepted: false,
    }
    .emit();
    app_ping(&conn).await?; // one small exchange so the server issues a ticket
    conn.close(0u32.into(), b"initial-done");

    // --- Reconnections ---
    for i in 1..=reconnects {
        if blackout_ms > 0 {
            tokio::time::sleep(Duration::from_millis(blackout_ms)).await;
        }

        let (conn, ms, tx, rx, ctx, crx, mode, zrtt) =
            reconnect(&endpoint, server, no_resumption).await?;
        Record {
            role: "client",
            phase: "reconnect",
            channel: channel.clone(),
            rtt_ms,
            iteration: i,
            handshake_ms: ms,
            setup_tx_bytes: tx,
            setup_rx_bytes: rx,
            crypto_frames_tx: ctx,
            crypto_frames_rx: crx,
            mode,
            zero_rtt_accepted: zrtt,
        }
        .emit();
        let _ = app_ping(&conn).await;
        conn.close(0u32.into(), b"reconnect-done");
    }

    endpoint.wait_idle().await;
    Ok(())
}

async fn full_handshake(
    endpoint: &Endpoint,
    server: SocketAddr,
) -> Result<(quinn::Connection, f64, u64, u64, u64, u64)> {
    let t0 = Instant::now();
    let conn = endpoint.connect(server, "localhost")?.await?;
    let ms = t0.elapsed().as_secs_f64() * 1000.0;
    let (tx, rx, ctx, crx) = setup_bytes(&conn);
    Ok((conn, ms, tx, rx, ctx, crx))
}

async fn reconnect(
    endpoint: &Endpoint,
    server: SocketAddr,
    no_resumption: bool,
) -> Result<(
    quinn::Connection,
    f64,
    u64,
    u64,
    u64,
    u64,
    &'static str,
    bool,
)> {
    if no_resumption {
        let (conn, ms, tx, rx, ctx, crx) = full_handshake(endpoint, server).await?;
        return Ok((conn, ms, tx, rx, ctx, crx, "full-1rtt", false));
    }

    let connecting = endpoint.connect(server, "localhost")?;
    let t0 = Instant::now();
    // Err(Connecting) means no usable ticket yet (expected on reconnect #1) -> full handshake.
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

/// Setup-cost snapshot: on-wire bytes and CRYPTO frame counts, taken the moment the
/// connection is established and before any app payload flows.
fn setup_bytes(conn: &quinn::Connection) -> (u64, u64, u64, u64) {
    let s = conn.stats();
    (
        s.udp_tx.bytes,
        s.udp_rx.bytes,
        s.frame_tx.crypto,
        s.frame_rx.crypto,
    )
}

/// One tiny request/response so the connection is genuinely used and the server issues a
/// resumption ticket. Called after the setup-bytes snapshot, so it never pollutes it.
async fn app_ping(conn: &quinn::Connection) -> Result<()> {
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(b"ping").await?;
    send.finish()?;
    let _ = recv.read_to_end(64).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Cert verification skip (benchmark only)
// ---------------------------------------------------------------------------

/// Accepts any server certificate. Safe ONLY because this is a closed-loop benchmark on an
/// emulated link; never use in a real deployment.
#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}