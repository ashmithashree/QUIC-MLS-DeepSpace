//! tls-baseline: QUIC + TLS 1.3 baseline runner for the QUIC-MLS deep-space evaluation.
//!
//! This is the control condition against which QUIC-MLS is compared. It uses Quinn's
//! *default* rustls TLS 1.3 session, so — unlike the MLS path — every reconnection pays
//! a real handshake. It optionally attempts 0-RTT resumption (RFC 8446), which the
//! `--no-resumption` flag disables to model the ticket-expiry case a long blackout forces.
//!
//! It measures, per connection, on the CLIENT side:
//!   * handshake / reconnection latency (Instant-based, wall clock over the emulated link)
//!   * on-wire bytes attributable to connection setup (udp tx/rx snapshot taken the moment
//!     the connection is established, before any application payload is sent)
//!   * whether the reconnection used 0-RTT or fell back to a full 1-RTT handshake
//!
//! Output is one JSON object per line on stdout (JSONL), tagged with the channel label and
//! RTT hint you pass in, so security_budget.py can ingest it the same way it ingests the
//! MLS runs. The runner does NOT set netem itself — the link profile is applied externally
//! by your namespace/tc scripts; the runner only records what it observes and the labels
//! you give it.
//!
//! Roles (run one of each, server first):
//!   tls-baseline server --listen 10.0.0.2:4443
//!   tls-baseline client --server 10.0.0.2:4443 --channel Mars --rtt-ms 1560000 \
//!                       --reconnects 16 --blackout-ms 15000
//!
//! Build/run on WSL2 (the sandbox has no Rust toolchain). See the three FLAG-ON-BUILD
//! notes below for the API points most likely to need a small tweak on your exact patch
//! versions of quinn 0.11.x / rustls 0.23.x.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Endpoint, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
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
        /// Address to bind, e.g. 10.0.0.2:4443
        #[arg(long)]
        listen: SocketAddr,
    },
    /// Measurement client. Start this in ns-alice.
    Client {
        /// Server address to connect to, e.g. 10.0.0.2:4443
        #[arg(long)]
        server: SocketAddr,
        /// Channel label, purely for tagging output (LEO | GEO | Lunar | Mars).
        #[arg(long, default_value = "unspecified")]
        channel: String,
        /// One-way or RTT hint in ms — tag only, echoed into each record so the
        /// analysis can correlate latency with the emulated link. Use the same
        /// convention you used for the MLS runs.
        #[arg(long, default_value_t = 0)]
        rtt_ms: u64,
        /// Number of reconnections to perform after the initial handshake.
        #[arg(long, default_value_t = 16)]
        reconnects: u32,
        /// Simulated offline gap between closing a connection and reconnecting (ms).
        /// Models the blackout window; the link itself is dark via netem, this just
        /// spaces the reconnect attempts.
        #[arg(long, default_value_t = 0)]
        blackout_ms: u64,
        /// Disable TLS session resumption / 0-RTT, forcing a full 1-RTT handshake on
        /// every reconnection. This is the RFC 8446 ticket-expiry case: after a long
        /// blackout no fresh ticket survives, so resumption is impossible.
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
        // One JSON object per line; security_budget.py reads these like the MLS runs.
        println!("{}", serde_json::to_string(self).expect("serialise record"));
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // rustls 0.23 requires a crypto provider to be installed before any config builder runs.
    // FLAG-ON-BUILD (1): if you enabled the `aws-lc-rs` feature instead of `ring`, swap this
    // for rustls::crypto::aws_lc_rs::default_provider().
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("install default rustls crypto provider");

    match Cli::parse().role {
        Role::Server { listen } => run_server(listen).await,
        Role::Client {
            server,
            channel,
            rtt_ms,
            reconnects,
            blackout_ms,
            no_resumption,
        } => {
            run_client(
                server,
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

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

fn build_server_config() -> Result<ServerConfig> {
    // Self-signed cert is fine: this is a benchmark, not a deployment. The client
    // skips verification (see SkipServerVerification). SAN "localhost" is what the
    // client passes as server_name on connect.
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .context("generate self-signed cert")?;
    let cert_der: CertificateDer<'static> = cert.cert.der().clone();
    let key_der: PrivateKeyDer<'static> =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .context("rustls server config")?;
    server_crypto.alpn_protocols = vec![ALPN.to_vec()];
    // Enable server-side acceptance of 0-RTT early data. If this field name differs on
    // your rustls patch, it's `max_early_data_size` on rustls::ServerConfig.
    server_crypto.max_early_data_size = u32::MAX;

    let server_config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));
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

    // Echo loop: read each bidi stream to end, write it back. This also ensures the
    // handshake fully completes and the server issues a session ticket for resumption.
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
    let provider = rustls::crypto::ring::default_provider();
    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification(Arc::new(provider))))
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![ALPN.to_vec()];

    if no_resumption {
        // Force a full 1-RTT handshake every time: no stored tickets, no early data.
        // Models the long-blackout case where any RFC 8446 ticket has expired.
        client_crypto.resumption = rustls::client::Resumption::disabled();
        client_crypto.enable_early_data = false;
    } else {
        // Default rustls client keeps an in-memory ticket store; enabling early data
        // lets the second+ connections attempt 0-RTT.
        client_crypto.enable_early_data = true;
    }

    Ok(ClientConfig::new(Arc::new(QuicClientConfig::try_from(
        client_crypto,
    )?)))
}

async fn run_client(
    server: SocketAddr,
    channel: String,
    rtt_ms: u64,
    reconnects: u32,
    blackout_ms: u64,
    no_resumption: bool,
) -> Result<()> {
    // Bind the client endpoint to an unspecified local port on the client-side interface.
    let bind: SocketAddr = "0.0.0.0:0".parse().unwrap();
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
    app_ping(&conn).await?; // exchange one small message so the server issues a ticket
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

/// Full 1-RTT handshake. Returns (conn, latency_ms, tx_bytes, rx_bytes, crypto_tx, crypto_rx).
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

/// Reconnection. Attempts 0-RTT when resumption is enabled; records which path was taken.
/// FLAG-ON-BUILD (2): `Connecting::into_0rtt()` returns Err(Connecting) when 0-RTT can't be
/// used (no ticket yet, or disabled), which we then await as a normal handshake — this is the
/// documented quinn 0.11 shape and the fallback is expected on the first reconnect.
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
    match connecting.into_0rtt() {
        Ok((conn, accepted)) => {
            // 0-RTT connection object is available immediately. The `accepted` future
            // resolves to whether the server actually accepted the early data. We time
            // to the point the connection is usable (0-RTT keys ready).
            let ms = t0.elapsed().as_secs_f64() * 1000.0;
            let zrtt = accepted.await;
            let (tx, rx, ctx, crx) = setup_bytes(&conn);
            Ok((conn, ms, tx, rx, ctx, crx, "0rtt", zrtt))
        }
        Err(connecting) => {
            // No usable ticket — full handshake fallback.
            let conn = connecting.await?;
            let ms = t0.elapsed().as_secs_f64() * 1000.0;
            let (tx, rx, ctx, crx) = setup_bytes(&conn);
            Ok((conn, ms, tx, rx, ctx, crx, "full-1rtt", false))
        }
    }
}

/// Snapshot of setup cost: bytes on the wire and CRYPTO frame counts, taken the moment the
/// connection is established and before any app payload flows, so it attributes to setup.
/// FLAG-ON-BUILD (3): field paths are quinn 0.11 `ConnectionStats`
/// (udp_tx.bytes / udp_rx.bytes / frame_tx.crypto / frame_rx.crypto). If a patch renames a
/// field, `conn.stats()` in your quinn version is the thing to check.
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
/// resumption ticket. Kept out of the setup-bytes snapshot by construction (called after it).
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

/// Accepts any server certificate. This is safe here ONLY because it is a closed-loop
/// benchmark on an emulated link; never use this in a real deployment.
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
