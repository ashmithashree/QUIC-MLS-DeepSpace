use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{atomic::AtomicBool, Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use mls_rs::{
    identity::{
        basic::{BasicCredential, BasicIdentityProvider},
        SigningIdentity,
    },
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, ExtensionList, MlsMessage,
};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;
use quic_mls::{
    apply_commit_window, run_commit_receiver, send_window_and_trim, CommitLog, CommitSink,
    ExportSecret, MlsClientConfig, MlsServerConfig, ControlMessage, PreambleSocket, write_message,
};
use quinn::{AsyncUdpSocket, ClientConfig, Endpoint, EndpointConfig, IdleTimeout, ServerConfig, TransportConfig};
use tokio::io::AsyncWriteExt;

const CS: CipherSuite = CipherSuite::CURVE25519_AES128;

// The paper's tunable transcript length `tl`: a total-byte budget across all
// preamble datagrams for one arm()/`send_preamble` call (still truncates to
// the earliest contiguous prefix of the backlog if set low, for research
// use). Unlike the old transport-parameter mechanism this replaced, there is
// no single-packet ceiling to size a small default around -- datagrams are
// chunked to fit the network MTU regardless of how large the backlog is --
// so the default is effectively unbounded.
const DEFAULT_TRANSCRIPT_MAX_BYTES: usize = usize::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Alice,
    Bob,
}

struct Args {
    role: Role,
    bind_addr: SocketAddr,
    peer_addr: Option<SocketAddr>,
    bootstrap_dir: PathBuf,
    commit_interval: Duration,
    duration: Duration,
    out_path: PathBuf,
    blackout_on: Duration,
    blackout_off: Duration,
    report_timeout: Duration,
    transcript_max_bytes: usize,
}

fn parse_args() -> Args {
    let mut role = None;
    let mut bind_addr = None;
    let mut peer_addr = None;
    let mut bootstrap_dir = PathBuf::from("/tmp/testbed-bootstrap");
    let mut commit_interval = Duration::from_secs(30);
    let mut duration = Duration::from_secs(120);
    let mut out_path = PathBuf::from("testbed-runner.csv");
    let mut blackout_on = Duration::from_secs(0);
    let mut blackout_off = Duration::from_secs(0);
    let mut report_timeout = Duration::from_secs(10);
    let mut transcript_max_bytes = DEFAULT_TRANSCRIPT_MAX_BYTES;

    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--role" => {
                let v = args.next().expect("--role requires a value");
                role = Some(match v.as_str() {
                    "alice" => Role::Alice,
                    "bob" => Role::Bob,
                    other => panic!("--role must be alice|bob, got {other}"),
                });
            }
            "--bind" => {
                let v = args.next().expect("--bind requires a value");
                bind_addr = Some(v.parse().expect("bad --bind addr"));
            }
            "--peer" => {
                let v = args.next().expect("--peer requires a value");
                peer_addr = Some(v.parse().expect("bad --peer addr"));
            }
            "--bootstrap-dir" => {
                bootstrap_dir = PathBuf::from(args.next().expect("--bootstrap-dir requires a value"));
            }
            "--commit-interval-secs" => {
                let v = args.next().expect("--commit-interval-secs requires a value");
                commit_interval = Duration::from_secs(v.parse().expect("bad --commit-interval-secs"));
            }
            "--duration-secs" => {
                let v = args.next().expect("--duration-secs requires a value");
                duration = Duration::from_secs(v.parse().expect("bad --duration-secs"));
            }
            "--out" => {
                out_path = PathBuf::from(args.next().expect("--out requires a value"));
            }
            "--blackout-on-secs" => {
                let v = args.next().expect("--blackout-on-secs requires a value");
                blackout_on = Duration::from_secs(v.parse().expect("bad --blackout-on-secs"));
            }
            "--blackout-off-secs" => {
                let v = args.next().expect("--blackout-off-secs requires a value");
                blackout_off = Duration::from_secs(v.parse().expect("bad --blackout-off-secs"));
            }
            "--report-timeout-secs" => {
                let v = args.next().expect("--report-timeout-secs requires a value");
                report_timeout = Duration::from_secs(v.parse().expect("bad --report-timeout-secs"));
            }
            "--transcript-max-bytes" => {
                let v = args.next().expect("--transcript-max-bytes requires a value");
                transcript_max_bytes = v.parse().expect("bad --transcript-max-bytes");
            }
            other => panic!("unknown flag: {other}"),
        }
    }

    Args {
        role: role.expect("--role alice|bob is required"),
        bind_addr: bind_addr.expect("--bind IP:PORT is required"),
        peer_addr,
        bootstrap_dir,
        commit_interval,
        duration,
        out_path,
        blackout_on,
        blackout_off,
        report_timeout,
        transcript_max_bytes,
    }
}

fn transport_config(idle: Duration) -> Arc<TransportConfig> {
    let mut cfg = TransportConfig::default();
    cfg.max_idle_timeout(Some(IdleTimeout::try_from(idle).unwrap()));
    Arc::new(cfg)
}

// `EndpointConfig::default()` has `grease_quic_bit: true` (RFC 9287): quinn-proto
// will then randomly clear the fixed bit (0x40) on outgoing packets to prevent
// implementations from ossifying on it always being set. That's exactly the bit
// PreambleSocket's marker check depends on to prove a datagram is real QUIC
// traffic (RFC 9000 S17.2/17.3.1 -- absent greasing, quinn-proto never clears
// both the header-form bit and the fixed bit together). Confirmed empirically:
// with greasing left on, real 1-RTT short-header packets were intermittently
// intercepted and dropped by the preamble layer instead of reaching quinn.
// Must be disabled on both endpoints for the discriminator to hold.
fn endpoint_config_without_quic_bit_greasing() -> EndpointConfig {
    let mut cfg = EndpointConfig::default();
    cfg.grease_quic_bit(false);
    cfg
}

struct Telemetry {
    f: tokio::fs::File,
    mode: &'static str,
}

impl Telemetry {
    async fn open(path: &Path, mode: &'static str) -> std::io::Result<Self> {
        let mut f = tokio::fs::File::create(path).await?;
        f.write_all(b"timestamp_ms,event,epoch,bytes,latency_ms,mode\n").await?;
        f.flush().await?;
        Ok(Self { f, mode })
    }

    async fn row(&mut self, event: &str, epoch: u64, bytes: u64, latency_ms: f64) -> std::io::Result<()> {
        let line = format!(
            "{},{},{},{},{:.3},{}\n",
            now_ms(),
            event,
            epoch,
            bytes,
            latency_ms,
            self.mode
        );
        self.f.write_all(line.as_bytes()).await?;
        self.f.flush().await
    }
}

fn now_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()
}

fn make_client(name: &str) -> Client<impl mls_rs::client_builder::MlsConfig> {
    let crypto = RustCryptoProvider::new();
    let cs_provider = crypto.cipher_suite_provider(CS).unwrap();
    let (sk, pk) = cs_provider.signature_key_generate().unwrap();
    let cred = BasicCredential::new(name.as_bytes().to_vec()).into_credential();
    let sig_id = SigningIdentity::new(cred, pk);
    Client::builder()
        .crypto_provider(RustCryptoProvider::new())
        .identity_provider(BasicIdentityProvider::new())
        .signing_identity(sig_id, sk, CS)
        .build()
}

async fn wait_for_file(path: &Path, poll: Duration) -> Vec<u8> {
    loop {
        if let Ok(b) = std::fs::read(path) {
            return b;
        }
        tokio::time::sleep(poll).await;
    }
}

async fn wait_for_ready(path: &Path, after: u64, poll: Duration) -> u64 {
    loop {
        if let Ok(s) = std::fs::read_to_string(path) {
            if let Ok(c) = s.trim().parse::<u64>() {
                if c > after {
                    return c;
                }
            }
        }
        tokio::time::sleep(poll).await;
    }
}

async fn bootstrap_bob(dir: &Path) -> Box<dyn quic_mls::ExportSecret> {
    std::fs::create_dir_all(dir).unwrap();
    let kp_path = dir.join("bob_kp.bin");
    let welcome_path = dir.join("welcome.bin");

    let bob = make_client("bob");
    let bob_kp = bob
        .generate_key_package_message(ExtensionList::new(), ExtensionList::new(), None)
        .unwrap();
    std::fs::write(&kp_path, bob_kp.to_bytes().unwrap()).unwrap();

    let welcome_bytes = wait_for_file(&welcome_path, Duration::from_millis(50)).await;
    let welcome = MlsMessage::from_bytes(&welcome_bytes).unwrap();
    let (bob_group, _) = bob.join_group(None, &welcome, None).unwrap();
    Box::new(bob_group)
}

async fn bootstrap_alice(dir: &Path) -> impl quic_mls::ExportSecret + 'static {
    std::fs::create_dir_all(dir).unwrap();
    let kp_path = dir.join("bob_kp.bin");
    let welcome_path = dir.join("welcome.bin");

    let alice = make_client("alice");
    let mut alice_group = alice
        .create_group(ExtensionList::new(), ExtensionList::new(), None)
        .unwrap();

    let bob_kp_bytes = wait_for_file(&kp_path, Duration::from_millis(50)).await;
    let bob_kp = MlsMessage::from_bytes(&bob_kp_bytes).unwrap();

    let commit_out = alice_group.commit_builder().add_member(bob_kp).unwrap().build().unwrap();
    alice_group.apply_pending_commit().unwrap();

    let welcome_bytes = commit_out.welcome_messages[0].to_bytes().unwrap();
    std::fs::write(&welcome_path, welcome_bytes).unwrap();

    alice_group
}

async fn run_bob(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let bob_group = bootstrap_bob(&args.bootstrap_dir).await;
    let bob_group = Arc::new(Mutex::new(bob_group));
    // Shared between the preamble socket's sink (handshake-adjacent catch-up,
    // applied as soon as a preamble datagram decodes, independent of and not
    // synchronized with MlsSession::read_handshake/write_handshake -- see the
    // race-condition note in the plan this was built from) and
    // run_commit_receiver (steady-state catch-up, post-handshake) below --
    // the same counter, so the two mechanisms agree on how far behind Bob
    // is instead of racing or double-applying.
    let local_epoch = Arc::new(Mutex::new(0u64));

    let mode = "0rtt";
    let mut out = Telemetry::open(&args.out_path, mode).await?;
    let ready_path = args.bootstrap_dir.join("bob_ready.bin");

    let scenario_start = Instant::now();
    let mut cycle: u64 = 0;
    let idle = args.report_timeout + args.commit_interval + Duration::from_secs(30);

    // MlsServerConfig is single-use (start_session takes ownership of the group
    // once), so a fresh one is required for every connection -- but the Endpoint
    // itself (and its bound UDP socket) is reused across reconnects.
    let make_server_config = |idle: Duration| {
        let mut cfg = ServerConfig::with_crypto(Arc::new(MlsServerConfig::new(
            Box::new(Arc::clone(&bob_group)),
        )));

        cfg.transport_config(transport_config(idle));
        cfg
    };

    // Decodes and applies a preamble datagram's commit window directly
    // against `bob_group`, independent of the QUIC handshake in flight on
    // the same socket. `apply_commit_window`'s existing `epoch <=
    // local_epoch` skip is what makes this safe against replay: nothing at
    // this layer binds a preamble to a connection ID or packet number, so a
    // captured preamble could be replayed by anyone who can reach this port,
    // at any time -- idempotency is the only thing preventing that from
    // being reapplied or causing confusion (see PreambleSocket's docs).
    //
    // Lock order MUST match run_commit_receiver's (control.rs: group, then
    // local_epoch) exactly. This sink runs synchronously inside
    // PreambleSocket::poll_recv, which the endpoint driver calls for the
    // whole lifetime of the socket -- concurrently, by construction, with
    // run_commit_receiver's steady-state loop on the same two mutexes for
    // the same connection. Acquiring them in the opposite order here would
    // be a textbook AB-BA deadlock: run_commit_receiver holding `group` and
    // waiting on `local_epoch` while this sink holds `local_epoch` and
    // waits on `group` freezes not just commit application but the entire
    // endpoint driver, since nothing else can proceed until poll_recv
    // returns.
    let sink: CommitSink = {
        let bob_group = Arc::clone(&bob_group);
        let local_epoch = Arc::clone(&local_epoch);
        Arc::new(move |window: &[(u64, Vec<u8>)]| {
            let mut group = bob_group.lock().unwrap();
            let mut epoch = local_epoch.lock().unwrap();
            let before = *epoch;
            match apply_commit_window(&mut *group, window, &mut epoch) {
                Ok(()) if *epoch != before => {
                    tracing::info!(
                        from_epoch = before,
                        to_epoch = *epoch,
                        "quic-mls: applied preamble commit window"
                    );
                }
                Ok(()) => {}
                Err(e) => {
                    tracing::warn!(
                        local_epoch = *epoch,
                        "quic-mls: could not apply preamble commit window: {e}"
                    );
                }
            }
        })
    };
    let bob_socket = tokio::net::UdpSocket::bind(args.bind_addr).await?;
    let preamble_socket: Arc<dyn AsyncUdpSocket> =
        Arc::new(PreambleSocket::new(bob_socket, Some(sink)));
    let endpoint = Endpoint::new_with_abstract_socket(
        endpoint_config_without_quic_bit_greasing(),
        Some(make_server_config(idle)),
        preamble_socket,
        quinn::default_runtime().expect("tokio runtime available"),
    )?;

    while scenario_start.elapsed() < args.duration {
        cycle += 1;
        if cycle > 1 {
            endpoint.set_server_config(Some(make_server_config(idle)));
        }
        std::fs::write(&ready_path, format!("{cycle}")).unwrap();

        let remaining = args.duration.saturating_sub(scenario_start.elapsed());
        let t0 = Instant::now();
        let incoming = match tokio::time::timeout(remaining + Duration::from_secs(30), endpoint.accept()).await {
            Ok(Some(incoming)) => incoming,
            _ => break,
        };
        let connecting = incoming.accept()?;
        let (conn, zero_rtt_accepted) = connecting
                .into_0rtt()
                .unwrap_or_else(|_| panic!("0-RTT keys not available"));

        let (send, recv) = match tokio::time::timeout(args.report_timeout, conn.accept_bi()).await {
            Ok(Ok(v)) => v,
            _ => {
                tracing::warn!("cycle {cycle}: stale connection (accept_bi timed out), abandoning and retrying");
                conn.close(0u32.into(), b"stale");
                continue;
            }
        };
        let is_0rtt = recv.is_0rtt();

        out.row("zero_rtt_available", 0, 0, t0.elapsed().as_secs_f64() * 1000.0).await?;
        out.row(if is_0rtt { "control_stream_0rtt" } else { "control_stream_1rtt" }, 0, 0, 0.0).await?;
        zero_rtt_accepted.await;
        let event = if cycle == 1 { "handshake_confirmed" } else { "reconnect_handshake_confirmed" };
        // By this point MlsSession::read_handshake has already applied any
        // transcript embedded in the peer's Initial flight, so local_epoch
        // reflects handshake-time catch-up, not just steady-state trickle.
        let epoch_now = *local_epoch.lock().unwrap();
        out.row(event, epoch_now, 0, t0.elapsed().as_secs_f64() * 1000.0).await?;

        let should_report = Arc::new(AtomicBool::new(true));
        let recv_task = tokio::spawn(run_commit_receiver(
            Arc::clone(&bob_group),
            send,
            recv,
            should_report,
            Arc::clone(&local_epoch),
        ));

        let _ = conn.closed().await;
        recv_task.abort();

        if args.blackout_off.is_zero() {
            break;
        }
    }

    out.row("done", 0, 0, 0.0).await?;
    Ok(())
}

async fn run_alice(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let peer_addr = args.peer_addr.ok_or("--peer is required for alice")?;

    let alice_group = bootstrap_alice(&args.bootstrap_dir).await;
    let alice_group = Arc::new(Mutex::new(CommitLog::new(alice_group)));

    let mode = "0rtt";
    let mut out = Telemetry::open(&args.out_path, mode).await?;
    let ready_path = args.bootstrap_dir.join("bob_ready.bin");

    let scenario_start = Instant::now();
    let mut epoch: u64 = 0;
    let mut cycle: u64 = 0;
    let mut last_ready_seen: u64 = 0;

    let idle = args.report_timeout + args.commit_interval + Duration::from_secs(30);

    let make_client_config = | idle: Duration| {
        let mut cfg = ClientConfig::new(Arc::new(MlsClientConfig::new(
            Box::new(Arc::clone(&alice_group)),
        )));
        cfg.transport_config(transport_config(idle));
        cfg
    };

    // Alice never receives a preamble in this testbed (Bob never originates
    // commits), so `sink = None` -- see PreambleSocket::new's docs. Kept as
    // a concrete handle (not just the `Arc<dyn AsyncUdpSocket>` handed to
    // quinn below) so `send_preamble` can be called on it directly from the
    // reconnect loop.
    let alice_socket = tokio::net::UdpSocket::bind(args.bind_addr).await?;
    let preamble_socket = Arc::new(PreambleSocket::new(alice_socket, None));
    let endpoint = Endpoint::new_with_abstract_socket(
        endpoint_config_without_quic_bit_greasing(),
        None,
        Arc::clone(&preamble_socket) as Arc<dyn AsyncUdpSocket>,
        quinn::default_runtime().expect("tokio runtime available"),
    )?;

    while scenario_start.elapsed() < args.duration {
        last_ready_seen = wait_for_ready(&ready_path, last_ready_seen, Duration::from_millis(20)).await;

        cycle += 1;
        let t0 = Instant::now();

        let (conn, mut send, mut recv) = if cycle == 1 {
            let connecting = endpoint.connect_with(make_client_config(idle), peer_addr, "localhost")?;
            let (conn, zero_rtt_accepted) = connecting
                .into_0rtt()
                .unwrap_or_else(|_| panic!("0-RTT keys not available"));

            let (mut send, recv) = conn.open_bi().await?;
            write_message(&mut send, &ControlMessage::Hello).await?;
            out.row("zero_rtt_available", 0, 0, t0.elapsed().as_secs_f64() * 1000.0).await?;

            let ok = zero_rtt_accepted.await;
            let event = if ok { "handshake_0rtt_accepted" } else { "handshake_0rtt_rejected" };
            out.row(event, 0, 0, t0.elapsed().as_secs_f64() * 1000.0).await?;
            (conn, send, recv)
        } else {
            // The commit transcript travels as one or more plaintext UDP
            // datagrams sent directly over the same socket quinn will use
            // for the QUIC connection, immediately before attempting the
            // reconnect -- not embedded in the handshake itself (see
            // PreambleSocket::send_preamble). A single best-effort
            // fire-and-forget send: never awaited under `report_timeout`,
            // since a dropped preamble datagram is simply retried (with an
            // equal-or-larger window) on the next contact window, per
            // invariant 1.
            let window = alice_group.lock().unwrap().window_bytes();
            let t_preamble = Instant::now();
            let embedded_bytes = preamble_socket
                .send_preamble(peer_addr, &window, args.transcript_max_bytes)
                .await?;
            out.row(
                "handshake_transcript_embedded",
                epoch,
                embedded_bytes,
                t_preamble.elapsed().as_secs_f64() * 1000.0,
            )
            .await?;

            let connect_result = tokio::time::timeout(args.report_timeout, async {
                let connecting = endpoint.connect_with(make_client_config(idle), peer_addr, "localhost")?;
                let (conn, zero_rtt_accepted) = connecting
                    .into_0rtt()
                    .unwrap_or_else(|_| panic!("0-RTT keys not available"));

                let (mut send, recv) = conn.open_bi().await?;
                write_message(&mut send, &ControlMessage::Hello).await?;
                let ok = zero_rtt_accepted.await;
                Ok::<_, Box<dyn std::error::Error>>((conn, send, recv, ok))
            })
            .await;

            // Alice never blocks waiting on Bob to catch up (invariant 1):
            // a failed cycle just moves on to the next contact window. Her
            // commit log is untouched (checkpoint/trim only ever advance
            // via a successful Report round trip in send_window_and_trim),
            // so the next attempt offers an equal-or-larger window.
            let (conn, send, recv, ok) = match connect_result {
                Ok(Ok(v)) => v,
                _ => continue,
            };

            out.row("zero_rtt_available", 0, 0, t0.elapsed().as_secs_f64() * 1000.0).await?;
            let event = if ok { "reconnect_handshake_0rtt_accepted" } else { "reconnect_handshake_0rtt_rejected" };
            out.row(event, 0, 0, t0.elapsed().as_secs_f64() * 1000.0).await?;
            (conn, send, recv)
        };

        if cycle > 1 {
            let t_flush = Instant::now();
            let bytes_sent = send_window_and_trim(&alice_group, &mut send, &mut recv, args.report_timeout).await?;
            out.row("blackout_recovery_flush", epoch, bytes_sent as u64, t_flush.elapsed().as_secs_f64() * 1000.0)
                .await?;
        }

        let phase_start = Instant::now();
        let on_duration = if args.blackout_on.is_zero() {
            args.duration.saturating_sub(scenario_start.elapsed())
        } else {
            args.blackout_on
        };

        let mut ticker = tokio::time::interval(args.commit_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let deadline = std::cmp::min(scenario_start + args.duration, phase_start + on_duration);
        
        while phase_start.elapsed() < on_duration && scenario_start.elapsed() < args.duration {
            tokio::select! {
                _ = ticker.tick() => {}
                _ = tokio::time::sleep_until(deadline.into()) => break,
            }
            if phase_start.elapsed() >= on_duration || scenario_start.elapsed() >= args.duration {
                break;
            }

            let t1 = Instant::now();
            alice_group.lock().unwrap().create_commit().unwrap();
            let cpu_ms = t1.elapsed().as_secs_f64() * 1000.0;
            epoch += 1;
            let t2 = Instant::now();
            let bytes_sent = send_window_and_trim(&alice_group, &mut send, &mut recv, args.report_timeout).await?;
            conn.force_key_update();
            let net_ms = t2.elapsed().as_secs_f64() * 1000.0;
            out.row("commit_cpu", epoch, 0, cpu_ms).await?;
            out.row("commit_net", epoch, bytes_sent as u64, net_ms).await?;
        }

        conn.close(0u32.into(), b"blackout");

        if args.blackout_off.is_zero() || scenario_start.elapsed() >= args.duration {
            break;
        }

        out.row("blackout_start", epoch, 0, 0.0).await?;

        let blackout_start = Instant::now();
        let mut bo_ticker = tokio::time::interval(args.commit_interval);
        bo_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let bo_deadline = std::cmp::min(scenario_start + args.duration, blackout_start + args.blackout_off);
        while blackout_start.elapsed() < args.blackout_off && scenario_start.elapsed() < args.duration {
            tokio::select! {
                _ = bo_ticker.tick() => {}
                _ = tokio::time::sleep_until(bo_deadline.into()) => break,
            }
            if blackout_start.elapsed() >= args.blackout_off || scenario_start.elapsed() >= args.duration {
                break;
            }
            alice_group.lock().unwrap().create_commit().unwrap();
            epoch += 1;
            out.row("commit_offline", epoch, 0, 0.0).await?;
        }

        out.row("blackout_end", epoch, 0, 0.0).await?;
    }

    out.row("done", epoch, 0, 0.0).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let args = parse_args();
    match args.role {
        Role::Alice => run_alice(args).await,
        Role::Bob => run_bob(args).await,
    }
}
