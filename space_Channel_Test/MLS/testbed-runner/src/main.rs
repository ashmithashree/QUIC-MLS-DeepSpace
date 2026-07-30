// Note
// Empirical measurement harness: runs Alice/Bob over Linux network-namespace
// + tc netem emulated channels, driving the connect/commit/blackout/
// reconnect cycle and logging per-event CSV telemetry that
// securityBudget.py later reduces to SSOR/RC/SB.
// References:
//   RFC 9287 (QUIC bit greasing — grease_quic_bit(false) requirement,
//   verified above endpoint_config_without_quic_bit_greasing), IETF,
//   Thomson, 2022.
//     https://www.rfc-editor.org/rfc/rfc9287.html
//   RFC 9000 section 17.2 / section 17.3.1 (fixed-bit invariant the marker depends on).
//     https://www.rfc-editor.org/rfc/rfc9000.html
//   Linux tc-netem(8) — network emulation used to construct the LEO/GEO/
//   Lunar/Mars channel profiles this harness runs against.
//     https://man7.org/linux/man-pages/man8/tc-netem.8.html
//   Emulation methodology follows: Kosek et al., "Exploring the QUIC and
//   TCP Interplay for Satellite Networks"
//   Channel parameter provenance: Blanchet, "Deep Space QUIC Profile"
//======================================================================================================================
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
    apply_commit_window, run_report_receiver, run_report_sender, CommitLog, CommitSink,
    ExportSecret, MlsClientConfig, MlsServerConfig, ControlMessage, PreambleSocket, write_message,
};
use quinn::{AsyncUdpSocket, ClientConfig, Endpoint, EndpointConfig, IdleTimeout, ServerConfig, TransportConfig};
use tokio::io::AsyncWriteExt;

const CS: CipherSuite = CipherSuite::CURVE25519_AES128;


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

async fn wait_for_ready(path: &Path, after: u64, poll: Duration, timeout: Duration) -> u64 {
    tracing::info!(after, ?timeout, "waiting for peer ready-cycle file");
    let start = Instant::now();
    loop {
        if let Ok(s) = std::fs::read_to_string(path) {
            if let Ok(c) = s.trim().parse::<u64>() {
                if c > after {
                    tracing::info!(cycle = c, elapsed_ms = start.elapsed().as_millis() as u64,
                        "peer ready-cycle observed");
                    return c;
                }
            }
        }
        if start.elapsed() >= timeout {
            tracing::warn!(after, elapsed_ms = start.elapsed().as_millis() as u64,
                "wait_for_ready timed out -- proceeding with stale cycle value, \
                 peer's connection-close notification may still be in flight or lost");
            return after;
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

    let local_epoch = Arc::new(Mutex::new(0u64));

    let (epoch_tx, epoch_rx) = tokio::sync::watch::channel(0u64);

    let mode = "0rtt";
    let mut out = Telemetry::open(&args.out_path, mode).await?;
    let ready_path = args.bootstrap_dir.join("bob_ready.bin");

    let scenario_start = Instant::now();
    let mut cycle: u64 = 0;
    let idle = args.report_timeout + args.commit_interval + Duration::from_secs(30);


    let make_server_config = |idle: Duration| {
        let mut cfg = ServerConfig::with_crypto(Arc::new(MlsServerConfig::new(
            Box::new(Arc::clone(&bob_group)),
        )));

        cfg.transport_config(transport_config(idle));
        cfg
    };

   
    let sink: CommitSink = {
        let bob_group = Arc::clone(&bob_group);
        let local_epoch = Arc::clone(&local_epoch);
        let epoch_tx = epoch_tx.clone();
        Arc::new(move |window: &[(u64, Vec<u8>)]| {
            let (new_epoch, changed) = {
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
                (*epoch, *epoch != before)
            };

            if changed {
                epoch_tx.send_replace(new_epoch);
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

        drop(recv);

        out.row("zero_rtt_available", 0, 0, t0.elapsed().as_secs_f64() * 1000.0).await?;
        out.row(if is_0rtt { "control_stream_0rtt" } else { "control_stream_1rtt" }, 0, 0, 0.0).await?;
        zero_rtt_accepted.await;
        let event = if cycle == 1 { "handshake_confirmed" } else { "reconnect_handshake_confirmed" };

        let epoch_now = *local_epoch.lock().unwrap();
        out.row(event, epoch_now, 0, t0.elapsed().as_secs_f64() * 1000.0).await?;

        let should_report = Arc::new(AtomicBool::new(true));
        let report_task = tokio::spawn(run_report_sender(
            send,
            epoch_rx.clone(),
            should_report,
        ));

        let _ = conn.closed().await;
        report_task.abort();

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


    let alice_socket = tokio::net::UdpSocket::bind(args.bind_addr).await?;
    let preamble_socket = Arc::new(PreambleSocket::new(alice_socket, None));
    let endpoint = Endpoint::new_with_abstract_socket(
        endpoint_config_without_quic_bit_greasing(),
        None,
        Arc::clone(&preamble_socket) as Arc<dyn AsyncUdpSocket>,
        quinn::default_runtime().expect("tokio runtime available"),
    )?;

    while scenario_start.elapsed() < args.duration {
        last_ready_seen = wait_for_ready(&ready_path, last_ready_seen, Duration::from_millis(20), args.report_timeout).await;

        cycle += 1;
        let t0 = Instant::now();

        let (conn, _send, recv) = if cycle == 1 {
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

            let (conn, send, recv, ok) = match connect_result {
                Ok(Ok(v)) => v,
                Err(_) => {
                    tracing::warn!(cycle, elapsed_ms = t0.elapsed().as_millis() as u64,
                        "reconnect attempt timed out after report_timeout, retrying next contact window");
                    out.row("reconnect_attempt_timed_out", epoch, 0,
                        t0.elapsed().as_secs_f64() * 1000.0).await?;
                    continue;
                }
                Ok(Err(e)) => {
                    tracing::warn!(cycle, error = %e,
                        "reconnect attempt failed (not a timeout), retrying next contact window");
                    out.row("reconnect_attempt_failed", epoch, 0,
                        t0.elapsed().as_secs_f64() * 1000.0).await?;
                    continue;
                }
            };

            out.row("zero_rtt_available", 0, 0, t0.elapsed().as_secs_f64() * 1000.0).await?;
            let event = if ok { "reconnect_handshake_0rtt_accepted" } else { "reconnect_handshake_0rtt_rejected" };
            out.row(event, 0, 0, t0.elapsed().as_secs_f64() * 1000.0).await?;
            (conn, send, recv)
        };


        let report_task = tokio::spawn(run_report_receiver(Arc::clone(&alice_group), recv));

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

            let window = alice_group.lock().unwrap().window_bytes();
            let bytes_sent = preamble_socket
                .send_preamble(peer_addr, &window, args.transcript_max_bytes)
                .await?;
            conn.force_key_update();
            let net_ms = t2.elapsed().as_secs_f64() * 1000.0;
            out.row("commit_cpu", epoch, 0, cpu_ms).await?;
            out.row("commit_net", epoch, bytes_sent as u64, net_ms).await?;
        }

        conn.close(0u32.into(), b"blackout");
        report_task.abort();

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
