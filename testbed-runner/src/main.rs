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
use quic_mls::{run_commit_receiver, send_window_and_trim, CommitLog, ExportSecret, MlsClientConfig, MlsServerConfig};
use quinn::{ClientConfig, Endpoint, ServerConfig};
use tokio::io::AsyncWriteExt;

const CS: CipherSuite = CipherSuite::CURVE25519_AES128;

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
    zero_rtt: bool,
}

fn parse_args() -> Args {
    let mut role = None;
    let mut bind_addr = None;
    let mut peer_addr = None;
    let mut bootstrap_dir = PathBuf::from("/tmp/testbed-bootstrap");
    let mut commit_interval = Duration::from_secs(30);
    let mut duration = Duration::from_secs(120);
    let mut out_path = PathBuf::from("testbed-runner.csv");
    let mut zero_rtt = false;

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
            "--zero-rtt" => {
                zero_rtt = true;
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
        zero_rtt,
    }
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

async fn bootstrap_bob(dir: &Path) -> impl quic_mls::ExportSecret + 'static {
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
    bob_group
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

    let mode = if args.zero_rtt { "0rtt" } else { "1rtt" };
    let server_config = if args.zero_rtt {
        ServerConfig::with_crypto(Arc::new(MlsServerConfig::new_with_early_data(Box::new(Arc::clone(
            &bob_group,
        )))))
    } else {
        ServerConfig::with_crypto(Arc::new(MlsServerConfig::new(Box::new(Arc::clone(&bob_group)))))
    };

    let endpoint = Endpoint::server(server_config, args.bind_addr)?;
    std::fs::write(args.bootstrap_dir.join("bob_ready.bin"), b"1").unwrap();
    let mut out = Telemetry::open(&args.out_path, mode).await?;

    let t0 = Instant::now();
    let incoming = endpoint.accept().await.ok_or("no incoming connection")?;

    let conn = if args.zero_rtt {
        let connecting = incoming.accept()?;
        // Deliberately not awaiting the ZeroRttAccepted future here: per
        // quinn-proto's own source, the `accepted_0rtt` flag it resolves
        // from is only ever written on the client side -- on the server
        // it's initialized false and never touched again, so awaiting it
        // here can hang forever instead of telling us anything. is_0rtt()
        // on the stream we actually receive (below) is the real signal;
        // see the caveat already noted in session.rs's early_data_accepted.
        let (conn, _zero_rtt_accepted) = connecting
            .into_0rtt()
            .unwrap_or_else(|_| panic!("0-RTT keys not available"));
        out.row("zero_rtt_available", 0, 0, t0.elapsed().as_secs_f64() * 1000.0).await?;
        conn
    } else {
        let conn = incoming.await?;
        out.row("handshake", 0, 0, t0.elapsed().as_secs_f64() * 1000.0).await?;
        conn
    };

    let (send, recv) = conn.accept_bi().await?;
    let is_0rtt = recv.is_0rtt();
out.row(if is_0rtt { "control_stream_0rtt" } else { "control_stream_1rtt" }, 0, 0, 0.0).await?;
    let should_report = Arc::new(AtomicBool::new(true));
    tokio::spawn(run_commit_receiver(Arc::clone(&bob_group), send, recv, should_report));

    tokio::time::sleep(args.duration).await;
    out.row("done", 0, 0, 0.0).await?;
    conn.close(0u32.into(), b"done");
    Ok(())
}

async fn run_alice(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let peer_addr = args.peer_addr.ok_or("--peer is required for alice")?;

    let alice_group = bootstrap_alice(&args.bootstrap_dir).await;
    let alice_group = Arc::new(Mutex::new(CommitLog::new(alice_group)));

    let mode = if args.zero_rtt { "0rtt" } else { "1rtt" };
    let client_config = if args.zero_rtt {
        ClientConfig::new(Arc::new(MlsClientConfig::new_with_early_data(Box::new(Arc::clone(
            &alice_group,
        )))))
    } else {
        ClientConfig::new(Arc::new(MlsClientConfig::new(Box::new(Arc::clone(&alice_group)))))
    };

    let mut endpoint = Endpoint::client(args.bind_addr)?;
    wait_for_file(&args.bootstrap_dir.join("bob_ready.bin"), Duration::from_millis(20)).await;
    endpoint.set_default_client_config(client_config);

    let mut out = Telemetry::open(&args.out_path, mode).await?;

    let t0 = Instant::now();
    let connecting = endpoint.connect(peer_addr, "localhost")?;

    let (conn, zero_rtt_accepted) = if args.zero_rtt {
        let (conn, zero_rtt_accepted) = connecting
            .into_0rtt()
            .unwrap_or_else(|_| panic!("0-RTT keys not available"));
        out.row("zero_rtt_available", 0, 0, t0.elapsed().as_secs_f64() * 1000.0).await?;
        (conn, Some(zero_rtt_accepted))
    } else {
        let conn = connecting.await?;
        out.row("handshake", 0, 0, t0.elapsed().as_secs_f64() * 1000.0).await?;
        (conn, None)
    };

    let (mut send, mut recv) = conn.open_bi().await?;

    // NOT calling create_commit() until the handshake has actually settled:
    // MlsSession derives its "handshake"/"1-rtt" keys from this same live,
    // shared group (see session.rs write_handshake), on quinn's internal
    // background driver, asynchronously and without any lock against the
    // app. If create_commit() advances the group to a new epoch before that
    // background derivation finishes reading the old one, Alice's handshake
    // keys stop matching Bob's -- the connection can never decrypt anything
    // again (confirmed live: an unrecoverable "failed to authenticate
    // packet" retry storm). Awaiting zero_rtt_accepted is safe *here*
    // because, per quinn-proto, it's only ever driven meaningfully on the
    // client; Bob (the server) must not wait on his own copy (see run_bob).
    if let Some(zero_rtt_accepted) = zero_rtt_accepted {
        let ok = zero_rtt_accepted.await;
        let event = if ok { "handshake_0rtt_accepted" } else { "handshake_0rtt_rejected" };
        out.row(event, 0, 0, t0.elapsed().as_secs_f64() * 1000.0).await?;
    }

    let start = Instant::now();
    let mut ticker = tokio::time::interval(args.commit_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut epoch: u64 = 0;

    while start.elapsed() < args.duration {
        ticker.tick().await;
        if start.elapsed() >= args.duration {
            break;
        }

        let t1 = Instant::now();
        alice_group.lock().unwrap().create_commit().unwrap();
        epoch += 1;

        let bytes_sent = send_window_and_trim(&alice_group, &mut send, &mut recv, Duration::from_secs(5)).await?;
        conn.force_key_update();

        let ms = t1.elapsed().as_secs_f64() * 1000.0;
        out.row("commit", epoch, bytes_sent as u64, ms).await?;
    }

    out.row("done", epoch, 0, 0.0).await?;
    conn.close(0u32.into(), b"done");
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