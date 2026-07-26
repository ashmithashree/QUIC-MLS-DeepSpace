//! Out-of-band delivery for the commit-window catch-up transcript.
//!
//! Earlier this rode along inside the QUIC handshake as a custom transport
//! parameter (see the removed `write_transcript_param`/`read_transcript_param`
//! in `transcript.rs`). That has a floor (the backlog has to fit) and a
//! ceiling (quinn-proto's `TransportParameters::read` rejects the combined
//! blob once it needs more than one packet) with no value of `tl` that
//! satisfies both for a real blackout-sized backlog. This module sidesteps
//! that entirely: the transcript travels as plain UDP datagrams sent
//! alongside (not inside) the QUIC handshake, intercepted at the socket
//! layer before quinn-proto ever sees them.
//!
//! `PreambleSocket` implements `quinn::AsyncUdpSocket` by wrapping a plain
//! `tokio::net::UdpSocket` directly -- deliberately *not* going through
//! `quinn_udp::UdpSocketState` (the fast path `quinn::TokioRuntime` uses).
//! That path unconditionally, opportunistically enables `UDP_GRO` on the
//! real socket at construction time (see `quinn-udp`'s `unix.rs`), and that
//! enablement happens at the OS level, independent of whatever this
//! wrapper's own `max_receive_segments()` reports upward to quinn's
//! `Endpoint` -- overriding that method to `1` bounds only what the layer
//! *above* the wrapper does with buffer sizing, not what the real kernel
//! socket may coalesce on receive. A plain `SOCK_DGRAM` socket never enables
//! GRO/GSO in the first place, so "one datagram per recv/send call" holds
//! for real rather than merely being asserted.
//!
//! **Caller requirement:** the `quinn::EndpointConfig` used with this socket
//! (on *both* peers) must have `grease_quic_bit(false)` set. quinn-proto
//! defaults `grease_quic_bit` to `true` (RFC 9287) and will then randomly
//! clear the fixed bit (0x40) on outgoing packets specifically to prevent
//! implementations from depending on it always being set -- which is
//! exactly what [`PREAMBLE_MARKER`]'s discriminator does. With greasing
//! left on, real 1-RTT short-header packets are intermittently
//! misidentified as preambles and dropped instead of reaching quinn
//! (confirmed empirically, not just in theory -- this doesn't show up in
//! this module's own unit tests since those never construct a real
//! `quinn::Endpoint`).
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::net::UdpSocket;

use crate::transcript::{decode_transcript, encode_transcript, TranscriptDecodeError};

/// Leading byte of every preamble datagram. RFC 9000 requires every real
/// QUIC packet's first byte to set the long-header bit (0x80) or, for a
/// short-header packet, the fixed bit (0x40) -- Sections 17.2 and 17.3.1;
/// the fixed bit is mandatory on every packet a compliant sender (including
/// quinn-proto) emits. A byte with both bits clear (`& 0xC0 == 0`) can
/// therefore never be the first byte of real QUIC traffic on either side,
/// making it a sound discriminator for datagrams sharing this UDP port.
///
/// Note this is *not* the same as `transcript::encode_transcript`'s own
/// inner magic (`b"QMT1"`, leading byte 0x51 = `0b0101_0001`) -- that byte
/// has the fixed bit set and would be indistinguishable from a plausible
/// short-header first byte if used alone as the wire-level marker. This
/// constant is a dedicated outer layer specifically chosen to satisfy the
/// RFC 9000 property above; the inner blob format is reused unmodified.
const PREAMBLE_MARKER: u8 = 0x00;

fn is_preamble_marker(first_byte: u8) -> bool {
    first_byte & 0xC0 == 0
}

/// Comfortably under a non-jumbogram Ethernet MTU (1500) minus typical
/// IP/UDP header overhead, leaving room for the 1-byte marker.
const MAX_DATAGRAM_PAYLOAD: usize = 1200;

/// Mirrors `encode_transcript`'s own internal header-size accounting
/// (MAGIC + 4-byte count) so a bucket built by [`bucket_window`] is
/// guaranteed to fit when re-encoded via `encode_transcript`.
const TRANSCRIPT_HEADER_LEN: usize = 4 + 4;

fn entry_wire_len(entry: &(u64, Vec<u8>)) -> usize {
    8 + 4 + entry.1.len()
}

/// Callback invoked with a decoded commit window on the receiving side.
/// Bob's callback applies it directly via [`crate::group::apply_commit_window`]
/// against his live group; Alice (who never receives a preamble in this
/// testbed) passes `None` instead of a sink -- see [`PreambleSocket::new`].
pub type CommitSink = Arc<dyn Fn(&[(u64, Vec<u8>)]) + Send + Sync>;

/// Splits `window` into MTU-sized, independently self-contained transcript
/// blobs. Each returned bucket is a complete, valid `encode_transcript`
/// input on its own (decodable without the others), truncated to the
/// earliest contiguous prefix of `window` that fits both:
///   - `per_datagram_budget`: bytes available in a single UDP datagram, and
///   - `total_budget`: the paper's tunable `tl`, a cumulative cap across all
///     buckets (`usize::MAX` disables it).
///
/// A gap is never introduced mid-window: if an entry doesn't fit (either
/// budget), every entry after it is dropped too, matching
/// `encode_transcript`'s own earliest-contiguous-prefix truncation policy,
/// just generalized across as many datagrams as the backlog needs.
fn bucket_window(
    window: &[(u64, Vec<u8>)],
    total_budget: usize,
    per_datagram_budget: usize,
) -> Vec<Vec<(u64, Vec<u8>)>> {
    let mut buckets = Vec::new();
    let mut current: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut current_len = TRANSCRIPT_HEADER_LEN;
    let mut total_len = 0usize;

    for entry in window {
        let entry_len = entry_wire_len(entry);

        if TRANSCRIPT_HEADER_LEN + entry_len > per_datagram_budget {
            break; // wouldn't fit in an empty datagram either -- stop here
        }
        if total_len + entry_len > total_budget {
            break;
        }
        if current_len + entry_len > per_datagram_budget {
            buckets.push(std::mem::take(&mut current));
            current_len = TRANSCRIPT_HEADER_LEN;
        }
        current.push(entry.clone());
        current_len += entry_len;
        total_len += entry_len;
    }
    if !current.is_empty() {
        buckets.push(current);
    }
    buckets
}

/// Recognizes and decodes a preamble datagram's payload.
///
/// Returns `None` if `datagram` doesn't even carry the marker (this is
/// ordinary QUIC traffic and must be passed through unchanged); `Some(_)`
/// once the marker matches, regardless of whether the inner blob then
/// decodes cleanly -- a marker match already proves the datagram is not
/// real QUIC traffic (see [`PREAMBLE_MARKER`]'s doc comment), so it is
/// never forwarded to quinn either way.
#[allow(clippy::type_complexity)] // matches the (epoch, commit_bytes) shape used throughout this module
fn parse_preamble(datagram: &[u8]) -> Option<Result<Vec<(u64, Vec<u8>)>, TranscriptDecodeError>> {
    let first = *datagram.first()?;
    if !is_preamble_marker(first) {
        return None;
    }
    Some(decode_transcript(&datagram[1..]))
}

/// A `quinn::AsyncUdpSocket` that carries the commit-window preamble
/// out-of-band, on the same UDP 4-tuple quinn's own QUIC traffic uses.
pub struct PreambleSocket {
    io: UdpSocket,
    sink: Option<CommitSink>,
    preamble_bytes_sent: AtomicU64,
}

impl std::fmt::Debug for PreambleSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreambleSocket").finish_non_exhaustive()
    }
}

impl PreambleSocket {
    /// `sink` is `Some(...)` on the receiving side (Bob): a decoded window
    /// is applied by calling it directly, independent of and never
    /// synchronized with `MlsSession::read_handshake`/`write_handshake` for
    /// whatever connection attempt is in flight on the same socket -- see
    /// the module-level race-condition note in the plan this was built
    /// from. `None` on the sending side (Alice in this testbed): a
    /// datagram matching the marker is still never forwarded to quinn (it's
    /// provably not QUIC traffic), it's just logged and dropped instead of
    /// applied anywhere.
    pub fn new(io: UdpSocket, sink: Option<CommitSink>) -> Self {
        Self { io, sink, preamble_bytes_sent: AtomicU64::new(0) }
    }

    /// Sends `window` (truncated to fit `total_budget`, the paper's `tl`)
    /// to `peer` as one or more preamble datagrams, over the same socket
    /// quinn will use for the QUIC connection that follows. Meant to be
    /// awaited once, synchronously, immediately before the reconnect's
    /// `endpoint.connect_with(...)` call -- a single best-effort
    /// fire-and-forget send. Never blocks on the peer: a dropped datagram
    /// is simply retried (with an equal-or-larger window, since the
    /// sender's checkpoint only advances on a confirmed `Report` round
    /// trip) on the next contact window, per the sender-never-blocks
    /// invariant.
    ///
    /// Returns the total bytes actually put on the wire (marker + blob,
    /// summed across every datagram sent) for telemetry.
    pub async fn send_preamble(
        &self,
        peer: SocketAddr,
        window: &[(u64, Vec<u8>)],
        total_budget: usize,
    ) -> io::Result<u64> {
        let mut total = 0u64;
        for bucket in bucket_window(window, total_budget, MAX_DATAGRAM_PAYLOAD - 1) {
            let blob = encode_transcript(&bucket, usize::MAX);
            if blob.is_empty() {
                continue;
            }
            let mut datagram = Vec::with_capacity(1 + blob.len());
            datagram.push(PREAMBLE_MARKER);
            datagram.extend_from_slice(&blob);
            self.io.send_to(&datagram, peer).await?;
            total += datagram.len() as u64;
        }
        self.preamble_bytes_sent.fetch_add(total, Ordering::Relaxed);
        Ok(total)
    }

    pub fn preamble_bytes_sent(&self) -> u64 {
        self.preamble_bytes_sent.load(Ordering::Relaxed)
    }

    fn handle_preamble_datagram(&self, payload: &[u8]) {
        match decode_transcript(payload) {
            Ok(window) => match &self.sink {
                Some(sink) => sink(&window),
                None => tracing::warn!(
                    entries = window.len(),
                    "quic-mls: received preamble datagram with no sink configured; dropping"
                ),
            },
            Err(e) => {
                // New, always-on parsing surface: this decodes arbitrary
                // network input for the lifetime of the socket, not just
                // during an active handshake (see module docs / plan's
                // "new risk" section). Never panics -- decode_transcript
                // is exhaustively fuzz-tested for exactly this in
                // transcript.rs -- and a malformed datagram is just logged
                // and dropped, same as any other adversarial input.
                tracing::warn!("quic-mls: malformed preamble datagram: {e}");
            }
        }
    }
}

struct PreamblePoller {
    socket: Arc<PreambleSocket>,
}

impl std::fmt::Debug for PreamblePoller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreamblePoller").finish_non_exhaustive()
    }
}

impl UdpPoller for PreamblePoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.socket.io.poll_send_ready(cx)
    }
}

impl AsyncUdpSocket for PreambleSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(PreamblePoller { socket: self })
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.io.try_send_to(transmit.contents, transmit.destination)?;
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut filled = 0usize;
        loop {
            if filled >= bufs.len() {
                return Poll::Ready(Ok(filled));
            }
            match self.io.poll_recv_ready(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => {
                    return if filled > 0 { Poll::Ready(Ok(filled)) } else { Poll::Ready(Err(e)) };
                }
                Poll::Pending => {
                    return if filled > 0 { Poll::Ready(Ok(filled)) } else { Poll::Pending };
                }
            }
            match self.io.try_recv_from(&mut bufs[filled]) {
                Ok((len, addr)) => match parse_preamble(&bufs[filled][..len]) {
                    // Intercepted: applied (or logged+dropped) internally,
                    // never handed to quinn. Keep draining -- an
                    // all-preamble-this-poll batch must not be reported as
                    // "0 real datagrams, still ready" (which could spin);
                    // we only return once genuinely out of data or we have
                    // at least one real datagram to report.
                    Some(_) => self.handle_preamble_datagram(&bufs[filled][1..len]),
                    None => {
                        meta[filled] = RecvMeta { addr, len, stride: len, ecn: None, dst_ip: None };
                        filled += 1;
                    }
                },
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if filled > 0 {
                        return Poll::Ready(Ok(filled));
                    }
                    continue; // back to poll_recv_ready to register the waker
                }
                Err(e) => {
                    return if filled > 0 { Poll::Ready(Ok(filled)) } else { Poll::Ready(Err(e)) };
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::{apply_commit_window, CommitLog, ExportSecret};
    use mls_rs::{
        identity::{basic::{BasicCredential, BasicIdentityProvider}, SigningIdentity},
        CipherSuite, CipherSuiteProvider, Client, CryptoProvider, ExtensionList,
    };
    use mls_rs_crypto_rustcrypto::RustCryptoProvider;

    const CS: CipherSuite = CipherSuite::CURVE25519_AES128;

    fn make_client(name: &str) -> Client<impl mls_rs::client_builder::MlsConfig> {
        let crypto = RustCryptoProvider::new();
        let cs_provider = crypto.cipher_suite_provider(CS).unwrap();
        let (secret_key, public_key) = cs_provider.signature_key_generate().unwrap();
        let credential = BasicCredential::new(name.as_bytes().to_vec()).into_credential();
        let signing_identity = SigningIdentity::new(credential, public_key);
        Client::builder()
            .crypto_provider(RustCryptoProvider::new())
            .identity_provider(BasicIdentityProvider::new())
            .signing_identity(signing_identity, secret_key, CS)
            .build()
    }

    fn sample_window() -> Vec<(u64, Vec<u8>)> {
        vec![
            (1, vec![0xAA; 10]),
            (2, vec![0xBB; 20]),
            (3, vec![0xCC; 5]),
        ]
    }

    #[test]
    fn parse_preamble_ignores_non_preamble_bytes() {
        assert!(parse_preamble(&[]).is_none());
        // 0x80.. -> long-header bit set.
        assert!(parse_preamble(&[0x80, 0, 0]).is_none());
        // 0x40.. -> short-header, fixed bit set.
        assert!(parse_preamble(&[0x40, 0, 0]).is_none());
        // 0xC0.. -> both set (long header, fixed bit set too).
        assert!(parse_preamble(&[0xC0, 0, 0]).is_none());
    }

    #[test]
    fn a_real_quic_long_header_packet_is_never_mistaken_for_a_preamble() {
        // Same RFC 9001 test-vector-derived Initial packet bytes used in
        // transcript.rs's equivalent negative test (see keys.rs's
        // derive_initial_keys_server_remote_decrypts_known_client_packet).
        let header: [u8; 19] = [
            0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0xb8, 0x58, 0xec, 0x6f, 0x80, 0x45, 0x2b,
            0x00, 0x00, 0x40, 0x21, 0x00,
        ];
        #[rustfmt::skip]
        let ciphertext_and_tag: [u8; 32] = [
            0x3e, 0xf5, 0x08, 0x07, 0xb8, 0x41, 0x91, 0xa1, 0x96, 0xf7, 0x60, 0xa6, 0xda, 0xd1, 0xe9, 0xd1, 0xc4,
            0x30, 0xc4, 0x89, 0x52, 0xcb, 0xa0, 0x14, 0x82, 0x50, 0xc2, 0x1c, 0x0a, 0x6a, 0x70, 0xe1,
        ];
        let mut packet_bytes = Vec::new();
        packet_bytes.extend_from_slice(&header);
        packet_bytes.extend_from_slice(&ciphertext_and_tag);

        assert!(parse_preamble(&packet_bytes).is_none());
    }

    #[test]
    fn a_real_quic_short_header_packet_is_never_mistaken_for_a_preamble() {
        // Constructed per RFC 9000 S17.3.1's mandatory bit layout for a
        // short header: bit 7 (0x80) clear = short header; bit 6 (0x40)
        // set = fixed bit, required on every packet a compliant sender
        // emits; remaining bits (spin, reserved, key phase, pn length) are
        // connection-specific and irrelevant to this discriminator, so
        // several representative values are exercised rather than one.
        let candidates: &[u8] = &[0x40, 0x41, 0x5d, 0x60, 0x7f];
        for &first_byte in candidates {
            assert_eq!(first_byte & 0xC0, 0x40, "fixture must actually be a valid short-header first byte");
            let mut packet_bytes = vec![first_byte];
            packet_bytes.extend_from_slice(&[0xAB; 8]); // destination connection ID
            packet_bytes.extend_from_slice(&[0x00, 0x01]); // packet number
            packet_bytes.extend_from_slice(&[0x11; 20]); // ciphertext + tag
            assert!(parse_preamble(&packet_bytes).is_none(), "first byte {first_byte:#x} must not be mistaken for a preamble");
        }
    }

    #[test]
    fn parse_preamble_round_trips_a_bucket() {
        let window = sample_window();
        let mut datagram = vec![PREAMBLE_MARKER];
        datagram.extend_from_slice(&encode_transcript(&window, usize::MAX));

        match parse_preamble(&datagram) {
            Some(Ok(decoded)) => assert_eq!(decoded, window),
            other => panic!("expected a decoded preamble, got {other:?}"),
        }
    }

    #[test]
    fn parse_preamble_rejects_malformed_payload_without_panicking() {
        // Marker present, but the "blob" after it is garbage of every
        // length -- must never panic, and must never fall through as "not
        // a preamble" (the marker byte alone already proves it isn't QUIC
        // traffic, so it must stay intercepted either way).
        for len in 0..40 {
            let mut datagram = vec![PREAMBLE_MARKER];
            datagram.extend((0..len).map(|i| (i * 13 + 7) as u8));
            match parse_preamble(&datagram) {
                Some(_) => {} // intercepted, decode may fail -- both fine
                None => panic!("a marker-prefixed datagram must always be intercepted"),
            }
        }
    }

    #[test]
    fn bucket_window_keeps_every_entry_under_an_unbounded_budget() {
        let window = sample_window();
        let buckets = bucket_window(&window, usize::MAX, MAX_DATAGRAM_PAYLOAD - 1);
        let flattened: Vec<_> = buckets.into_iter().flatten().collect();
        assert_eq!(flattened, window);
    }

    #[test]
    fn bucket_window_splits_a_backlog_too_large_for_one_datagram() {
        // ~518-byte commits, 10 of them (~5.18KB) -- the exact shape of the
        // scenario that livelocked under the old transport-parameter
        // mechanism at every tried `--transcript-max-bytes` value.
        let window: Vec<(u64, Vec<u8>)> = (1..=10u64).map(|e| (e, vec![0xEE; 518])).collect();
        let buckets = bucket_window(&window, usize::MAX, MAX_DATAGRAM_PAYLOAD - 1);

        assert!(buckets.len() > 1, "must not fit in a single MTU-sized datagram");
        for bucket in &buckets {
            let blob = encode_transcript(bucket, usize::MAX);
            assert!(blob.len() < MAX_DATAGRAM_PAYLOAD, "bucket must fit the per-datagram budget including the marker");
        }
        let flattened: Vec<_> = buckets.into_iter().flatten().collect();
        assert_eq!(flattened, window, "no entry may be dropped when the total budget is unbounded");
    }

    #[test]
    fn bucket_window_truncates_to_earliest_contiguous_prefix_under_a_total_budget() {
        let window = sample_window();
        let header_len = TRANSCRIPT_HEADER_LEN;
        let first_entry_len = entry_wire_len(&window[0]);
        let budget = first_entry_len; // room for exactly one entry's payload bytes

        let buckets = bucket_window(&window, budget, MAX_DATAGRAM_PAYLOAD - 1);
        let flattened: Vec<_> = buckets.into_iter().flatten().collect();
        assert_eq!(flattened, vec![window[0].clone()]);
        let _ = header_len; // budget is entry-bytes-only; header overhead is per-datagram, not cumulative
    }

    #[test]
    fn bucket_window_zero_budget_yields_nothing() {
        let window = sample_window();
        assert!(bucket_window(&window, 0, MAX_DATAGRAM_PAYLOAD - 1).is_empty());
    }

    /// End-to-end: Alice's `CommitLog` accrues a blackout-sized backlog,
    /// `send_preamble` puts it on the wire over a real loopback UDP socket,
    /// and the receiving side's decode-and-apply pipeline (the same
    /// `parse_preamble` + `apply_commit_window` combination `poll_recv`
    /// uses) catches Bob up in one shot -- reproducing the scenario that
    /// livelocked under the old transport-parameter mechanism at every
    /// tried `--transcript-max-bytes` value.
    #[tokio::test]
    async fn preamble_delivers_a_blackout_sized_backlog_over_a_real_socket() {
        let alice = make_client("alice");
        let bob = make_client("bob");

        let mut alice_group = alice.create_group(ExtensionList::new(), ExtensionList::new(), None).unwrap();
        let bob_kp = bob.generate_key_package_message(ExtensionList::new(), ExtensionList::new(), None).unwrap();
        let commit_out = alice_group.commit_builder().add_member(bob_kp).unwrap().build().unwrap();
        alice_group.apply_pending_commit().unwrap();
        let (mut bob_group, _) = bob.join_group(None, &commit_out.welcome_messages[0], None).unwrap();

        let mut alice_log = CommitLog::new(alice_group);
        const N: u64 = 10;
        for _ in 0..N {
            alice_log.create_commit().unwrap();
        }
        // Bob's plain group never sees any of these -- the blackout.

        let sender_io = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_io = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver_io.local_addr().unwrap();
        let sender = PreambleSocket::new(sender_io, None);

        let window = alice_log.window_bytes();
        let sent = sender.send_preamble(receiver_addr, &window, usize::MAX).await.unwrap();
        assert!(sent > 0);

        let mut bob_epoch = 0u64;
        let mut buf = vec![0u8; 2048];
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while bob_epoch < N {
            let (len, _) =
                tokio::time::timeout_at(deadline, receiver_io.recv_from(&mut buf))
                    .await
                    .expect("preamble datagrams must all arrive on loopback well within 5s")
                    .unwrap();
            match parse_preamble(&buf[..len]) {
                Some(Ok(chunk)) => {
                    apply_commit_window(&mut bob_group, &chunk, &mut bob_epoch).unwrap();
                }
                other => panic!("expected a decodable preamble chunk, got {other:?}"),
            }
        }
        assert_eq!(bob_epoch, N, "Bob must fully catch up from a single arm()'s worth of datagrams");
    }
}
