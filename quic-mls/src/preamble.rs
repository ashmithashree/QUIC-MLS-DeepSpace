//Note:
// Out-of-band UDP datagram channel for the commit-window catch-up
// transcript, replacing the earlier transport-parameter approach in
// transcript.rs (removed after hitting a hard CRYPTO-stream fragmentation
// ceiling around 1500–2553 bytes).
// References:
//   RFC 9000 section 17.2 / section 17.3.1 (fixed-bit requirement on every real QUIC
//   packet the property PREAMBLE_MARKER relies on), IETF, Iyengar & 
//   Thomson, 2021.
//     https://www.rfc-editor.org/rfc/rfc9000.html
//   RFC 9287 (QUIC bit greasing — why grease_quic_bit(false) is required
//   on both peers for the marker to be reliable), IETF, Thomson, 2022.
//     https://www.rfc-editor.org/rfc/rfc9287.html
//   quinn crate docs, AsyncUdpSocket trait.
//     https://docs.rs/quinn/latest/quinn/trait.AsyncUdpSocket.html
//   Design lineage: replay-from-checkpoint recovery follows the custody
//   transfer pattern in DTN — RFC 9171, IETF, Burleigh
//   et al., 2022, and RFC 4838 (DTN Architecture), IETF, Cerf et al., 2007.
//     https://www.rfc-editor.org/rfc/rfc9171.html
//     https://www.rfc-editor.org/rfc/rfc4838.html
//======================================================================================================================
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

const PREAMBLE_MARKER: u8 = 0x00;

fn is_preamble_marker(first_byte: u8) -> bool {
    first_byte & 0xC0 == 0
}


const MAX_DATAGRAM_PAYLOAD: usize = 1200;


const TRANSCRIPT_HEADER_LEN: usize = 4 + 4;

fn entry_wire_len(entry: &(u64, Vec<u8>)) -> usize {
    8 + 4 + entry.1.len()
}


pub type CommitSink = Arc<dyn Fn(&[(u64, Vec<u8>)]) + Send + Sync>;
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

#[allow(clippy::type_complexity)] // matches the (epoch, commit_bytes) shape used throughout this module
fn parse_preamble(datagram: &[u8]) -> Option<Result<Vec<(u64, Vec<u8>)>, TranscriptDecodeError>> {
    let first = *datagram.first()?;
    if !is_preamble_marker(first) {
        return None;
    }
    Some(decode_transcript(&datagram[1..]))
}


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
    
    pub fn new(io: UdpSocket, sink: Option<CommitSink>) -> Self {
        Self { io, sink, preamble_bytes_sent: AtomicU64::new(0) }
    }

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

