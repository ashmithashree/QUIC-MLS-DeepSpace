use bytes::Buf;
use quinn_proto::coding::Codec;
use quinn_proto::VarInt;

// Custom transport-parameter id for the embedded commit transcript. RFC 9000
// s7.4.1 reserves ids of the form `31 * N + 27` for GREASE and requires every
// other unrecognized id to be skipped by readers (confirmed against
// quinn-proto's TransportParameters::read, which does exactly that) -- so any
// id outside that pattern is safe to piggyback here. Chosen to be
// unmistakably non-standard rather than adjacent to the low, IANA-assigned ids.
pub const TRANSCRIPT_TP_ID: u64 = 0x5051_4d54; // ascii-ish "PQMT", arbitrary

const MAGIC: [u8; 4] = *b"QMT1";

/// Why a transcript blob failed to decode. Never constructed from a panic --
/// every path here returns this instead of indexing out of bounds.
#[derive(Debug, PartialEq, Eq)]
pub enum TranscriptDecodeError {
    /// Fewer bytes were present than the header/entries declared.
    Truncated,
    /// The leading magic bytes didn't match -- this isn't transcript data.
    BadMagic,
}

impl std::fmt::Display for TranscriptDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "transcript blob is truncated"),
            Self::BadMagic => write!(f, "transcript magic bytes did not match"),
        }
    }
}

impl std::error::Error for TranscriptDecodeError {}

/// Encodes `(epoch, commit_bytes)` entries into a self-delimited blob,
/// keeping the earliest contiguous entries that fit within `max_bytes`
/// (dropping the tail, not the head -- a receiver that only gets a prefix of
/// the gap still makes contiguous progress). Returns an empty `Vec` if
/// `window` is empty or `max_bytes` is 0 (the paper's tl=0 case: nothing is
/// sent, appropriate under a strongly-consistent delivery service).
pub fn encode_transcript(window: &[(u64, Vec<u8>)], max_bytes: usize) -> Vec<u8> {
    if window.is_empty() || max_bytes == 0 {
        return Vec::new();
    }

    let header_len = MAGIC.len() + 4;
    let mut included: Vec<&(u64, Vec<u8>)> = Vec::new();
    let mut body_len = 0usize;
    for entry in window {
        let entry_len = 8 + 4 + entry.1.len();
        if header_len + body_len + entry_len > max_bytes {
            break;
        }
        body_len += entry_len;
        included.push(entry);
    }
    if included.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::with_capacity(header_len + body_len);
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&(included.len() as u32).to_be_bytes());
    for (epoch, bytes) in included {
        out.extend_from_slice(&epoch.to_be_bytes());
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(bytes);
    }
    out
}

/// Inverse of [`encode_transcript`]. Rejects malformed or truncated input
/// without panicking.
pub fn decode_transcript(bytes: &[u8]) -> Result<Vec<(u64, Vec<u8>)>, TranscriptDecodeError> {
    if bytes.len() < MAGIC.len() + 4 {
        return Err(TranscriptDecodeError::Truncated);
    }
    if bytes[..MAGIC.len()] != MAGIC {
        return Err(TranscriptDecodeError::BadMagic);
    }

    let mut pos = MAGIC.len();
    let count = u32::from_be_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;

    // Cap the speculative allocation regardless of the (attacker-reachable)
    // declared count; the loop below still bounds-checks every entry.
    let mut out = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        if pos + 8 + 4 > bytes.len() {
            return Err(TranscriptDecodeError::Truncated);
        }
        let epoch = u64::from_be_bytes(bytes[pos..pos + 8].try_into().unwrap());
        pos += 8;
        let len = u32::from_be_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if pos + len > bytes.len() {
            return Err(TranscriptDecodeError::Truncated);
        }
        out.push((epoch, bytes[pos..pos + len].to_vec()));
        pos += len;
    }
    Ok(out)
}

/// Appends the transcript as one transport-parameter-shaped TLV
/// (varint id, varint len, payload) to `buf`. Writes nothing if the encoded
/// transcript is empty (empty window, or `max_bytes == 0`), so a peer with
/// no pending commits (e.g. Bob) produces byte-identical handshake data to
/// before this feature existed.
pub fn write_transcript_param(buf: &mut Vec<u8>, window: &[(u64, Vec<u8>)], max_bytes: usize) {
    let payload = encode_transcript(window, max_bytes);
    if payload.is_empty() {
        return;
    }
    VarInt::from_u64(TRANSCRIPT_TP_ID)
        .expect("id fits in a VarInt")
        .encode(buf);
    VarInt::from_u64(payload.len() as u64)
        .expect("transcript payload fits in a VarInt")
        .encode(buf);
    buf.extend_from_slice(&payload);
}

/// Scans a raw transport-parameter TLV stream for our custom id and decodes
/// it if present. Returns `None` if absent, malformed, or truncated -- never
/// panics, and never mistakes an arbitrary byte sequence (e.g. a real QUIC
/// packet) for a transcript, since that requires both a matching varint-
/// framed id and our magic bytes to line up.
pub fn read_transcript_param(buf: &[u8]) -> Option<Vec<(u64, Vec<u8>)>> {
    let mut reader: &[u8] = buf;
    while reader.has_remaining() {
        let id = VarInt::decode(&mut reader).ok()?.into_inner();
        let len = VarInt::decode(&mut reader).ok()?.into_inner() as usize;
        if reader.remaining() < len {
            return None;
        }
        if id == TRANSCRIPT_TP_ID {
            let payload = &reader[..len];
            return decode_transcript(payload).ok();
        }
        reader.advance(len);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_window() -> Vec<(u64, Vec<u8>)> {
        vec![
            (1, vec![0xAA; 10]),
            (2, vec![0xBB; 20]),
            (3, vec![0xCC; 5]),
        ]
    }

    #[test]
    fn round_trip() {
        let window = sample_window();
        let encoded = encode_transcript(&window, usize::MAX);
        let decoded = decode_transcript(&encoded).unwrap();
        assert_eq!(decoded, window);
    }

    #[test]
    fn tlv_round_trip_through_a_larger_buffer() {
        let window = sample_window();
        let mut buf = Vec::new();
        buf.extend_from_slice(b"unrelated-leading-bytes");
        write_transcript_param(&mut buf, &window, usize::MAX);
        buf.extend_from_slice(b"unrelated-trailing-bytes-that-are-not-a-tlv-at-all");

        // A scan starting mid-buffer (right at our TLV) must find it...
        let from_our_tlv = &buf[b"unrelated-leading-bytes".len()..];
        assert_eq!(read_transcript_param(from_our_tlv), Some(window));
    }

    #[test]
    fn empty_window_writes_nothing() {
        let mut buf = Vec::new();
        write_transcript_param(&mut buf, &[], usize::MAX);
        assert!(buf.is_empty());
    }

    #[test]
    fn zero_cap_disables_embedding() {
        let window = sample_window();
        let mut buf = Vec::new();
        write_transcript_param(&mut buf, &window, 0);
        assert!(buf.is_empty());
        assert_eq!(encode_transcript(&window, 0), Vec::<u8>::new());
    }

    #[test]
    fn oversize_window_is_truncated_to_earliest_contiguous_prefix() {
        let window = sample_window();
        // Budget for header + exactly the first entry, nothing more.
        let header_len = MAGIC.len() + 4;
        let first_entry_len = 8 + 4 + window[0].1.len();
        let cap = header_len + first_entry_len;

        let encoded = encode_transcript(&window, cap);
        assert!(encoded.len() <= cap);
        let decoded = decode_transcript(&encoded).unwrap();
        assert_eq!(decoded, vec![window[0].clone()]);
    }

    #[test]
    fn cap_too_small_for_any_entry_yields_empty_blob() {
        let window = sample_window();
        let encoded = encode_transcript(&window, 3); // smaller than any header
        assert!(encoded.is_empty());
    }

    #[test]
    fn malformed_and_truncated_input_rejected_without_panicking() {
        assert_eq!(decode_transcript(&[]), Err(TranscriptDecodeError::Truncated));
        assert_eq!(
            decode_transcript(b"short"),
            Err(TranscriptDecodeError::Truncated)
        );
        assert_eq!(
            decode_transcript(b"NOPE0000"),
            Err(TranscriptDecodeError::BadMagic)
        );

        // Well-formed header claiming 5 entries, but no entry bytes follow.
        let mut truncated_entries = Vec::new();
        truncated_entries.extend_from_slice(&MAGIC);
        truncated_entries.extend_from_slice(&5u32.to_be_bytes());
        assert_eq!(
            decode_transcript(&truncated_entries),
            Err(TranscriptDecodeError::Truncated)
        );

        // A valid single entry, sliced off mid-payload.
        let window = sample_window();
        let full = encode_transcript(&window, usize::MAX);
        for cut in 1..full.len() {
            // Must never panic regardless of where the cut lands.
            let _ = decode_transcript(&full[..cut]);
        }
    }

    #[test]
    fn read_transcript_param_never_panics_on_arbitrary_bytes() {
        for len in 0..64 {
            let garbage: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let _ = read_transcript_param(&garbage);
        }
    }

    #[test]
    fn a_real_quic_initial_packet_is_never_mistaken_for_a_transcript() {
        // A real Initial packet header + ciphertext from quinn-proto's own
        // RFC 9001 test vector (see keys.rs's
        // derive_initial_keys_server_remote_decrypts_known_client_packet) --
        // structurally nothing like our TLV framing, and critically doesn't
        // happen to carry our magic bytes anywhere reachable by the scanner.
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

        assert_eq!(read_transcript_param(&packet_bytes), None);
        assert!(decode_transcript(&packet_bytes).is_err());
    }
}
