//Note:
// Wire encoding for (epoch, commit_bytes) transcript entries. Originally
// carried inside a custom QUIC transport parameter; that path is removed
// but this encoding is reused unmodified by preamble.rs.
// Reference: RFC 9000 §7.4 (Transport Parameters — the mechanism this
//   module originally rode inside), IETF, Iyengar & Thomson, 2021.
//   https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameters
//======================================================================================================================
const MAGIC: [u8; 4] = *b"QMT1";

#[derive(Debug, PartialEq, Eq)]
pub enum TranscriptDecodeError {
    
    Truncated,
   
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

