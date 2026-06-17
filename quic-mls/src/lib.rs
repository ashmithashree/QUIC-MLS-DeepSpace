use bytes::BytesMut;
use quinn_proto::crypto::{CryptoError, HeaderKey, KeyPair, Keys, PacketKey};

// ── Stub keys (replaced in Step 2) ───────────────────────────────────────────

struct StubPacketKey;
impl PacketKey for StubPacketKey {
    fn encrypt(&self, _pn: u64, _buf: &mut [u8], _header_len: usize) {
        unimplemented!("replace in step 2")
    }
    fn decrypt(
        &self,
        _pn: u64,
        _header: &[u8],
        _payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        unimplemented!("replace in step 2")
    }
    fn tag_len(&self) -> usize { 16 }
    fn confidentiality_limit(&self) -> u64 { u64::MAX }
    fn integrity_limit(&self) -> u64 { u64::MAX }
}

struct StubHeaderKey;
impl HeaderKey for StubHeaderKey {
    fn decrypt(&self, _pn_offset: usize, _packet: &mut [u8]) {
        unimplemented!("replace in step 2")
    }
    fn encrypt(&self, _pn_offset: usize, _packet: &mut [u8]) {
        unimplemented!("replace in step 2")
    }
    fn sample_size(&self) -> usize { 16 }
}

fn stub_keys() -> Keys {
    Keys {
        header: KeyPair {
            local:  Box::new(StubHeaderKey),
            remote: Box::new(StubHeaderKey),
        },
        packet: KeyPair {
            local:  Box::new(StubPacketKey),
            remote: Box::new(StubPacketKey),
        },
    }
}

// ── Handshake state ───────────────────────────────────────────────────────────

use quinn_proto::Side;

enum HsState {
    Initial,         // write_handshake not yet called
    SentHandshakeKeys, // returned Handshake Keys; waiting for 1-RTT call
    Done,            // returned 1-RTT Keys; handshake complete
}

pub struct MlsSession {
    side:  Side,
    state: HsState,
}

impl MlsSession {
    pub fn new(side: Side) -> Self {
        Self { side, state: HsState::Initial }
    }
}

// ── Session trait impl ────────────────────────────────────────────────────────

use std::any::Any;
use quinn_proto::{
    crypto::{ExportKeyingMaterialError, Session},
    transport_parameters::TransportParameters,
    ConnectionId, TransportError,
};

impl Session for MlsSession {
    // Initial keys must follow RFC 9001 §5.2 — not MLS-derived.
    // Replaced in Step 2 with the standard QUIC Initial key schedule.
    fn initial_keys(&self, _dst_cid: &ConnectionId, _side: Side) -> Keys {
        stub_keys()
    }

    fn is_handshaking(&self) -> bool {
        !matches!(self.state, HsState::Done)
    }

    // MLS group membership is the authentication — no TLS cert chain.
    fn handshake_data(&self) -> Option<Box<dyn Any>> { None }
    fn peer_identity(&self) -> Option<Box<dyn Any>> { None }

    // 0-RTT not implemented in Phase 1.
    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> { None }
    fn early_data_accepted(&self) -> Option<bool> { Some(false) }

    // Step 3: decode the peer's TransportParameters from CRYPTO frames here.
    fn read_handshake(&mut self, _buf: &[u8]) -> Result<bool, TransportError> {
        Ok(false)
    }

    // Step 3: return Some(...) once TransportParameters are decoded.
    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        Ok(None)
    }

    // Step 2+3: write our TransportParameters into buf, then return
    // MLS-derived Keys for the Handshake space, then 1-RTT space.
    fn write_handshake(&mut self, _buf: &mut Vec<u8>) -> Option<Keys> {
        None
    }

    // Step 4: advance the MLS epoch and derive new PacketKeys.
    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        None
    }

    // Retry-packet integrity: Step 2 delegates this to a standard impl.
    fn is_valid_retry(
        &self,
        _orig_dst_cid: &ConnectionId,
        _header: &[u8],
        _payload: &[u8],
    ) -> bool {
        false
    }

    fn export_keying_material(
        &self,
        _output: &mut [u8],
        _label: &[u8],
        _context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        Err(ExportKeyingMaterialError)
    }
}
