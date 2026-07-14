use crate::group::ExportSecret;
use crate::keys::{derive_initial_keys, derive_mls_keys};
use quinn_proto::coding::Codec;
use quinn_proto::crypto::{ExportKeyingMaterialError, HeaderKey, KeyPair, Keys, PacketKey, Session};
use quinn_proto::{transport_parameters::TransportParameters, ConnectionId, Side, TransportError, VarInt};
use std::any::Any;
use crate::retry::{verify_retry_tag};

enum HsState {
    Initial,               // call 1: write local_params at Initial level; return no keys
    AwaitingZeroRttKeys,    // gate: wait for peer_params, then hand quinn-proto its first upgrade (Initial -> Handshake)
    ConfirmingZeroRttKeys,  // next call: write the marker byte, hand quinn-proto its second upgrade (Handshake -> Data)
    Done,                   // final state: nothing left to do
}

// RFC 9000 s18.2 transport parameter IDs for the handful of integer
// parameters a 0-RTT client needs in order to open a stream and write
// flow-controlled data on it before any bytes have arrived from the server.
const TP_INITIAL_MAX_DATA: u64 = 0x04;
const TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x06;
const TP_INITIAL_MAX_STREAMS_BIDI: u64 = 0x08;

// Codec::encode is the method that turns a number into its QUIC byte representation
// the function has to actually do the encoding first, then count the result, instead of guessing the length up front
fn encode_transport_param(buf: &mut Vec<u8>, id: u64, value: u64) {
    //scratch buffer seperate from buf to hold the encoded value, 
    // so we can measure its length before writing the length prefix to buf.
    let mut encoded_value = Vec::new();
    VarInt::from_u64(value).expect("test-scale value fits in a VarInt").encode(&mut encoded_value);
    VarInt::from_u64(id).expect("id fits in a VarInt").encode(buf);
    VarInt::from_u64(encoded_value.len() as u64).expect("length fits in a VarInt").encode(buf);
    buf.extend_from_slice(&encoded_value);
}

fn synthetic_cached_peer_params(side: Side) -> TransportParameters {
    let mut buf = Vec::new();
    encode_transport_param(&mut buf, TP_INITIAL_MAX_DATA, 65536);
    encode_transport_param(&mut buf, TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, 65536);
    encode_transport_param(&mut buf, TP_INITIAL_MAX_STREAMS_BIDI, 1);
    TransportParameters::read(side, &mut buf.as_slice())
        .expect("hand-encoded transport parameters must parse")
}

pub struct MlsSession {
    group: Box<dyn ExportSecret>,
    side: Side,
    state: HsState,
    local_params: TransportParameters,
    peer_params: Option<TransportParameters>,
    cached_peer_params: Option<TransportParameters>,
    key_update_generation: u64,
    pinned_zero_rtt_keys: Option<Keys>,
}

impl MlsSession {

    pub fn new(group: Box<dyn ExportSecret>, side: Side, local_params: TransportParameters) -> Self {
        let pinned_zero_rtt_keys = derive_mls_keys(group.as_ref(), "0-rtt", side, b"")
            .expect("MLS group must have a valid epoch exporter secret");
        let cached_peer_params = (side == Side::Client).then(|| synthetic_cached_peer_params(side));
        Self {
            group, side, state: HsState::Initial, local_params,
            peer_params: None, cached_peer_params, key_update_generation: 0,
            pinned_zero_rtt_keys: Some(pinned_zero_rtt_keys),
        }
    }

    pub fn create_commit(&mut self) -> Result<Vec<u8>, mls_rs::error::MlsError> {
        self.group.create_commit()
    }

    pub fn apply_commit(&mut self, commit: &[u8]) -> Result<(), mls_rs::error::MlsError> {
        self.group.apply_commit(commit)
    }
}

impl Session for MlsSession {
    // Initial keys must follow RFC 9001 5.2 not MLS-derived.
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> Keys {
        derive_initial_keys(dst_cid, side)
    }

    fn is_handshaking(&self) -> bool {
        !matches!(self.state, HsState::Done)
    }

    // MLS group membership is the authentication no TLS cert chain.
    fn handshake_data(&self) -> Option<Box<dyn Any>> { None }
    fn peer_identity(&self) -> Option<Box<dyn Any>> { None }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
        let keys = derive_mls_keys(self.group.as_ref(), "0-rtt", self.side, b"").ok()?;
        let (hk, pk) = match self.side {
            Side::Client => (keys.header.local, keys.packet.local),
            Side::Server => (keys.header.remote, keys.packet.remote),
        };
        Some((hk, pk))
    }

    
    fn early_data_accepted(&self) -> Option<bool> { Some(true) }

    
    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        match self.state {
            HsState::Initial => {
                self.local_params.write(buf);
                self.state = HsState::AwaitingZeroRttKeys;
                None
            }
            // Gate on the peer's params, then signal quinn-proto's first
            // upgrade (Initial -> Handshake) with an empty buf. quinn-proto
            // treats an empty-buf Some(Keys) as "keys changed but nothing to
            // send yet" and immediately re-invokes write_handshake in the
            // same tick, which is what lets ConfirmingZeroRttKeys run right
            // after this within a single write_crypto() pass.
            HsState::AwaitingZeroRttKeys => {
                if self.peer_params.is_none() {
                    return None;
                }
                self.state = HsState::ConfirmingZeroRttKeys;
                Some(derive_mls_keys(self.group.as_ref(), "0-rtt", self.side, b"")
                    .expect("MLS group must have a valid epoch exporter secret"))
            }
            // Pushes one dummy byte to buf so quinn-proto has real CRYPTO
            // frame content to send at the (now former) Handshake level,
            // then signals its second upgrade (Handshake -> Data) by
            // returning the pinned 0-RTT keys. The caller uses these to
            // encrypt/decrypt 1-RTT-level packets.
            HsState::ConfirmingZeroRttKeys => {
                buf.push(0);
                self.state = HsState::Done;
                self.pinned_zero_rtt_keys.take()
            }
            HsState::Done => None,
        }
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        // Only the first (Initial-level) call carries real TransportParameters.
        if self.peer_params.is_none() {
            let mut reader = buf;
            self.peer_params = Some(TransportParameters::read(self.side, &mut reader)?);
        }
        Ok(false) // handshake_data() never gets populated  we have no TLS-style negotiated data
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        // Real params (once read_handshake actually sees them) always win
        // over the synthetic 0-RTT bootstrap value.
        Ok(self.peer_params.or(self.cached_peer_params))
    }

    // MLS-derived Keys for the 1-RTT space, after the handshake is complete.
    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        self.key_update_generation += 1;
    let keys = derive_mls_keys(
        self.group.as_ref(), "0-rtt", self.side,
        &self.key_update_generation.to_be_bytes(),
    ).expect("MLS group must have a valid epoch exporter secret");
    Some(keys.packet)
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        verify_retry_tag(orig_dst_cid, header, payload)
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

#[cfg(test)]
mod handshake_key_tests {
    use super::*;
    use bytes::BytesMut;
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

    #[test]
    fn handshake_keys_from_real_mls_group_round_trip() {
        let alice = make_client("alice");
        let bob = make_client("bob");

        let mut alice_group = alice.create_group(ExtensionList::new(), ExtensionList::new(), None).unwrap();
        let bob_kp = bob.generate_key_package_message(ExtensionList::new(), ExtensionList::new(), None).unwrap();
        let commit_out = alice_group.commit_builder().add_member(bob_kp).unwrap().build().unwrap();
        alice_group.apply_pending_commit().unwrap();
        let (bob_group, _) = bob.join_group(None, &commit_out.welcome_messages[0], None).unwrap();

        let alice_keys = derive_mls_keys(&alice_group, "0-rtt", Side::Client, b"").unwrap();
        let bob_keys = derive_mls_keys(&bob_group, "0-rtt", Side::Server, b"").unwrap();

        let header_len = 5;
        let plaintext = b"hello from alice";
        let mut buf = vec![0u8; header_len + plaintext.len() + 16];
        buf[..header_len].copy_from_slice(b"HDRXX");
        buf[header_len..header_len + plaintext.len()].copy_from_slice(plaintext);

        alice_keys.packet.local.encrypt(0, &mut buf, header_len);

        let mut payload = BytesMut::from(&buf[header_len..]);
        bob_keys.packet.remote.decrypt(0, &buf[..header_len], &mut payload).unwrap();
        assert_eq!(&payload[..], plaintext);
    }

    #[test]
    fn full_handshake_round_trip_between_two_sessions() {
        let alice = make_client("alice");
        let bob = make_client("bob");

        let mut alice_group = alice.create_group(ExtensionList::new(), ExtensionList::new(), None).unwrap();
        let bob_kp = bob.generate_key_package_message(ExtensionList::new(), ExtensionList::new(), None).unwrap();
        let commit_out = alice_group.commit_builder().add_member(bob_kp).unwrap().build().unwrap();
        alice_group.apply_pending_commit().unwrap();
        let (bob_group, _) = bob.join_group(None, &commit_out.welcome_messages[0], None).unwrap();

        let alice_params = TransportParameters::read(Side::Client, &mut &[][..]).unwrap();
        let bob_params = TransportParameters::read(Side::Server, &mut &[][..]).unwrap();

        let mut alice_session = MlsSession::new(Box::new(alice_group), Side::Client, alice_params);
        let mut bob_session = MlsSession::new(Box::new(bob_group), Side::Server, bob_params);

        // ── Call 1 (Initial): write params at Initial level, no keys yet ──────
        // (default-valued TransportParameters are omitted on the wire, so an
        // empty buf here is expected only non-default fields get written.)
        let mut alice_buf = Vec::new();
        assert!(alice_session.write_handshake(&mut alice_buf).is_none());

        let mut bob_buf = Vec::new();
        assert!(bob_session.write_handshake(&mut bob_buf).is_none());

        alice_session.read_handshake(&bob_buf).unwrap();
        bob_session.read_handshake(&alice_buf).unwrap();

        assert!(alice_session.transport_parameters().unwrap().is_some());
        assert!(bob_session.transport_parameters().unwrap().is_some());
        assert!(alice_session.is_handshaking());
        assert!(bob_session.is_handshaking());

    
        assert!(alice_session.write_handshake(&mut Vec::new()).is_some());
        assert!(bob_session.write_handshake(&mut Vec::new()).is_some());
        assert!(alice_session.is_handshaking());
        assert!(bob_session.is_handshaking());

        // ── Call 3 (ConfirmingZeroRttKeys): marker byte, keys ready -> Done ────
        let alice_0rtt_keys = alice_session.write_handshake(&mut Vec::new()).expect("0-RTT keys on call 3");
        let bob_0rtt_keys = bob_session.write_handshake(&mut Vec::new()).expect("0-RTT keys on call 3");

        assert!(!alice_session.is_handshaking());
        assert!(!bob_session.is_handshaking());

        // 0-RTT keys must work cross-party.
        let header_len = 5;
        let plaintext = b"zero rtt level data";
        let mut buf = vec![0u8; header_len + plaintext.len() + 16];
        buf[..header_len].copy_from_slice(b"HDRXX");
        buf[header_len..header_len + plaintext.len()].copy_from_slice(plaintext);
        alice_0rtt_keys.packet.local.encrypt(0, &mut buf, header_len);
        let mut payload = BytesMut::from(&buf[header_len..]);
        bob_0rtt_keys.packet.remote.decrypt(0, &buf[..header_len], &mut payload).unwrap();
        assert_eq!(&payload[..], plaintext);

        // The handshake is fully done — a further call must do nothing.
        assert!(alice_session.write_handshake(&mut Vec::new()).is_none());
    }

    #[test]
    fn next_1rtt_keys_reflects_new_epoch_after_commit() {
        let alice = make_client("alice");
        let bob = make_client("bob");

        let mut alice_group = alice.create_group(ExtensionList::new(), ExtensionList::new(), None).unwrap();
        let bob_kp = bob.generate_key_package_message(ExtensionList::new(), ExtensionList::new(), None).unwrap();
        let commit_out = alice_group.commit_builder().add_member(bob_kp).unwrap().build().unwrap();
        alice_group.apply_pending_commit().unwrap();
        let (bob_group, _) = bob.join_group(None, &commit_out.welcome_messages[0], None).unwrap();

        let mut alice_session = MlsSession::new(
            Box::new(alice_group), Side::Client,
            TransportParameters::read(Side::Client, &mut &[][..]).unwrap(),
        );
        let mut bob_session = MlsSession::new(
            Box::new(bob_group), Side::Server,
            TransportParameters::read(Side::Server, &mut &[][..]).unwrap(),
        );

        // Epoch 1.
        let alice_epoch1 = alice_session.next_1rtt_keys().expect("epoch 1 keys");
        let bob_epoch1 = bob_session.next_1rtt_keys().expect("epoch 1 keys");

        let header_len = 5;
        let plaintext = b"epoch data";
        let mut buf1 = vec![0u8; header_len + plaintext.len() + 16];
        buf1[..header_len].copy_from_slice(b"HDRXX");
        buf1[header_len..header_len + plaintext.len()].copy_from_slice(plaintext);
        alice_epoch1.local.encrypt(0, &mut buf1, header_len);
        let epoch1_ciphertext = buf1[header_len..].to_vec();
        let mut payload1 = BytesMut::from(&buf1[header_len..]);
        bob_epoch1.remote.decrypt(0, &buf1[..header_len], &mut payload1).unwrap();
        assert_eq!(&payload1[..], plaintext);

        // Advance the epoch: Alice proposes a bare Commit, Bob applies it.
        let commit_bytes = alice_session.create_commit().unwrap();
        bob_session.apply_commit(&commit_bytes).unwrap();

        // Epoch 2: next_1rtt_keys must reflect the new epoch.
        let alice_epoch2 = alice_session.next_1rtt_keys().expect("epoch 2 keys");
        let bob_epoch2 = bob_session.next_1rtt_keys().expect("epoch 2 keys");

        let mut buf2 = vec![0u8; header_len + plaintext.len() + 16];
        buf2[..header_len].copy_from_slice(b"HDRXX");
        buf2[header_len..header_len + plaintext.len()].copy_from_slice(plaintext);
        alice_epoch2.local.encrypt(0, &mut buf2, header_len);
        let mut payload2 = BytesMut::from(&buf2[header_len..]);
        bob_epoch2.remote.decrypt(0, &buf2[..header_len], &mut payload2).unwrap();
        assert_eq!(&payload2[..], plaintext);

        // Same plaintext, same packet number, genuinely different key.
        assert_ne!(epoch1_ciphertext, buf2[header_len..]);
    }
    #[test]
fn quic_mls_distinct_keys_per_epoch() {
    let alice = make_client("alice");
    let bob = make_client("bob");

    let mut alice_group = alice.create_group(ExtensionList::new(), ExtensionList::new(), None).unwrap();
    let bob_kp = bob.generate_key_package_message(ExtensionList::new(), ExtensionList::new(), None).unwrap();
    let commit_out = alice_group.commit_builder().add_member(bob_kp).unwrap().build().unwrap();
    alice_group.apply_pending_commit().unwrap();
    let (bob_group, _) = bob.join_group(None, &commit_out.welcome_messages[0], None).unwrap();

    let mut alice_session = MlsSession::new(
        Box::new(alice_group), Side::Client,
        TransportParameters::read(Side::Client, &mut &[][..]).unwrap(),
    );
    let mut bob_session = MlsSession::new(
        Box::new(bob_group), Side::Server,
        TransportParameters::read(Side::Server, &mut &[][..]).unwrap(),
    );

    let header_len = 5;
    let plaintext = b"epoch data";

    
    let round_trip = |alice_keys: &KeyPair<Box<dyn PacketKey>>,
                       bob_keys: &KeyPair<Box<dyn PacketKey>>|
                       -> Vec<u8> {
        let mut buf = vec![0u8; header_len + plaintext.len() + 16];
        buf[..header_len].copy_from_slice(b"HDRXX");
        buf[header_len..header_len + plaintext.len()].copy_from_slice(plaintext);
        alice_keys.local.encrypt(0, &mut buf, header_len);
        let ciphertext = buf[header_len..].to_vec();

        let mut payload = BytesMut::from(&buf[header_len..]);
        bob_keys.remote.decrypt(0, &buf[..header_len], &mut payload).unwrap();
        assert_eq!(&payload[..], plaintext);

        ciphertext
    };

    // Commit #1: epoch 1 -> 2.
    let commit1 = alice_session.create_commit().unwrap();
    bob_session.apply_commit(&commit1).unwrap();
    let alice_epoch_a = alice_session.next_1rtt_keys().expect("keys after commit 1");
    let bob_epoch_a = bob_session.next_1rtt_keys().expect("keys after commit 1");
    let ciphertext_a = round_trip(&alice_epoch_a, &bob_epoch_a);

    // Commit #2: epoch 2 -> 3.
    let commit2 = alice_session.create_commit().unwrap();
    bob_session.apply_commit(&commit2).unwrap();
    let alice_epoch_b = alice_session.next_1rtt_keys().expect("keys after commit 2");
    let bob_epoch_b = bob_session.next_1rtt_keys().expect("keys after commit 2");
    let ciphertext_b = round_trip(&alice_epoch_b, &bob_epoch_b);

    // Same plaintext, same packet number, two consecutive commits ->
    // the derived keys must still be genuinely different.
    assert_ne!(ciphertext_a, ciphertext_b);
}
#[test]
fn next_1rtt_keys_reflects_new_generation_within_same_epoch() {
   let alice = make_client("alice");
        let bob = make_client("bob");

        let mut alice_group = alice.create_group(ExtensionList::new(), ExtensionList::new(), None).unwrap();
        let bob_kp = bob.generate_key_package_message(ExtensionList::new(), ExtensionList::new(), None).unwrap();
        let commit_out = alice_group.commit_builder().add_member(bob_kp).unwrap().build().unwrap();
        alice_group.apply_pending_commit().unwrap();
        let (bob_group, _) = bob.join_group(None, &commit_out.welcome_messages[0], None).unwrap();

        let mut alice_session = MlsSession::new(
            Box::new(alice_group), Side::Client,
            TransportParameters::read(Side::Client, &mut &[][..]).unwrap(),
        );
        let mut bob_session = MlsSession::new(
            Box::new(bob_group), Side::Server,
            TransportParameters::read(Side::Server, &mut &[][..]).unwrap(),
        );

    let alice_gen1 = alice_session.next_1rtt_keys().expect("gen 1 keys");
    let bob_gen1   = bob_session.next_1rtt_keys().expect("gen 1 keys");
    // round-trip encrypt/decrypt gen1, capture ciphertext (same header_len/plaintext/pn=0 pattern as the existing tests)
    let header_len = 5;
    let plaintext = b"epoch data";
    let mut buf1 = vec![0u8; header_len + plaintext.len() + 16];        
    buf1[..header_len].copy_from_slice(b"HDRXX");
    buf1[header_len..header_len + plaintext.len()].copy_from_slice(plaintext);
    alice_gen1.local.encrypt(0, &mut buf1, header_len);
    let gen1_ciphertext = buf1[header_len..].to_vec();        
    let mut payload1 = BytesMut::from(&buf1[header_len..]);
    bob_gen1.remote.decrypt(0, &buf1[..header_len], &mut payload1).unwrap();
    assert_eq!(&payload1[..], plaintext);
    // NO commit here — same epoch, just call again:
    let alice_gen2 = alice_session.next_1rtt_keys().expect("gen 2 keys");
    let bob_gen2   = bob_session.next_1rtt_keys().expect("gen 2 keys");
    // round-trip encrypt/decrypt gen2 cross-party, same plaintext + pn=0
    let mut buf2 = vec![0u8; header_len + plaintext.len() + 16];        
    buf2[..header_len].copy_from_slice(b"HDRXX");
    buf2[header_len..header_len + plaintext.len()].copy_from_slice(plaintext);
    alice_gen2.local.encrypt(0, &mut buf2, header_len);
    let gen2_ciphertext = buf2[header_len..].to_vec();        
    let mut payload2 = BytesMut::from(&buf2[header_len..]);
    bob_gen2.remote.decrypt(0, &buf2[..header_len], &mut payload2).unwrap();
    assert_eq!(&payload2[..], plaintext);
    assert_ne!(gen1_ciphertext, gen2_ciphertext); // genuinely different key, same epoch
}

}
