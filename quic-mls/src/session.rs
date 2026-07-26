use crate::group::{apply_commit_window, ExportSecret};
use crate::keys::{derive_initial_keys, derive_mls_keys};
use crate::transcript::{read_transcript_param, write_transcript_param};
use quinn_proto::coding::Codec;
use quinn_proto::crypto::{ExportKeyingMaterialError, HeaderKey, KeyPair, Keys, PacketKey, Session};
use quinn_proto::{transport_parameters::TransportParameters, ConnectionId, Side, TransportError, VarInt};
use std::any::Any;
use std::sync::{Arc, Mutex};
use crate::retry::{verify_retry_tag};

enum HsState {
    Initial,               
    AwaitingZeroRttKeys,    
    ConfirmingZeroRttKeys,  
    Done,                   
}

// RFC 9000 s18.2 transport parameter IDs for the handful of integer
// parameters a 0-RTT client needs in order to open a stream and write
// flow-controlled data on it before any bytes have arrived from the server.
const TP_INITIAL_MAX_DATA: u64 = 0x04;
const TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x06;
const TP_INITIAL_MAX_STREAMS_BIDI: u64 = 0x08;


fn encode_transport_param(buf: &mut Vec<u8>, id: u64, value: u64) {
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
    // Receiver-side bookkeeping for `apply_commit_window`, counting commits
    // originated by the peer (not mls-rs's own internal epoch numbering --
    // see CommitLog's parallel counter). Shared with whatever steady-state
    // control-plane task (e.g. testbed-runner's `run_commit_receiver`) also
    // advances it post-handshake, so the two mechanisms can't double-apply
    // or race on the notion of "how far behind are we".
    received_epoch: Arc<Mutex<u64>>,
    // The paper's tunable transcript length `tl`, expressed as a byte cap on
    // the encoded blob embedded in the Initial-level handshake data. 0
    // disables embedding entirely (tl=0, the strongly-consistent-DS case).
    transcript_cap: usize,
    // Snapshotted lazily on the first `write_handshake` call (HsState::Initial),
    // not at construction -- see the comment there for why that specific
    // point in time is the one that satisfies both the reconnection fix and
    // the pre-existing race regression test.
    pinned_zero_rtt_upgrade_keys: Option<Keys>,
    pinned_zero_rtt_keys: Option<Keys>,
}

impl MlsSession {

    pub fn new(
        group: Box<dyn ExportSecret>,
        side: Side,
        local_params: TransportParameters,
        received_epoch: Arc<Mutex<u64>>,
        transcript_cap: usize,
    ) -> Self {
        let cached_peer_params = (side == Side::Client).then(|| synthetic_cached_peer_params(side));
        Self {
            group, side, state: HsState::Initial, local_params,
            peer_params: None, cached_peer_params, key_update_generation: 0,
            received_epoch, transcript_cap,
            pinned_zero_rtt_upgrade_keys: None,
            pinned_zero_rtt_keys: None,
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
            // The first call for either side. Traced against quinn-proto
            // 0.11.14: for the CLIENT this runs synchronously inside
            // `Connection::new` (`write_crypto()` before `init_0rtt()`),
            // before the application can possibly race a `create_commit()`
            // in against it -- preserving the invariant
            // `quic_mls_0rtt_create_commit_race_before_handshake_confirms`
            // depends on. For the SERVER this runs inside
            // `process_early_payload`, strictly *after* that same
            // function's frame loop has already called `read_handshake` on
            // the peer's Initial CRYPTO data (`connection/mod.rs`: the
            // Crypto-frame arm at line ~2688 precedes the `write_crypto()`
            // call at line ~2714) -- so by the time we snapshot here, any
            // transcript the peer embedded in that same flight has already
            // been applied to `self.group` in `read_handshake` below. One
            // snapshot, taken at the one point that is simultaneously early
            // enough for the sender and late enough for the receiver.
            HsState::Initial => {
                self.local_params.write(buf);
                // Fig. 2 line 22: ast' rides alongside the ciphertext tuple,
                // not inside it. Here that means appended to the Initial-
                // level handshake data, before any MLS-derived key for this
                // connection has been computed on either side. Empty for a
                // peer with nothing pending (e.g. Bob, who never originates
                // commits), so this is a no-op byte-for-byte when unused.
                write_transcript_param(buf, &self.group.pending_commit_window(), self.transcript_cap);
                self.pinned_zero_rtt_upgrade_keys =
                    derive_mls_keys(self.group.as_ref(), "0-rtt", self.side, b"").ok();
                self.pinned_zero_rtt_keys =
                    derive_mls_keys(self.group.as_ref(), "0-rtt", self.side, b"").ok();
                self.state = HsState::AwaitingZeroRttKeys;
                None
            }
           
            HsState::AwaitingZeroRttKeys => {
                if self.peer_params.is_none() {
                    return None;
                }
                self.state = HsState::ConfirmingZeroRttKeys;
                self.pinned_zero_rtt_upgrade_keys.take()
            }
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

            // Fig. 2 Dec, lines 1-12: parse ast out of the tuple, replay any
            // commits we're missing, before any key for this connection is
            // derived (see write_handshake above, which always runs after
            // this in the same processing pass). A gap or a rejected commit
            // is logged and otherwise ignored here -- catching up is best-
            // effort and never blocks or aborts the handshake; if it didn't
            // fully succeed, this connection's keys simply won't match and
            // the caller (testbed-runner) will see the cycle fail and retry
            // on the next contact window, per invariant 1 (sender never
            // blocks on the receiver).
            if let Some(window) = read_transcript_param(buf) {
                let mut epoch = self.received_epoch.lock().unwrap();
                let before = *epoch;
                match apply_commit_window(self.group.as_mut(), &window, &mut epoch) {
                    Ok(()) if *epoch != before => {
                        tracing::info!(
                            side = ?self.side,
                            from_epoch = before,
                            to_epoch = *epoch,
                            "quic-mls: applied handshake-embedded commit transcript"
                        );
                    }
                    Ok(()) => {}
                    Err(e) => {
                        tracing::warn!(
                            side = ?self.side,
                            local_epoch = *epoch,
                            "quic-mls: could not apply handshake-embedded transcript: {e}"
                        );
                    }
                }
            }
        }
        Ok(false) 
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        
        Ok(self.peer_params.or(self.cached_peer_params))
    }

   
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
    use crate::group::CommitLog;
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

    // Test-only convenience: a fresh, unshared epoch counter and an
    // unbounded transcript cap, matching what most tests want.
    fn new_session(group: Box<dyn ExportSecret>, side: Side, params: TransportParameters) -> MlsSession {
        MlsSession::new(group, side, params, Arc::new(Mutex::new(0)), usize::MAX)
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

        let mut alice_session = new_session(Box::new(alice_group), Side::Client, alice_params);
        let mut bob_session = new_session(Box::new(bob_group), Side::Server, bob_params);

        
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

      
        let alice_0rtt_keys = alice_session.write_handshake(&mut Vec::new()).expect("0-RTT keys on call 3");
        let bob_0rtt_keys = bob_session.write_handshake(&mut Vec::new()).expect("0-RTT keys on call 3");

        assert!(!alice_session.is_handshaking());
        assert!(!bob_session.is_handshaking());

       
        let header_len = 5;
        let plaintext = b"zero rtt level data";
        let mut buf = vec![0u8; header_len + plaintext.len() + 16];
        buf[..header_len].copy_from_slice(b"HDRXX");
        buf[header_len..header_len + plaintext.len()].copy_from_slice(plaintext);
        alice_0rtt_keys.packet.local.encrypt(0, &mut buf, header_len);
        let mut payload = BytesMut::from(&buf[header_len..]);
        bob_0rtt_keys.packet.remote.decrypt(0, &buf[..header_len], &mut payload).unwrap();
        assert_eq!(&payload[..], plaintext);

       
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

        let mut alice_session = new_session(
            Box::new(alice_group), Side::Client,
            TransportParameters::read(Side::Client, &mut &[][..]).unwrap(),
        );
        let mut bob_session = new_session(
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

    let mut alice_session = new_session(
        Box::new(alice_group), Side::Client,
        TransportParameters::read(Side::Client, &mut &[][..]).unwrap(),
    );
    let mut bob_session = new_session(
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

        let mut alice_session = new_session(
            Box::new(alice_group), Side::Client,
            TransportParameters::read(Side::Client, &mut &[][..]).unwrap(),
        );
        let mut bob_session = new_session(
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

// Reproduces the reconnection-after-blackout scenario: Alice's group
// advances N epochs with no corresponding apply on Bob's group (the
// blackout), then a *new* pair of `MlsSession`s is constructed for the
// reconnect attempt. Bob's session must reach epoch N purely from the
// transcript embedded in Alice's Initial-level handshake data -- applied in
// `read_handshake`, before either side's `write_handshake` derives a key --
// and the two sides' first derived keys must then match.
#[test]
fn epoch_mismatch_resolves_via_handshake_embedded_transcript() {
    let alice = make_client("alice");
    let bob = make_client("bob");

    let mut alice_group = alice.create_group(ExtensionList::new(), ExtensionList::new(), None).unwrap();
    let bob_kp = bob.generate_key_package_message(ExtensionList::new(), ExtensionList::new(), None).unwrap();
    let commit_out = alice_group.commit_builder().add_member(bob_kp).unwrap().build().unwrap();
    alice_group.apply_pending_commit().unwrap();
    let (bob_group, _) = bob.join_group(None, &commit_out.welcome_messages[0], None).unwrap();

    // Alice's group is wrapped in a CommitLog, exactly as testbed-runner
    // wraps it, so she has a window to embed.
    let mut alice_log = CommitLog::new(alice_group);

    const N: u64 = 3;
    for _ in 0..N {
        alice_log.create_commit().unwrap();
    }
    // Bob's plain group never sees any of these three commits -- this is
    // the blackout: Bob is 3 epochs behind by the time the two reconnect.

    let bob_epoch = Arc::new(Mutex::new(0u64));
    let mut alice_session = MlsSession::new(
        Box::new(alice_log), Side::Client,
        TransportParameters::read(Side::Client, &mut &[][..]).unwrap(),
        Arc::new(Mutex::new(0)), usize::MAX,
    );
    let mut bob_session = MlsSession::new(
        Box::new(bob_group), Side::Server,
        TransportParameters::read(Side::Server, &mut &[][..]).unwrap(),
        Arc::clone(&bob_epoch), usize::MAX,
    );

    // Call 1 (Initial): Alice's flight now carries the 3-commit transcript.
    let mut alice_buf = Vec::new();
    assert!(alice_session.write_handshake(&mut alice_buf).is_none());

    // Bob processes Alice's flight -- applying the transcript -- *before*
    // producing his own first flight. This ordering matters and matches
    // real quinn-proto: for the server, `process_early_payload` runs its
    // frame loop (which calls `read_handshake` on the just-received Initial
    // CRYPTO data) to completion before calling `write_crypto()` (which
    // calls `write_handshake` for the first time). Getting this backwards
    // in the test would snapshot Bob's keys before he's caught up, which
    // read_handshake's own gating (`peer_params.is_none()`) doesn't itself
    // enforce -- the caller (quinn-proto, and this test) has to.
    bob_session.read_handshake(&alice_buf).unwrap();
    assert_eq!(*bob_epoch.lock().unwrap(), N, "Bob must have caught up to Alice's epoch");

    let mut bob_buf = Vec::new();
    assert!(bob_session.write_handshake(&mut bob_buf).is_none());
    alice_session.read_handshake(&bob_buf).unwrap();

    // Calls 2 and 3: derive the keys that would become this connection's
    // real 1-RTT traffic keys.
    assert!(alice_session.write_handshake(&mut Vec::new()).is_some());
    assert!(bob_session.write_handshake(&mut Vec::new()).is_some());
    let alice_keys = alice_session.write_handshake(&mut Vec::new()).expect("alice keys");
    let bob_keys = bob_session.write_handshake(&mut Vec::new()).expect("bob keys");

    let header_len = 5;
    let plaintext = b"post-blackout data";
    let mut buf = vec![0u8; header_len + plaintext.len() + 16];
    buf[..header_len].copy_from_slice(b"HDRXX");
    buf[header_len..header_len + plaintext.len()].copy_from_slice(plaintext);
    alice_keys.packet.local.encrypt(0, &mut buf, header_len);
    let mut payload = BytesMut::from(&buf[header_len..]);
    bob_keys.packet.remote.decrypt(0, &buf[..header_len], &mut payload)
        .expect("keys must match despite the pre-handshake epoch gap");
    assert_eq!(&payload[..], plaintext);
}

}
