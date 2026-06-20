use crate::group::ExportSecret;
use crate::keys::{derive_initial_keys, derive_mls_keys};
use quinn_proto::crypto::{ExportKeyingMaterialError, HeaderKey, KeyPair, Keys, PacketKey, Session};
use quinn_proto::{transport_parameters::TransportParameters, ConnectionId, Side, TransportError};
use std::any::Any;
use crate::retry::{verify_retry_tag};
enum HsState {
    Initial,             // call 1: write local_params at Initial level; return no keys
    AwaitingHandshakeKeys, // gate: stay here until peer_params arrives, then signal Handshake keys
    AwaitingOneRttKeys,    // next call: write nothing; signal 1-RTT keys ready
    Done,                // final state: nothing left to do
}

pub struct MlsSession {
    group: Box<dyn ExportSecret>,
    side: Side,
    state: HsState,
    local_params: TransportParameters,
    peer_params: Option<TransportParameters>,
}

impl MlsSession {
    pub fn new(group: Box<dyn ExportSecret>, side: Side, local_params: TransportParameters) -> Self {
        Self { group, side, state: HsState::Initial, local_params, peer_params: None }
    }

    pub fn create_commit(&mut self) -> Result<Vec<u8>, mls_rs::error::MlsError> {
        self.group.create_commit()
    }

    pub fn apply_commit(&mut self, commit: &[u8]) -> Result<(), mls_rs::error::MlsError> {
        self.group.apply_commit(commit)
    }
}

impl Session for MlsSession {
    // Initial keys must follow RFC 9001 5.2 — not MLS-derived.
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> Keys {
        derive_initial_keys(dst_cid, side)
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

    
    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        match self.state {
            HsState::Initial => {
                self.local_params.write(buf);
                self.state = HsState::AwaitingHandshakeKeys;
                None
            }
            HsState::AwaitingHandshakeKeys => {
                if self.peer_params.is_none() {
                    return None;
                }
                self.state = HsState::AwaitingOneRttKeys;
                Some(derive_mls_keys(self.group.as_ref(), "handshake", self.side)
                    .expect("MLS group must have a valid epoch exporter secret"))
            }
            HsState::AwaitingOneRttKeys => {
                buf.push(0);
                self.state = HsState::Done;
                Some(derive_mls_keys(self.group.as_ref(), "1-rtt", self.side)
                    .expect("MLS group must have a valid epoch exporter secret"))
            }
            HsState::Done => None,
        }
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        // Only the first (Initial-level) call carries real TransportParameters.
        // The later Handshake-level call just delivers our liveness marker
        // byte, which has no structure to parse — ignore its content.
        if self.peer_params.is_none() {
            let mut reader = buf;
            self.peer_params = Some(TransportParameters::read(self.side, &mut reader)?);
        }
        Ok(false) // handshake_data() never gets populated — we have no TLS-style negotiated data
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        Ok(self.peer_params)
    }

    // MLS-derived Keys for the 1-RTT space, after the handshake is complete.
    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        let keys = derive_mls_keys(self.group.as_ref(), "1-rtt", self.side)
            .expect("MLS group must have a valid epoch exporter secret");
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

        let alice_keys = derive_mls_keys(&alice_group, "handshake", Side::Client).unwrap();
        let bob_keys = derive_mls_keys(&bob_group, "handshake", Side::Server).unwrap();

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
        // empty buf here is expected — only non-default fields get written.)
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

        // ── Call 2 (AwaitingHandshakeKeys): no data, Handshake keys ready ──────
        let alice_hs_keys = alice_session.write_handshake(&mut Vec::new()).expect("handshake keys on call 2");
        let bob_hs_keys = bob_session.write_handshake(&mut Vec::new()).expect("handshake keys on call 2");
        assert!(alice_session.is_handshaking());
        assert!(bob_session.is_handshaking());

        // Handshake-level keys must already work cross-party.
        let header_len = 5;
        let hs_plaintext = b"handshake level data";
        let mut buf = vec![0u8; header_len + hs_plaintext.len() + 16];
        buf[..header_len].copy_from_slice(b"HDRXX");
        buf[header_len..header_len + hs_plaintext.len()].copy_from_slice(hs_plaintext);
        alice_hs_keys.packet.local.encrypt(0, &mut buf, header_len);
        let hs_ciphertext = buf[header_len..].to_vec();
        let mut payload = BytesMut::from(&buf[header_len..]);
        bob_hs_keys.packet.remote.decrypt(0, &buf[..header_len], &mut payload).unwrap();
        assert_eq!(&payload[..], hs_plaintext);

        // ── Call 3 (AwaitingOneRttKeys): no data, 1-RTT keys ready -> Done ─────
        let alice_1rtt_keys = alice_session.write_handshake(&mut Vec::new()).expect("1-RTT keys on call 3");
        let bob_1rtt_keys = bob_session.write_handshake(&mut Vec::new()).expect("1-RTT keys on call 3");

        assert!(!alice_session.is_handshaking());
        assert!(!bob_session.is_handshaking());

        // 1-RTT keys must also work cross-party...
        let mut buf2 = vec![0u8; header_len + hs_plaintext.len() + 16];
        buf2[..header_len].copy_from_slice(b"HDRXX");
        buf2[header_len..header_len + hs_plaintext.len()].copy_from_slice(hs_plaintext);
        alice_1rtt_keys.packet.local.encrypt(0, &mut buf2, header_len);
        let mut payload2 = BytesMut::from(&buf2[header_len..]);
        bob_1rtt_keys.packet.remote.decrypt(0, &buf2[..header_len], &mut payload2).unwrap();
        assert_eq!(&payload2[..], hs_plaintext);

        // ...but must be a genuinely different key: same plaintext, same packet
        // number, different ciphertext, because "handshake" and "1-rtt" are
        // different export_secret labels.
        assert_ne!(hs_ciphertext, buf2[header_len..]);

        // The handshake is fully done — a fourth call must do nothing.
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
}
