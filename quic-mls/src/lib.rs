use bytes::BytesMut;
use quinn_proto::crypto::{CryptoError, HeaderKey, KeyPair, Keys, PacketKey};


// ── RFC 9001 / TLS 1.3 HKDF-Expand-Label ─────────────────────────────────────

use hkdf::Hkdf;
use sha2::Sha256;
const INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
    0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
];
fn hkdf_label_info(label: &str, context: &[u8], len: usize) -> Vec<u8> {
    let full_label = format!("tls13 {label}");
    let mut info = Vec::with_capacity(2 + 1 + full_label.len() + 1 + context.len());
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(full_label.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    info
}


fn hkdf_expand_label(secret: &[u8], label: &str, context: &[u8], len: usize) -> Vec<u8> {
    let info = hkdf_label_info(label, context, len);
    let hkdf = Hkdf::<Sha256>::from_prk(secret).expect("secret is a valid 32-byte PRK");
    let mut okm = vec![0u8; len];
    hkdf.expand(&info, &mut okm).expect("len is far below HKDF's 255*32-byte max");
    okm
}


#[cfg(test)]
mod hkdf_tests {
    use super::*;

    #[test]
    fn output_length_matches_request() {
        let secret = [0x42u8; 32];
        assert_eq!(hkdf_expand_label(&secret, "quic key", b"", 16).len(), 16);
        assert_eq!(hkdf_expand_label(&secret, "quic iv", b"", 12).len(), 12);
    }

    #[test]
    fn different_labels_give_different_output() {
        let secret = [0x42u8; 32];
        let key = hkdf_expand_label(&secret, "quic key", b"", 16);
        let hp = hkdf_expand_label(&secret, "quic hp", b"", 16);
        assert_ne!(key, hp, "different labels must not collide");
    }

    #[test]
    fn same_input_is_deterministic() {
        let secret = [0x42u8; 32];
        let a = hkdf_expand_label(&secret, "quic hp", b"", 16);
        let b = hkdf_expand_label(&secret, "quic hp", b"", 16);
        assert_eq!(a, b, "both endpoints must derive identical keys from the same secret");
    }

    #[test]
    fn different_secrets_give_different_output() {
        let a = hkdf_expand_label(&[0x42u8; 32], "quic key", b"", 16);
        let b = hkdf_expand_label(&[0x43u8; 32], "quic key", b"", 16);
        assert_ne!(a, b);
    }
}


//------Aes128GcmPacketKey----------------------------------------------
use aes_gcm::{aead::AeadInPlace, Aes128Gcm, Key, KeyInit, Nonce, Tag};
//type Aes128Gcm so default is 16 byts aeadinplace trait gives you. encrypt and decrypt in place handles buffer. key nonce tag fixed size 
#[derive(Debug, PartialEq)]
struct Aes128GcmPacketKey { key: [u8; 16], iv: [u8; 12] }
fn nonce_for(iv: &[u8; 12], packet: u64) -> [u8; 12] {
    let mut nonce = *iv;
    let pn_bytes = packet.to_be_bytes(); // 8 bytes, big-endian
    // first four bytes are untouched, last 8 bytes are packet number 
    for i in 0..8 {
        nonce[4 + i] ^= pn_bytes[i];
    }
    nonce
}
impl PacketKey for Aes128GcmPacketKey {
    // Encrypts the payload in buf, leaving the header untouched. The tag is written to the end of buf.
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        let nonce_bytes = nonce_for(&self.iv, packet);
        let (header, rest) = buf.split_at_mut(header_len);
        let pt_len = rest.len() - 16;
        let (plaintext, tag_dst) = rest.split_at_mut(pt_len);
        //plain text gets encrypted in place
        let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&self.key));
        //tag is the authentication tag, which is written to the end of the buffer. The encrypt_in_place_detached method encrypts the plaintext in place and returns the tag.
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce_bytes), header, plaintext)
            .expect("encryption with a valid key/nonce never fails");
        tag_dst.copy_from_slice(&tag);
    }

    //Decrypts the payload in place, leaving the header untouched. The tag is expected to be at the end of the payload.
    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        // crypto error is returned if the tag does not match, indicating that the payload has been tampered with or corrupted. The payload is truncated to remove the tag after decryption.
        let nonce_bytes = nonce_for(&self.iv, packet);
        let tag_start = payload.len() - 16;
        let (ciphertext, tag) = payload.split_at_mut(tag_start);

        let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&self.key));
        cipher
            .decrypt_in_place_detached(Nonce::from_slice(&nonce_bytes), header, ciphertext, Tag::from_slice(tag))
            .map_err(|_| CryptoError)?;

        payload.truncate(tag_start);
        Ok(())
    }

    fn tag_len(&self) -> usize { 16 }

    // Disables QUIC's automatic usage-based key rotation
    fn confidentiality_limit(&self) -> u64 { u64::MAX }

    fn integrity_limit(&self) -> u64 { u64::MAX }
}

//------Aes128EcbHeaderKey----------------------------------------------
struct Aes128EcbHeaderKey { key: [u8; 16] }
impl HeaderKey for Aes128EcbHeaderKey {
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        self.apply_mask(pn_offset, packet);
    }
    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        self.apply_mask(pn_offset, packet);
    }
    fn sample_size(&self) -> usize { 16 }
}
impl Aes128EcbHeaderKey {
    // Computes the mask for header protection using AES-ECB mode. The sample is a 16-byte slice from the packet, and the mask is derived by encrypting this sample with the header protection key.
    fn compute_mask(&self, sample: &[u8]) -> [u8; 16] {
        use aes::cipher::{BlockEncrypt, KeyInit};
        let cipher = aes::Aes128::new_from_slice(&self.key).expect("key is 16 bytes");
        let mut block = aes::Block::clone_from_slice(sample);
        cipher.encrypt_block(&mut block);
        let mut mask = [0u8; 16];
        mask.copy_from_slice(&block);
        mask
    }

    // Applies the computed mask to the packet's header for protection.
    fn apply_mask(&self, pn_offset: usize, packet: &mut [u8]) {
        let sample = &packet[pn_offset + 4..pn_offset + 20];
        let mask = self.compute_mask(sample);
        // The first byte of the packet is masked differently depending on whether it's a long header or a short header. The packet number length is determined by the lower two bits of the first byte, and the corresponding bytes are masked accordingly.
        let is_long_header = packet[0] & 0x80 != 0;
        if is_long_header {
            packet[0] ^= mask[0] & 0x0f;
        } else {
            packet[0] ^= mask[0] & 0x1f;
        }

        let pn_len = (packet[0] & 0x03) as usize + 1;
        for i in 0..pn_len {
            packet[pn_offset + i] ^= mask[1 + i];
        }
    }
}


//----client server directional keys------------------------------------------------
fn derive_keys_from_secret(secret: &[u8]) -> (Aes128GcmPacketKey, Aes128EcbHeaderKey) {
    let key: [u8; 16] = hkdf_expand_label(secret, "quic key", b"", 16).try_into().expect("16 bytes");
    let iv:  [u8; 12] = hkdf_expand_label(secret, "quic iv",  b"", 12).try_into().expect("12 bytes");
    let hp:  [u8; 16] = hkdf_expand_label(secret, "quic hp",  b"", 16).try_into().expect("16 bytes");
    (Aes128GcmPacketKey { key, iv }, Aes128EcbHeaderKey { key: hp })
}

fn derive_directional_keys(client_secret: &[u8], server_secret: &[u8], side: Side) -> Keys {
    let (client_packet, client_header) = derive_keys_from_secret(client_secret);
    let (server_packet, server_header) = derive_keys_from_secret(server_secret);

    let (local_packet, remote_packet, local_header, remote_header) = match side {
        Side::Client => (client_packet, server_packet, client_header, server_header),
        Side::Server => (server_packet, client_packet, server_header, client_header),
    };

    Keys {
        header: KeyPair { local: Box::new(local_header), remote: Box::new(remote_header) },
        packet: KeyPair { local: Box::new(local_packet), remote: Box::new(remote_packet) },
    }
}

#[cfg(test)]
mod directional_tests {
    use super::*;

    #[test]
    fn client_and_server_keys_are_independent_but_cross_compatible() {
        let client_secret = [0x11u8; 32];
        let server_secret = [0x22u8; 32];

        let client_keys = derive_directional_keys(&client_secret, &server_secret, Side::Client);
        let server_keys = derive_directional_keys(&client_secret, &server_secret, Side::Server);

        let header_len = 5;
        let plaintext = b"hello quic-mls";
        let mut buf = vec![0u8; header_len + plaintext.len() + 16];
        buf[..header_len].copy_from_slice(b"HDRXX");
        buf[header_len..header_len + plaintext.len()].copy_from_slice(plaintext);

        // Client sends using its local key...
        client_keys.packet.local.encrypt(0, &mut buf, header_len);

        // ...server receives it using its remote key.
        let mut payload = BytesMut::from(&buf[header_len..]);
        server_keys.packet.remote.decrypt(0, &buf[..header_len], &mut payload).unwrap();
        assert_eq!(&payload[..], plaintext);
    }
}


#[test]
fn same_secret_reproduces_identical_key_different_secret_does_not() {
    let client_secret = [0x11u8; 32];
    let server_secret = [0x22u8; 32];

    let (client_packet, _) = derive_keys_from_secret(&client_secret);
    let (server_packet, _) = derive_keys_from_secret(&server_secret);

    // Different secrets must give different keys (direction independence).
    assert_ne!(client_packet, server_packet);

    // The SAME secret, derived twice, must give the IDENTICAL key — this is
    // exactly why client.local (built from client_secret) and server.remote
    // (also built from client_secret) end up byte-for-byte equal in
    // derive_directional_keys, even though we never compare them directly there.
    let (client_packet_again, _) = derive_keys_from_secret(&client_secret);
    assert_eq!(client_packet, client_packet_again);
}
fn derive_initial_secrets(dst_cid: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // Hkdf::new runs Extract(salt, dst_cid) and keeps the resulting PRK
    // internally, ready for repeated Expand calls below.
    let hkdf = Hkdf::<Sha256>::new(Some(&INITIAL_SALT), dst_cid);

    let mut client_secret = vec![0u8; 32];
    hkdf.expand(&hkdf_label_info("client in", b"", 32), &mut client_secret)
        .expect("32 bytes is within HKDF's max output");

    let mut server_secret = vec![0u8; 32];
    hkdf.expand(&hkdf_label_info("server in", b"", 32), &mut server_secret)
        .expect("32 bytes is within HKDF's max output");

    (client_secret, server_secret)
}

fn derive_initial_keys(dst_cid: &[u8], side: Side) -> Keys {
    let (client_secret, server_secret) = derive_initial_secrets(dst_cid);
    derive_directional_keys(&client_secret, &server_secret, side)
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

#[test]
fn initial_secrets_are_deterministic_and_cid_sensitive() {
    let cid_a = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    let cid_b = [0x00; 8];

    let (client_a, server_a) = derive_initial_secrets(&cid_a);
    let (client_a_again, _) = derive_initial_secrets(&cid_a);
    assert_eq!(client_a, client_a_again, "same CID must give same secret");
    assert_ne!(client_a, server_a, "client and server secrets must differ");

    let (client_b, _) = derive_initial_secrets(&cid_b);
    assert_ne!(client_a, client_b, "different CIDs must give different secrets");
}

