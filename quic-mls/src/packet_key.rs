use aes_gcm::{aead::AeadInPlace, Aes128Gcm, Key, KeyInit, Nonce, Tag};
use bytes::BytesMut;
use quinn_proto::crypto::{CryptoError, PacketKey};

//type Aes128Gcm so default is 16 byts aeadinplace trait gives you. encrypt and decrypt in place handles buffer. key nonce tag fixed size
#[derive(Debug, PartialEq)]
pub(crate) struct Aes128GcmPacketKey {
    pub(crate) key: [u8; 16],
    pub(crate) iv: [u8; 12],
}

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
