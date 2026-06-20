use quinn_proto::crypto::HeaderKey;

pub(crate) struct Aes128EcbHeaderKey {
    pub(crate) key: [u8; 16],
}

impl HeaderKey for Aes128EcbHeaderKey {
    // The receiver doesn't know pn_len until the first byte's mask has been
    // removed, so pn_len must be read AFTER unmasking packet[0].
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let mask = self.compute_mask(&packet[pn_offset + 4..pn_offset + 20]);
        Self::xor_first_byte(packet, mask[0]);
        let pn_len = (packet[0] & 0x03) as usize + 1;
        Self::xor_pn_bytes(packet, pn_offset, pn_len, &mask);
    }

    // The sender already knows pn_len from how it encoded the packet number.
    // Masking packet[0] can flip its low 2 bits, so pn_len must be read
    // BEFORE masking — otherwise the wrong number of pn bytes get masked.
    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let mask = self.compute_mask(&packet[pn_offset + 4..pn_offset + 20]);
        let pn_len = (packet[0] & 0x03) as usize + 1;
        Self::xor_first_byte(packet, mask[0]);
        Self::xor_pn_bytes(packet, pn_offset, pn_len, &mask);
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


    // Long headers only let the mask touch the low 4 bits; short headers the low 5.
    fn xor_first_byte(packet: &mut [u8], mask_byte: u8) {
        let is_long_header = packet[0] & 0x80 != 0;
        if is_long_header {
            packet[0] ^= mask_byte & 0x0f;
        } else {
            packet[0] ^= mask_byte & 0x1f;
        }
    }

    fn xor_pn_bytes(packet: &mut [u8], pn_offset: usize, pn_len: usize, mask: &[u8; 16]) {
        for i in 0..pn_len {
            packet[pn_offset + i] ^= mask[1 + i];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hkdf::{hkdf_expand_label, hkdf_label_info, INITIAL_SALT};
    use ::hkdf::Hkdf;
    use sha2::Sha256;

    // Known-good vector reproduced from quinn-proto's own test suite
    // (quinn-proto-0.11.14 src/packet.rs::header_encoding) — a verified
    // reference implementation's actual output, not a hand-derived value.
    #[test]
    fn compute_mask_matches_known_vector() {
        let dst_cid = [0x06u8, 0xb8, 0x58, 0xec, 0x6f, 0x80, 0x45, 0x2b];
        let extracted = Hkdf::<Sha256>::new(Some(&INITIAL_SALT), &dst_cid);
        let mut client_secret = vec![0u8; 32];
        extracted
            .expand(&hkdf_label_info("client in", b"", 32), &mut client_secret)
            .unwrap();
        let hp_key: [u8; 16] = hkdf_expand_label(&client_secret, "quic hp", b"", 16)
            .try_into()
            .unwrap();

        let header_key = Aes128EcbHeaderKey { key: hp_key };

        // 16-byte sample taken from the known-good encrypted packet, at
        // pn_offset+4 (pn_offset=18 in that packet).
        let sample: [u8; 16] = [
            0x07, 0xb8, 0x41, 0x91, 0xa1, 0x96, 0xf7, 0x60,
            0xa6, 0xda, 0xd1, 0xe9, 0xd1, 0xc4, 0x30, 0xc4,
        ];

        let mask = header_key.compute_mask(&sample);

        // Unprotected first byte 0xc0 -> protected 0xc8 means mask[0]&0x0f == 0x08.
        // Unprotected pn byte 0x00 -> protected 0xbe means mask[1] == 0xbe.
        assert_eq!(mask[0] & 0x0f, 0x08, "mask[0] low nibble should be 0x08");
        assert_eq!(mask[1], 0xbe, "mask[1] should be 0xbe");
    }

    #[test]
    fn apply_mask_matches_known_vector_full_packet() {
        let dst_cid = [0x06u8, 0xb8, 0x58, 0xec, 0x6f, 0x80, 0x45, 0x2b];
        let extracted = Hkdf::<Sha256>::new(Some(&INITIAL_SALT), &dst_cid);
        let mut client_secret = vec![0u8; 32];
        extracted
            .expand(&hkdf_label_info("client in", b"", 32), &mut client_secret)
            .unwrap();
        let hp_key: [u8; 16] = hkdf_expand_label(&client_secret, "quic hp", b"", 16)
            .try_into()
            .unwrap();
        let header_key = Aes128EcbHeaderKey { key: hp_key };

        // The unprotected packet (header_data, including the plain pn byte,
        // followed by the AEAD ciphertext+tag, which header protection never
        // touches).
        #[rustfmt::skip]
        let mut packet: Vec<u8> = vec![
            0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0xb8, 0x58, 0xec, 0x6f, 0x80, 0x45, 0x2b, 0x00, 0x00, 0x40, 0x21, 0x00,
            0x3e, 0xf5, 0x08, 0x07, 0xb8, 0x41, 0x91, 0xa1, 0x96, 0xf7, 0x60, 0xa6, 0xda, 0xd1, 0xe9, 0xd1, 0xc4,
            0x30, 0xc4, 0x89, 0x52, 0xcb, 0xa0, 0x14, 0x82, 0x50, 0xc2, 0x1c, 0x0a, 0x6a, 0x70, 0xe1,
        ];

        #[rustfmt::skip]
        let expected: Vec<u8> = vec![
            0xc8, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0xb8, 0x58, 0xec, 0x6f, 0x80, 0x45, 0x2b, 0x00, 0x00, 0x40, 0x21, 0xbe,
            0x3e, 0xf5, 0x08, 0x07, 0xb8, 0x41, 0x91, 0xa1, 0x96, 0xf7, 0x60, 0xa6, 0xda, 0xd1, 0xe9, 0xd1, 0xc4,
            0x30, 0xc4, 0x89, 0x52, 0xcb, 0xa0, 0x14, 0x82, 0x50, 0xc2, 0x1c, 0x0a, 0x6a, 0x70, 0xe1,
        ];

        header_key.encrypt(18, &mut packet);
        assert_eq!(packet, expected);
    }
}
