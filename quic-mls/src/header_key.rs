use quinn_proto::crypto::HeaderKey;

pub(crate) struct Aes128EcbHeaderKey {
    pub(crate) key: [u8; 16],
}

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
