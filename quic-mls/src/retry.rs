use aes_gcm::{aead::AeadInPlace, Aes128Gcm, Key, KeyInit, Nonce, Tag};
const RETRY_INTEGRITY_KEY: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
const RETRY_INTEGRITY_NONCE: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

pub(crate) fn compute_retry_tag(orig_dst_cid: &[u8], packet: &[u8]) -> [u8; 16] {
    let mut pseudo_packet = Vec::with_capacity(1 + orig_dst_cid.len() + packet.len());
    pseudo_packet.push(orig_dst_cid.len() as u8);
    pseudo_packet.extend_from_slice(orig_dst_cid);
    pseudo_packet.extend_from_slice(packet);

    let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&RETRY_INTEGRITY_KEY));
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&RETRY_INTEGRITY_NONCE), &pseudo_packet, &mut [])
        .expect("MAC-only AEAD call with an empty buffer cannot fail");
    let mut out = [0u8; 16];
    out.copy_from_slice(&tag);
    out
}

pub(crate) fn verify_retry_tag(orig_dst_cid: &[u8], header: &[u8], payload: &[u8]) -> bool {
    let Some(tag_start) = payload.len().checked_sub(16) else { return false };

    let mut pseudo_packet = Vec::with_capacity(1 + orig_dst_cid.len() + header.len() + tag_start);
    pseudo_packet.push(orig_dst_cid.len() as u8);
    pseudo_packet.extend_from_slice(orig_dst_cid);
    pseudo_packet.extend_from_slice(header);
    pseudo_packet.extend_from_slice(&payload[..tag_start]);

    let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&RETRY_INTEGRITY_KEY));
    cipher
        .decrypt_in_place_detached(Nonce::from_slice(&RETRY_INTEGRITY_NONCE), &pseudo_packet, &mut [], Tag::from_slice(&payload[tag_start..]))
        .is_ok()
}
