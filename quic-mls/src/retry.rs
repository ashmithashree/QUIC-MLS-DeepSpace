//Note:
// Retry packet integrity check (AEAD-based, fixed key/nonce per RFC).
// Reference: RFC 9001 §5.8 (Retry Packet Integrity), IETF, Thomson & Turner, 2021.
//   https://www.rfc-editor.org/rfc/rfc9001.html#name-retry-packet-integrity
// AES-128-GCM packet protection and AES-ECB header protection, structured
// to satisfy quinn-proto's PacketKey / HeaderKey traits.
// References:
//   RFC 9001 section 5.3 (AEAD Usage) and section 5.4 (Header Protection), IETF, 2021.
//     https://www.rfc-editor.org/rfc/rfc9001.html
//   quinn-proto crate docs, crypto::{PacketKey, HeaderKey} traits.
//     https://docs.rs/quinn-proto/latest/quinn_proto/crypto/
//======================================================================================================================
use aes_gcm::{aead::AeadInPlace, Aes128Gcm, Key, KeyInit, Nonce, Tag};
//Reference vector from https://www.rfc-editor.org/rfc/rfc9001.html#name-retry-packet-integrity
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

