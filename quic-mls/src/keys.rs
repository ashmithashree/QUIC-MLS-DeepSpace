use crate::group::ExportSecret;
use crate::header_key::Aes128EcbHeaderKey;
use crate::hkdf::{hkdf_expand_label, hkdf_label_info, INITIAL_SALT};
use crate::packet_key::Aes128GcmPacketKey;
use hkdf::Hkdf;
use quinn_proto::crypto::{KeyPair, Keys};
use quinn_proto::Side;
use sha2::Sha256;

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

pub(crate) fn derive_initial_keys(dst_cid: &[u8], side: Side) -> Keys {
    let (client_secret, server_secret) = derive_initial_secrets(dst_cid);
    derive_directional_keys(&client_secret, &server_secret, side)
}

pub(crate) fn derive_mls_keys(group: &dyn ExportSecret, level: &str, side: Side) -> Result<Keys, mls_rs::error::MlsError> {
    let client_secret = group.export_secret(format!("quic-mls c2s {level}").as_bytes(), b"", 32)?;
    let server_secret = group.export_secret(format!("quic-mls s2c {level}").as_bytes(), b"", 32)?;
    Ok(derive_directional_keys(&client_secret, &server_secret, side))
}

#[cfg(test)]
mod directional_tests {
    use super::*;
    use bytes::BytesMut;

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

#[test]
fn derive_initial_keys_server_remote_decrypts_known_client_packet() {
    use bytes::BytesMut;

    let dst_cid = [0x06u8, 0xb8, 0x58, 0xec, 0x6f, 0x80, 0x45, 0x2b];
    let server_keys = derive_initial_keys(&dst_cid, Side::Server);

    // Known-good vector (quinn-proto's own test suite, src/packet.rs::header_encoding):
    // a real Initial packet, encrypted by the CLIENT, that this exact
    // dst_cid must decrypt correctly via the SERVER's `.remote` key.
    let header: [u8; 19] = [
        0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0xb8, 0x58, 0xec, 0x6f, 0x80, 0x45, 0x2b, 0x00, 0x00, 0x40, 0x21, 0x00,
    ];
    #[rustfmt::skip]
    let ciphertext_and_tag: [u8; 32] = [
        0x3e, 0xf5, 0x08, 0x07, 0xb8, 0x41, 0x91, 0xa1, 0x96, 0xf7, 0x60, 0xa6, 0xda, 0xd1, 0xe9, 0xd1, 0xc4,
        0x30, 0xc4, 0x89, 0x52, 0xcb, 0xa0, 0x14, 0x82, 0x50, 0xc2, 0x1c, 0x0a, 0x6a, 0x70, 0xe1,
    ];

    let mut payload = BytesMut::from(&ciphertext_and_tag[..]);
    server_keys.packet.remote.decrypt(0, &header, &mut payload).unwrap();
    assert_eq!(&payload[..], &[0u8; 16][..]);
}

#[test]
fn full_initial_packet_round_trip_with_20_byte_cid() {
    use bytes::BytesMut;

    // Quinn's default RandomConnectionIdGenerator uses MAX_CID_SIZE (20 bytes),
    // not the 8-byte CID from the reference vector — reproduce that shape.
    let dst_cid: [u8; 20] = [
        0x4d, 0xd1, 0x0b, 0x5d, 0x5c, 0x3b, 0x99, 0x7f, 0x91, 0xd5,
        0x69, 0x9d, 0xb2, 0x68, 0x92, 0x0e, 0xd9, 0xa4, 0x7c, 0x72,
    ];
    let client_keys = derive_initial_keys(&dst_cid, Side::Client);
    let server_keys = derive_initial_keys(&dst_cid, Side::Server);

    // Build a realistic Initial-packet-shaped buffer: 1(first byte) +
    // 4(version) + 1(dcid_len) + 20(dcid) + 1(scid_len) + 1(token_len) +
    // 2(length varint) = 30 bytes of header, then a packet number byte,
    // then plaintext, then tag space.
    let mut header = vec![0xc0u8, 0x00, 0x00, 0x00, 0x01, 20];
    header.extend_from_slice(&dst_cid);
    header.extend_from_slice(&[0x00, 0x00, 0x40, 0x21]); // scid_len, token_len, length varint
    let pn_offset = header.len();
    header.push(0x00); // packet number byte (pn=0, 1-byte encoding)
    let header_len = header.len();

    let plaintext = [0u8; 16];
    let mut buf = header.clone();
    buf.extend_from_slice(&plaintext);
    buf.extend_from_slice(&[0u8; 16]); // tag space

    client_keys.packet.local.encrypt(0, &mut buf, header_len);
    client_keys.header.local.encrypt(pn_offset, &mut buf);

    // Server receives: undo header protection, then decrypt the payload.
    server_keys.header.remote.decrypt(pn_offset, &mut buf);
    assert_eq!(&buf[..header_len], &header[..], "header must round-trip unchanged");

    let mut payload = BytesMut::from(&buf[header_len..]);
    server_keys.packet.remote.decrypt(0, &buf[..header_len], &mut payload).unwrap();
    assert_eq!(&payload[..], &plaintext[..]);
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
