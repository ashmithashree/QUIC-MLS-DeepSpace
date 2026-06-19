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
