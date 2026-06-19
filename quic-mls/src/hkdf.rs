use hkdf::Hkdf;
use sha2::Sha256;

pub(crate) const INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
    0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
];

pub(crate) fn hkdf_label_info(label: &str, context: &[u8], len: usize) -> Vec<u8> {
    let full_label = format!("tls13 {label}");
    let mut info = Vec::with_capacity(2 + 1 + full_label.len() + 1 + context.len());
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(full_label.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    info
}

pub(crate) fn hkdf_expand_label(secret: &[u8], label: &str, context: &[u8], len: usize) -> Vec<u8> {
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
