// All mls-rs operations are synchronous when the `mls_build_async` feature is
// absent (the default).  No tokio runtime is needed here.
use mls_rs::{
    identity::{
        basic::{BasicCredential, BasicIdentityProvider},
        SigningIdentity,
    },
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, ExtensionList,
};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;

const CS: CipherSuite = CipherSuite::CURVE25519_AES128;

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("MLS: {0}")]
    Mls(#[from] mls_rs::error::MlsError),
    #[error("crypto: {0}")]
    Crypto(String),
}

/// Build a Client whose identity is `name` using in-memory storage and the
/// RustCrypto cipher-suite provider.
fn make_client(name: &str) -> Result<Client<impl mls_rs::client_builder::MlsConfig>, Error> {
    let crypto = RustCryptoProvider::new();
    let cs_provider = crypto
        .cipher_suite_provider(CS)
        .ok_or_else(|| Error::Crypto(format!("cipher suite {CS:?} not supported")))?;

    // Generate a fresh signature key pair for this identity.
    let (secret_key, public_key) = cs_provider
        .signature_key_generate()
        .map_err(|e| Error::Crypto(format!("{e:?}")))?;

    let credential = BasicCredential::new(name.as_bytes().to_vec()).into_credential();
    let signing_identity = SigningIdentity::new(credential, public_key);

    Ok(Client::builder()
        .crypto_provider(RustCryptoProvider::new())
        .identity_provider(BasicIdentityProvider::new())
        .signing_identity(signing_identity, secret_key, CS)
        .build())
}

fn main() -> Result<(), Error> {
    let alice = make_client("alice")?;
    let bob = make_client("bob")?;

    // ── Epoch 0 → 1: Alice creates group, adds Bob via Commit ────────────────

    let mut alice_group = alice.create_group(ExtensionList::new(), ExtensionList::new(), None)?;

    let bob_kp =
        bob.generate_key_package_message(ExtensionList::new(), ExtensionList::new(), None)?;

    // Add Bob as a member; the Welcome message in commit_out is how Bob joins.
    let commit_out = alice_group.commit_builder().add_member(bob_kp)?.build()?;
    alice_group.apply_pending_commit()?;

    let (mut bob_group, _) = bob.join_group(None, &commit_out.welcome_messages[0], None)?;

    // ── Epoch 1: both members must derive identical export_secret ────────────

    let alice_e1 = alice_group.export_secret(b"quic-mls-baseline", b"", 32)?;
    let bob_e1 = bob_group.export_secret(b"quic-mls-baseline", b"", 32)?;
    assert_eq!(
        alice_e1, bob_e1,
        "epoch 1: alice and bob export_secret must match"
    );
    println!("epoch 1  export_secret: alice == bob  \u{2713}");

    // ── Epoch 1 → 2: bare Commit advances the epoch ─────────────────────────

    // Alice creates a commit with no proposals to advance the epoch.
    let commit2 = alice_group.commit(vec![])?;
    alice_group.apply_pending_commit()?;
    // Bob must process the same commit message to advance to epoch 2.
    bob_group.process_incoming_message(commit2.commit_message)?;

    // ── Epoch 2: secrets must match again, and differ from epoch 1 ──────────

    let alice_e2 = alice_group.export_secret(b"quic-mls-baseline", b"", 32)?;
    let bob_e2 = bob_group.export_secret(b"quic-mls-baseline", b"", 32)?;
    assert_eq!(
        alice_e2, bob_e2,
        "epoch 2: alice and bob export_secret must match"
    );
    assert_ne!(
        alice_e1, alice_e2,
        "epoch rotation must produce a different export_secret"
    );
    println!("epoch 2  export_secret: alice == bob  \u{2713}");
    println!("epoch 1  !=  epoch 2                  \u{2713}");

    Ok(())
}
