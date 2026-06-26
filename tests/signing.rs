//! ed25519 manifest authenticity (ADR-0003): a valid signature verifies and
//! resolves the signer; a tampered signature, an unregistered signer, a
//! missing-context signature, and an unsigned manifest each get the right
//! verdict. Generates a keypair in-test so it's self-contained.
#![cfg(feature = "signing")]

use aiueos::manifest::Manifest;
use aiueos::policy::Policy;
use aiueos::signing::{verify, SigStatus};
use ed25519_dalek::{Signer, SigningKey};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A deterministic keypair from a fixed seed (test-only).
fn keypair() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn policy_with_signer(name: &str, key_hex: &str) -> Policy {
    let src = format!("{{:aiueos/signers {{:{name} \"{key_hex}\"}}}}");
    Policy::from_edn(&kotoba_edn::parse(&src).unwrap()).unwrap()
}

fn signed_manifest(sig_hex: &str) -> Manifest {
    Manifest::parse_str(&format!(
        r#"{{:aiueos/component :driver/sensor :aiueos/kind :driver
            :aiueos/wasm-sha256 "abc123"
            :aiueos/signer "alice" :aiueos/signature "{sig_hex}"}}"#,
    ))
    .unwrap()
}

#[test]
fn a_valid_signature_verifies_and_names_the_signer() {
    let key = keypair();
    // sign the canonical message for (id=driver/sensor, hash=abc123)
    let sig = key.sign(b"driver/sensor\nabc123");
    let m = signed_manifest(&hex(&sig.to_bytes()));
    let policy = policy_with_signer("alice", &hex(key.verifying_key().as_bytes()));
    assert_eq!(
        verify(&m, &policy).unwrap(),
        SigStatus::Verified("alice".into())
    );
}

#[test]
fn a_tampered_signature_is_denied() {
    let key = keypair();
    // sign a DIFFERENT message → the signature won't verify the manifest's binding
    let sig = key.sign(b"driver/sensor\nDIFFERENT");
    let m = signed_manifest(&hex(&sig.to_bytes()));
    let policy = policy_with_signer("alice", &hex(key.verifying_key().as_bytes()));
    assert!(
        verify(&m, &policy).is_err(),
        "wrong-message signature must be denied"
    );
}

#[test]
fn an_unregistered_signer_is_denied() {
    let key = keypair();
    let sig = key.sign(b"driver/sensor\nabc123");
    let m = signed_manifest(&hex(&sig.to_bytes()));
    // policy registers a different signer name → "alice" is unknown
    let policy = policy_with_signer("bob", &hex(key.verifying_key().as_bytes()));
    assert!(
        verify(&m, &policy).is_err(),
        "unregistered signer must be denied"
    );
}

#[test]
fn an_unsigned_manifest_is_unsigned() {
    let m = Manifest::parse_str(
        r#"{:aiueos/component :driver/s :aiueos/kind :driver :aiueos/wasm-sha256 "abc123"}"#,
    )
    .unwrap();
    assert_eq!(verify(&m, &Policy::default()).unwrap(), SigStatus::Unsigned);
}

#[test]
fn a_signature_without_artifact_hash_is_denied() {
    // signed but nothing to bind (no :aiueos/wasm-sha256)
    let m = Manifest::parse_str(
        r#"{:aiueos/component :driver/s :aiueos/kind :driver
            :aiueos/signer "alice" :aiueos/signature "deadbeef"}"#,
    )
    .unwrap();
    let policy = policy_with_signer("alice", &hex(keypair().verifying_key().as_bytes()));
    assert!(verify(&m, &policy).is_err(), "no hash to bind → denied");
}
