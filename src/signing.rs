//! Manifest authenticity — ed25519 verification of signed manifests (ADR-0003).
//!
//! A signature attests *"component `<id>` is exactly these bytes, vouched for by
//! this signer"* — it covers the canonical [`Manifest::signed_message`]
//! (`"<id>\n<wasm-sha256>"`). The signer is resolved to a public key via the
//! policy [`signers`](crate::policy::Policy::signers) registry. This module does
//! verification only; signing (key custody) lives in tooling, not the runtime.

use crate::error::{AiueosError, Result};
use crate::manifest::Manifest;
use crate::policy::Policy;
use ed25519_dalek::{Signature, VerifyingKey};

/// The authenticity status of a manifest under a policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigStatus {
    /// No `:aiueos/signature` — authenticity is up to policy (may still run).
    Unsigned,
    /// Signature verified against a registered signer's key. Carries the signer id.
    Verified(String),
}

/// Decode an even-length hex string into bytes. A non-hex digit or odd length is
/// an error (we never want a malformed key/sig to be silently treated as empty).
fn from_hex(s: &str, what: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(AiueosError::Schema(format!("{what}: odd-length hex")));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| AiueosError::Schema(format!("{what}: invalid hex")))
        })
        .collect()
}

/// Verify a manifest's signature against the policy signer registry.
///
/// - No signature → [`SigStatus::Unsigned`] (policy decides whether that's allowed).
/// - Signed → the signer must be registered **and** the signature must verify over
///   the canonical message, else a hard [`AiueosError::Denied`]. A bad signature is
///   never downgraded to "unsigned" — a forged attestation is worse than none.
pub fn verify(m: &Manifest, policy: &Policy) -> Result<SigStatus> {
    let sig_hex = match &m.signature {
        None => return Ok(SigStatus::Unsigned),
        Some(s) => s,
    };
    let deny = |msg: String| {
        Err(AiueosError::Denied(vec![crate::policy::Violation {
            component: m.id.clone(),
            kind: crate::policy::ViolationKind::BadSignature,
            message: msg,
        }]))
    };

    let signer = match &m.signer {
        Some(s) => s,
        None => return deny("signature present but no :aiueos/signer".into()),
    };
    let msg = match m.signed_message() {
        Some(b) => b,
        None => return deny("signed manifest must declare :aiueos/wasm-sha256".into()),
    };
    let key_hex = match policy.signers.get(signer) {
        Some(k) => k,
        None => return deny(format!("signer `{signer}` is not a registered signer")),
    };

    let key_bytes = from_hex(key_hex, "signer key")?;
    let sig_bytes = from_hex(sig_hex, "signature")?;
    let key_arr: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| AiueosError::Schema("signer key must be 32 bytes".into()))?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| AiueosError::Schema("signature must be 64 bytes".into()))?;

    let vk = VerifyingKey::from_bytes(&key_arr)
        .map_err(|_| AiueosError::Schema("bad public key".into()))?;
    match vk.verify_strict(msg.as_bytes(), &Signature::from_bytes(&sig_arr)) {
        Ok(()) => Ok(SigStatus::Verified(signer.clone())),
        Err(_) => deny(format!("signature does not verify for signer `{signer}`")),
    }
}
