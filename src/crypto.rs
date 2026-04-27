//! Ed25519 key generation, signing, and verification.
//!
//! Wraps the `ed25519-dalek` crate.  Key material is held in 32-byte seeds
//! (not expanded private keys).  The [`Keypair`] type is annotated with
//! `ZeroizeOnDrop` so that secret data is scrubbed from memory on drop.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::ZeroizeOnDrop;

/// An Ed25519 key pair stored as raw 32-byte seeds.
#[derive(ZeroizeOnDrop)]
pub(crate) struct Keypair {
    pub public: [u8; 32],
    pub secret: [u8; 32],
}

/// Derive the Ed25519 public key from a 32-byte secret seed.
pub(crate) fn derive_public(secret_seed: &[u8; 32]) -> [u8; 32] {
    let signing_key = SigningKey::from_bytes(secret_seed);
    signing_key.verifying_key().to_bytes()
}

/// Generate a fresh random key pair using the OS CSPRNG.
pub(crate) fn generate_keypair() -> Keypair {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    Keypair {
        public: verifying_key.to_bytes(),
        secret: signing_key.to_bytes(),
    }
}

/// Sign `message` with the given 32-byte secret seed.
pub(crate) fn sign(message: &[u8], secret_seed: &[u8; 32]) -> [u8; 64] {
    let signing_key = SigningKey::from_bytes(secret_seed);
    signing_key.sign(message).to_bytes()
}

/// Result of an Ed25519 signature verification.
pub(crate) enum VerifyResult {
    Valid,
    InvalidSignature,
    InvalidPublicKey,
}

/// Verify `signature` over `message` using the given 32-byte public key.
pub(crate) fn verify(message: &[u8], signature: &[u8; 64], public_key: &[u8; 32]) -> VerifyResult {
    let verifying_key = match VerifyingKey::from_bytes(public_key) {
        Ok(vk) => vk,
        Err(_) => return VerifyResult::InvalidPublicKey,
    };
    let sig = Signature::from_bytes(signature);
    match verifying_key.verify(message, &sig) {
        Ok(()) => VerifyResult::Valid,
        Err(_) => VerifyResult::InvalidSignature,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let keypair = generate_keypair();
        let message = b"hello world";
        let signature = sign(message, &keypair.secret);
        assert!(matches!(
            verify(message, &signature, &keypair.public),
            VerifyResult::Valid
        ));
    }

    #[test]
    fn tampered_message_fails_verification() {
        let keypair = generate_keypair();
        let signature = sign(b"original", &keypair.secret);
        assert!(matches!(
            verify(b"tampered", &signature, &keypair.public),
            VerifyResult::InvalidSignature
        ));
    }

    #[test]
    fn wrong_key_fails_verification() {
        let alice = generate_keypair();
        let bob = generate_keypair();
        let signature = sign(b"msg", &alice.secret);
        assert!(matches!(
            verify(b"msg", &signature, &bob.public),
            VerifyResult::InvalidSignature
        ));
    }

    #[test]
    fn invalid_public_key_detected() {
        let keypair = generate_keypair();
        let signature = sign(b"msg", &keypair.secret);
        // Corrupt a valid key mid-byte — extremely unlikely to remain valid
        let mut bad_pub = keypair.public;
        bad_pub[16] ^= 0x01;
        assert!(matches!(
            verify(b"msg", &signature, &bad_pub),
            VerifyResult::InvalidPublicKey
        ));
    }
}
