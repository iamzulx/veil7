// Author: Iamzulx
// Copyright (c) 2026
// License: MIT
//! libcrux backend adapter — formally verified PQ primitives.
//!
//! Wraps `libcrux-ml-kem` and `libcrux-ml-dsa` to provide the same
//! interface that veil7's L2/L4/L5 layers expect. Replaces the RustCrypto
//! `ml-kem` and `ml-dsa` crates with hax/F*-verified implementations.
//!
//! ## Why libcrux?
//! - **Formally verified**: core arithmetic, NTT, serialization via hax/F*
//! - **Constant-time**: secret-independence checked via type system
//! - **No C dependencies**: pure Rust with optional SIMD (AVX2/NEON)
//! - **FIPS 203/204 compliant**
//! - **Audited codebase**: from Cryspen (HACL* project)

use crate::VeilError;

// ── Re-export libcrux types ─────────────────────────────────────────────────

pub use libcrux_ml_kem::mlkem768::{
    self, MlKem768Ciphertext, MlKem768KeyPair, MlKem768PrivateKey, MlKem768PublicKey,
};
pub use libcrux_ml_kem::MlKemSharedSecret;

pub use libcrux_ml_dsa::ml_dsa_65::{
    self, MLDSA65KeyPair, MLDSA65Signature, MLDSA65SigningKey, MLDSA65VerificationKey,
};

// ── Key size constants ──────────────────────────────────────────────────────

/// ML-KEM-768 public key size (1184 bytes).
pub const KEM_PK_SIZE: usize = 1184;
/// ML-KEM-768 private key size (2400 bytes).
pub const KEM_SK_SIZE: usize = 2400;
/// ML-KEM-768 ciphertext size (1088 bytes).
pub const KEM_CT_SIZE: usize = 1088;
/// ML-KEM-768 shared secret size (32 bytes).
pub const KEM_SS_SIZE: usize = 32;
/// ML-KEM-768 keygen seed size (64 bytes).
pub const KEM_SEED_SIZE: usize = 64;

/// ML-DSA-65 verification key size (1952 bytes).
pub const DSA_VK_SIZE: usize = 1952;
/// ML-DSA-65 signing key size (4032 bytes).
pub const DSA_SK_SIZE: usize = 4032;
/// ML-DSA-65 signature size (3309 bytes).
pub const DSA_SIG_SIZE: usize = 3309;
/// ML-DSA-65 keygen seed size (32 bytes).
pub const DSA_SEED_SIZE: usize = 32;

// ── Key validation ──────────────────────────────────────────────────────────

/// Validate ML-KEM-768 public key.
///
/// Checks that the public key has the correct size.
/// Returns true if valid, false otherwise.
pub fn validate_kem_pk(pk_bytes: &[u8]) -> bool {
    // Check size - libcrux will validate format when key is used
    pk_bytes.len() == KEM_PK_SIZE
}

/// Validate ML-DSA-65 verification key.
///
/// Checks that the verification key has the correct size.
/// Returns true if valid, false otherwise.
pub fn validate_dsa_vk(vk_bytes: &[u8]) -> bool {
    // Check size - libcrux will validate format when key is used
    vk_bytes.len() == DSA_VK_SIZE
}

// ── Key generation ──────────────────────────────────────────────────────────

/// Generate ML-KEM-768 key pair from a 64-byte seed (FIPS 203).
///
/// Deterministic: same seed → same key pair.
pub fn kem_keygen(seed: [u8; KEM_SEED_SIZE]) -> MlKem768KeyPair {
    mlkem768::generate_key_pair(seed)
}

/// Generate ML-DSA-65 key pair from a 32-byte seed (FIPS 204).
///
/// Deterministic: same seed → same key pair.
pub fn dsa_keygen(seed: [u8; DSA_SEED_SIZE]) -> MLDSA65KeyPair {
    ml_dsa_65::generate_key_pair(seed)
}

// ── KEM operations ──────────────────────────────────────────────────────────

/// Encapsulate: produce (ciphertext, shared_secret) from a public key.
///
/// `randomness` is a 32-byte seed for the encapsulation coins.
pub fn kem_encapsulate(
    pk: &MlKem768PublicKey,
    randomness: [u8; KEM_SS_SIZE],
) -> (MlKem768Ciphertext, MlKemSharedSecret) {
    mlkem768::encapsulate(pk, randomness)
}

/// Decapsulate: recover shared secret from ciphertext + private key.
pub fn kem_decapsulate(sk: &MlKem768PrivateKey, ct: &MlKem768Ciphertext) -> MlKemSharedSecret {
    mlkem768::decapsulate(sk, ct)
}

// ── Signature operations ────────────────────────────────────────────────────

/// Sign a message with ML-DSA-65 (FIPS 204, Algorithm 7).
///
/// - `sk`: signing key
/// - `message`: the data to sign
/// - `context`: domain separator (may be empty, max 255 bytes)
/// - `randomness`: 32-byte signing randomness
///
/// Returns `Ok(signature)` or `Err(VeilError::Crypto)` on signing failure.
pub fn dsa_sign(
    sk: &MLDSA65SigningKey,
    message: &[u8],
    context: &[u8],
    randomness: [u8; 32],
) -> Result<MLDSA65Signature, VeilError> {
    ml_dsa_65::sign(sk, message, context, randomness).map_err(|_| VeilError::Crypto)
}

/// Verify an ML-DSA-65 signature (FIPS 204, Algorithm 8).
///
/// Returns `Ok(())` if valid, `Err(VeilError::Crypto)` if invalid.
pub fn dsa_verify(
    vk: &MLDSA65VerificationKey,
    message: &[u8],
    context: &[u8],
    signature: &MLDSA65Signature,
) -> Result<(), VeilError> {
    ml_dsa_65::verify(vk, message, context, signature).map_err(|_| VeilError::Crypto)
}

// ── Serialization helpers ───────────────────────────────────────────────────

/// Get public key bytes from a KEM key pair.
pub fn kem_pk_bytes(kp: &MlKem768KeyPair) -> &[u8; KEM_PK_SIZE] {
    kp.public_key().as_slice()
}

/// Get private key bytes from a KEM key pair.
pub fn kem_sk_bytes(kp: &MlKem768KeyPair) -> &[u8; KEM_SK_SIZE] {
    kp.private_key().as_slice()
}

/// Get verification key bytes from a DSA key pair.
pub fn dsa_vk_bytes(kp: &MLDSA65KeyPair) -> &[u8; DSA_VK_SIZE] {
    kp.verification_key.as_ref()
}

/// Get signing key bytes from a DSA key pair.
pub fn dsa_sk_bytes(kp: &MLDSA65KeyPair) -> &[u8; DSA_SK_SIZE] {
    kp.signing_key.as_ref()
}

/// Reconstruct a KEM public key from raw bytes.
pub fn kem_pk_from_bytes(bytes: &[u8; KEM_PK_SIZE]) -> MlKem768PublicKey {
    MlKem768PublicKey::from(*bytes)
}

/// Reconstruct a KEM private key from raw bytes.
pub fn kem_sk_from_bytes(bytes: &[u8; KEM_SK_SIZE]) -> MlKem768PrivateKey {
    MlKem768PrivateKey::from(*bytes)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kem_keygen_deterministic() {
        let seed = [0x42u8; KEM_SEED_SIZE];
        let kp1 = kem_keygen(seed);
        let kp2 = kem_keygen(seed);
        assert_eq!(kem_pk_bytes(&kp1), kem_pk_bytes(&kp2));
    }

    #[test]
    fn kem_keygen_different_seeds() {
        let kp1 = kem_keygen([0x01; KEM_SEED_SIZE]);
        let kp2 = kem_keygen([0x02; KEM_SEED_SIZE]);
        assert_ne!(kem_pk_bytes(&kp1), kem_pk_bytes(&kp2));
    }

    #[test]
    fn kem_encapsulate_decapsulate_roundtrip() {
        let kp = kem_keygen([0xAB; KEM_SEED_SIZE]);
        let pk = kp.public_key();
        let sk = kp.private_key();

        let randomness = [0xCD; KEM_SS_SIZE];
        let (ct, ss_enc) = kem_encapsulate(pk, randomness);
        let ss_dec = kem_decapsulate(sk, &ct);

        assert_eq!(ss_enc.as_slice(), ss_dec.as_slice());
    }

    #[test]
    fn kem_wrong_key_decapsulate_differs() {
        let kp1 = kem_keygen([0x11; KEM_SEED_SIZE]);
        let kp2 = kem_keygen([0x22; KEM_SEED_SIZE]);

        let (ct, ss_enc) = kem_encapsulate(kp1.public_key(), [0xEE; KEM_SS_SIZE]);
        let ss_wrong = kem_decapsulate(kp2.private_key(), &ct);

        assert_ne!(ss_enc.as_slice(), ss_wrong.as_slice());
    }

    #[test]
    fn dsa_keygen_deterministic() {
        let seed = [0x55; DSA_SEED_SIZE];
        let kp1 = dsa_keygen(seed);
        let kp2 = dsa_keygen(seed);
        assert_eq!(dsa_vk_bytes(&kp1), dsa_vk_bytes(&kp2));
    }

    #[test]
    fn dsa_sign_verify_roundtrip() {
        let kp = dsa_keygen([0x66; DSA_SEED_SIZE]);
        let msg = b"veil7 test message";
        let ctx = b"veil7:test:v1";
        let rng = [0x77; 32];

        let sig = dsa_sign(&kp.signing_key, msg, ctx, rng).unwrap();
        assert!(dsa_verify(&kp.verification_key, msg, ctx, &sig).is_ok());
    }

    #[test]
    fn dsa_verify_wrong_message() {
        let kp = dsa_keygen([0x88; DSA_SEED_SIZE]);
        let sig = dsa_sign(&kp.signing_key, b"original", b"ctx", [0x99; 32]).unwrap();
        assert!(dsa_verify(&kp.verification_key, b"tampered", b"ctx", &sig).is_err());
    }

    #[test]
    fn dsa_verify_wrong_context() {
        let kp = dsa_keygen([0xAA; DSA_SEED_SIZE]);
        let sig = dsa_sign(&kp.signing_key, b"msg", b"ctx-a", [0xBB; 32]).unwrap();
        assert!(dsa_verify(&kp.verification_key, b"msg", b"ctx-b", &sig).is_err());
    }

    #[test]
    fn dsa_verify_wrong_key() {
        let kp1 = dsa_keygen([0xCC; DSA_SEED_SIZE]);
        let kp2 = dsa_keygen([0xDD; DSA_SEED_SIZE]);
        let sig = dsa_sign(&kp1.signing_key, b"msg", b"ctx", [0xEE; 32]).unwrap();
        assert!(dsa_verify(&kp2.verification_key, b"msg", b"ctx", &sig).is_err());
    }

    #[test]
    fn kem_key_sizes_correct() {
        let kp = kem_keygen([0x00; KEM_SEED_SIZE]);
        assert_eq!(kem_pk_bytes(&kp).len(), KEM_PK_SIZE);
        assert_eq!(kem_sk_bytes(&kp).len(), KEM_SK_SIZE);
    }

    #[test]
    fn dsa_key_sizes_correct() {
        let kp = dsa_keygen([0x00; DSA_SEED_SIZE]);
        assert_eq!(dsa_vk_bytes(&kp).len(), DSA_VK_SIZE);
        assert_eq!(dsa_sk_bytes(&kp).len(), DSA_SK_SIZE);
    }
}
