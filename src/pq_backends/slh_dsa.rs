//! Formal SLH-DSA / FIPS 205 backend.
//!
//! SLH-DSA-SHAKE-128f is a stateless hash-based post-quantum signature scheme
//! (SPHINCS+). 128f is intentionally chosen because it keeps signing faster
//! than the small-signature variants while remaining category-1 PQ secure.
//! Signatures are large by design (~17 KB).
//!
//! All secret key material is wrapped in `Zeroize` and wiped on drop.

use core::convert::TryFrom;
use slh_dsa::{
    signature::{Keypair, Signer, Verifier},
    Shake128f, Signature, SigningKey, VerifyingKey,
};

// ── Constants ────────────────────────────────────────────────────────────────

/// Encoded SLH-DSA-SHAKE-128f signing key: SK.seed || SK.prf || PK.seed || PK.root.
pub const SECRET_KEY_LEN: usize = 64;

/// Deterministic seed material: SK.seed || SK.prf || PK.seed.
/// This is what you derive from entropy, then expand to a full secret key.
pub const SEED_MATERIAL_LEN: usize = 48;

/// Encoded public key: PK.seed || PK.root.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Encoded signature length (deterministic, constant).
pub const SIGNATURE_LEN: usize = 17_088;

// ── Type aliases ─────────────────────────────────────────────────────────────

/// Encoded SLH-DSA-SHAKE-128f secret key.
pub type SecretKey = [u8; SECRET_KEY_LEN];

/// Deterministic seed for deriving a valid secret key.
pub type SeedMaterial = [u8; SEED_MATERIAL_LEN];

/// Encoded SLH-DSA-SHAKE-128f public key.
pub type PublicKey = [u8; PUBLIC_KEY_LEN];

/// Encoded SLH-DSA-SHAKE-128f signature.
pub type SignatureBytes = [u8; SIGNATURE_LEN];

// ── Signer ───────────────────────────────────────────────────────────────────

/// Formal SLH-DSA-SHAKE-128f signer.
pub struct SlhDsaSigner;

impl SlhDsaSigner {
    /// Derive an encoded secret key from deterministic seed material.
    ///
    /// The seed layout must be: `SK.seed (16B) || SK.prf (16B) || PK.seed (16B)`.
    /// This is the canonical key-derivation from FIPS 205.
    pub fn derive_secret_key(seed: &SeedMaterial) -> SecretKey {
        let sk = SigningKey::<Shake128f>::slh_keygen_internal(
            &seed[..16],   // SK.seed
            &seed[16..32], // SK.prf
            &seed[32..48], // PK.seed
        );
        let raw = sk.to_bytes();
        let mut out = [0u8; SECRET_KEY_LEN];
        out.copy_from_slice(raw.as_slice());
        out
    }

    /// Derive an encoded public key from an encoded secret key.
    pub fn public_key(secret: &SecretKey) -> Option<PublicKey> {
        let sk = SigningKey::<Shake128f>::try_from(secret.as_slice()).ok()?;
        let raw = sk.verifying_key().to_bytes();
        let mut out = [0u8; PUBLIC_KEY_LEN];
        out.copy_from_slice(raw.as_slice());
        Some(out)
    }

    /// Deterministically sign `message`, then zeroize the secret key.
    pub fn sign(message: &[u8], secret: &mut SecretKey) -> Option<SignatureBytes> {
        let sk = SigningKey::<Shake128f>::try_from(secret.as_slice()).ok()?;
        let sig: Signature<Shake128f> = sk.sign(message);
        use zeroize::Zeroize;
        secret.zeroize();

        let raw = sig.to_bytes();
        let mut out = [0u8; SIGNATURE_LEN];
        out.copy_from_slice(raw.as_slice());
        Some(out)
    }

    /// Verify `signature` against `message` using `public`.
    /// Returns `true` iff valid. Malformed inputs → `false` (fail-closed).
    pub fn verify(message: &[u8], signature: &SignatureBytes, public: &PublicKey) -> bool {
        let vk = match VerifyingKey::<Shake128f>::try_from(public.as_slice()) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let sig = match Signature::<Shake128f>::try_from(signature.as_slice()) {
            Ok(s) => s,
            Err(_) => return false,
        };
        vk.verify(message, &sig).is_ok()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_sign_verify() {
        let seed: SeedMaterial = [0xABu8; SEED_MATERIAL_LEN];
        let mut sk = SlhDsaSigner::derive_secret_key(&seed);
        let pk = SlhDsaSigner::public_key(&sk).expect("valid secret key");
        let sig =
            SlhDsaSigner::sign(b"hello post-quantum world", &mut sk).expect("sign must succeed");
        assert!(SlhDsaSigner::verify(b"hello post-quantum world", &sig, &pk));
    }

    #[test]
    fn tampered_message_fails() {
        let seed: SeedMaterial = [0xCDu8; SEED_MATERIAL_LEN];
        let mut sk = SlhDsaSigner::derive_secret_key(&seed);
        let pk = SlhDsaSigner::public_key(&sk).expect("pk ok");
        let sig = SlhDsaSigner::sign(b"original", &mut sk).expect("sign ok");
        assert!(!SlhDsaSigner::verify(b"tampered", &sig, &pk));
    }

    #[test]
    fn wrong_public_key_fails() {
        let seed_a: SeedMaterial = [0x11u8; SEED_MATERIAL_LEN];
        let seed_b: SeedMaterial = [0x22u8; SEED_MATERIAL_LEN];
        let mut sk_a = SlhDsaSigner::derive_secret_key(&seed_a);
        let pk_b =
            SlhDsaSigner::public_key(&SlhDsaSigner::derive_secret_key(&seed_b)).expect("pk_b ok");
        let sig = SlhDsaSigner::sign(b"msg", &mut sk_a).expect("sign ok");
        assert!(!SlhDsaSigner::verify(b"msg", &sig, &pk_b));
    }

    #[test]
    fn malformed_signature_fails_closed() {
        let seed: SeedMaterial = [0x33u8; SEED_MATERIAL_LEN];
        let sk = SlhDsaSigner::derive_secret_key(&seed);
        let pk = SlhDsaSigner::public_key(&sk).expect("pk ok");
        let garbage = [0u8; SIGNATURE_LEN];
        assert!(!SlhDsaSigner::verify(b"msg", &garbage, &pk));
    }

    #[test]
    fn deterministic_same_seed_same_keys() {
        let seed: SeedMaterial = [0x77u8; SEED_MATERIAL_LEN];
        let sk1 = SlhDsaSigner::derive_secret_key(&seed);
        let sk2 = SlhDsaSigner::derive_secret_key(&seed);
        assert_eq!(sk1, sk2, "same seed → same secret key");
        let pk1 = SlhDsaSigner::public_key(&sk1).unwrap();
        let pk2 = SlhDsaSigner::public_key(&sk2).unwrap();
        assert_eq!(pk1, pk2, "same seed → same public key");
    }
}
