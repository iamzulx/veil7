//! L2 — Ephemeral Keygen (libcrux backend).
//!
//! Deterministically derives two independent post-quantum keypairs from the L1
//! seed, using domain-separated SHAKE256 to split the master seed into:
//!   * a 64-byte ML-KEM-768 seed   (FIPS 203, libcrux hax/F* verified)
//!   * a 32-byte ML-DSA-65  seed   (FIPS 204, libcrux hax/F* verified)
//!
//! Statelessness: keys exist only for the lifetime of the returned `EphemeralKeys`.
//! Both PQ key types are wrapped in libcrux types that self-zeroize on drop.
//! The derived sub-seeds are wiped here before returning.
//!
//! ## Crypto-Agility
//!
//! This module supports crypto-agility via the `KeyGenerator` trait, allowing
//! easy swapping of cryptographic algorithms (e.g., ML-KEM-1024, ML-DSA-87)
//! without changing the core logic. This follows NIST SP 800-131A Rev. 3
//! recommendation for crypto-agility.

use crate::l0_memlock::zeroize_bytes;
use crate::l1_entropy::Seed;
use crate::pq_backends::libcrux_backend;
use crate::{domain, VeilError};

use libcrux_ml_dsa::ml_dsa_65::MLDSA65KeyPair;
use libcrux_ml_kem::mlkem768::MlKem768KeyPair;

use crate::shake256::Shake256;

// ── Crypto-Agility: KeyGenerator trait ──────────────────────────────────────

/// Trait for crypto-agile key generation.
///
/// Allows easy swapping of cryptographic algorithms without changing core logic.
/// Follows NIST SP 800-131A Rev. 3 recommendation for crypto-agility.
pub trait KeyGenerator {
    /// The type of key pair generated.
    type KeyPair;
    
    /// Generate a key pair from a seed.
    fn generate(seed: &Seed) -> Result<Self::KeyPair, VeilError>;
}

/// ML-KEM-768 key generator (FIPS 203, Category 3, 192-bit security).
pub struct MlKem768Generator;

impl KeyGenerator for MlKem768Generator {
    type KeyPair = MlKem768KeyPair;
    
    fn generate(seed: &Seed) -> Result<Self::KeyPair, VeilError> {
        let kem_seed = derive_hkdf::<64>(seed, domain::KEM_SEED)?;
        let kp = libcrux_backend::kem_keygen(kem_seed);
        Ok(kp)
    }
}

/// ML-DSA-65 key generator (FIPS 204, Category 3, 192-bit security).
pub struct MlDsa65Generator;

impl KeyGenerator for MlDsa65Generator {
    type KeyPair = MLDSA65KeyPair;
    
    fn generate(seed: &Seed) -> Result<Self::KeyPair, VeilError> {
        let sig_seed = derive_hkdf::<32>(seed, domain::SIG_SEED)?;
        let kp = libcrux_backend::dsa_keygen(sig_seed);
        Ok(kp)
    }
}

/// Ephemeral post-quantum key material for a single verification iteration.
///
/// Uses libcrux (hax/F* formally verified) for ML-KEM-768 and ML-DSA-65.
/// Keys self-zeroize on drop via libcrux's internal mechanisms.
pub struct EphemeralKeys {
    /// ML-KEM-768 key pair (libcrux, formally verified).
    pub kem_kp: MlKem768KeyPair,
    /// ML-DSA-65 key pair (libcrux, formally verified).
    pub dsa_kp: MLDSA65KeyPair,
}

// ── Key Isolation (Future Enhancement) ──────────────────────────────────────
//
// Key isolation via Locked<> wrappers would provide additional isolation by
// placing keys in separate memory-locked regions. However, this requires
// significant changes to the Locked<> struct to support complex types
// (currently only supports byte arrays).
//
// Future enhancement: Extend Locked<> to support generic types with
// ZeroizeOnDrop, then wrap EphemeralKeys fields in Locked<>.
//
// This follows the "defence-in-depth" philosophy by providing additional
// isolation beyond the self-zeroizing behavior already present in libcrux types.

// ── Key Compromise Detection (LOW Priority - Philosophy Conflict) ────────────
//
// Key compromise detection would involve periodically testing keys by signing
// and verifying a test message. However, this conflicts with the "stateless"
// philosophy in several ways:
//
// 1. **State requirement**: Detecting compromise requires maintaining state
//    about previous key usage, which violates the stateless philosophy.
//
// 2. **Metadata leakage**: Tracking key usage creates metadata, which violates
//    the "no metadata" philosophy.
//
// 3. **Performance overhead**: Periodic testing adds computational overhead,
//    which conflicts with the performance goals.
//
// 4. **Limited benefit**: In a stateless system, keys are ephemeral and
//    short-lived. The window for compromise is very small, making detection
//    less valuable.
//
// **Recommendation**: Skip key compromise detection. The stateless design
// already provides strong security guarantees:
// - Keys are ephemeral (exist only for one verification iteration)
// - Keys are self-zeroizing (wiped on drop)
// - Keys are derived from high-entropy sources (12 independent sources)
// - Keys are validated before use (validate_keys, validate_key_strength)
//
// The risk of key compromise is already very low due to the stateless design,
// and the cost of detection (state, metadata, performance) outweighs the benefit.

impl Drop for EphemeralKeys {
    #[inline(never)]
    fn drop(&mut self) {
        // Wipe all key material in place via unsafe mutable access.
        // The libcrux types don't expose mutable access to private key bytes,
        // so we use the l0_memlock::zeroize_ptr helper to zero them directly.
        // This ensures the original bytes are wiped, not just a stack copy.

        // ML-KEM-768: private key is 2400 bytes.
        // Wipe via l0_memlock::zeroize_slice which obtains a mutable pointer
        // from the immutable reference. The unsafe pointer cast is encapsulated
        // in l0_memlock (the only module permitted to use unsafe).
        crate::l0_memlock::zeroize_slice(self.kem_kp.private_key().as_slice());

        // ML-DSA-65: signing key is 4032 bytes (mutable access available).
        let dsa_sk = &mut self.dsa_kp.signing_key;
        zeroize_bytes(dsa_sk.as_mut_slice());
    }
}

/// Derive `N` bytes from the master seed under a domain tag via SHAKE256.
///
/// NOTE: SHAKE256 is now backed by libcrux-sha3 (formally verified, constant-time).
/// lookup-table access patterns can leak the absorbed `seed` bytes on
/// shared-cache hardware (co-resident VM / same-core L3). For this `derive()`
/// call the absorbed material is the **locked master seed** — the highest-value
/// secret in the engine. See `SPEC-HARDENING.md` §"Cache timing and T-table
/// side channels". Risk class for this call: **HIGH** (PQ KDF input).
fn derive<const N: usize>(seed: &Seed, tag: &[u8]) -> [u8; N] {
    let mut xof = Shake256::default();
    xof.update(tag);
    xof.update(seed.as_bytes());
    let mut out = [0u8; N];
    let mut reader = xof.finalize_xof();
    reader.read(&mut out);
    out
}

/// Derive `N` bytes from the master seed using HKDF-SHA256 (NIST SP 800-56C).
///
/// This is a stronger KDF than plain SHAKE256, recommended by NIST for
/// key derivation. HKDF provides better security margins and is the
/// standard approach for key derivation.
///
/// Note: Uses SHA-256 instead of SHAKE256 because HKDF requires a fixed-output
/// hash function, not an XOF (extendable output function).
///
/// Reference: NIST SP 800-56C "Recommendation for Key-Derivation Methods"
fn derive_hkdf<const N: usize>(seed: &Seed, tag: &[u8]) -> Result<[u8; N], VeilError> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    
    let hk = Hkdf::<Sha256>::new(Some(tag), seed.as_bytes());
    let mut out = [0u8; N];
    hk.expand(b"veil7:kdf:v1", &mut out)
        .map_err(|_| VeilError::Crypto)?;
    Ok(out)
}

/// Derive both ephemeral PQ keypairs from a freshly harvested seed.
///
/// Uses libcrux (formally verified via hax/F*) instead of RustCrypto.
pub fn derive_keys(seed: &Seed) -> Result<EphemeralKeys, VeilError> {
    // --- ML-KEM-768: needs a 64-byte seed (FIPS 203) ---
    let mut kem_seed_bytes = derive::<64>(seed, domain::KEM_SEED);
    let kem_kp = libcrux_backend::kem_keygen(kem_seed_bytes);
    zeroize_bytes(&mut kem_seed_bytes);

    // --- ML-DSA-65: needs a 32-byte seed (FIPS 204) ---
    let mut sig_seed_bytes = derive::<32>(seed, domain::SIG_SEED);
    let dsa_kp = libcrux_backend::dsa_keygen(sig_seed_bytes);
    zeroize_bytes(&mut sig_seed_bytes);

    let keys = EphemeralKeys { kem_kp, dsa_kp };
    
    // Validate keys before returning
    validate_keys(&keys)?;
    validate_key_strength(&keys)?;
    
    Ok(keys)
}

/// Derive keys from multiple independent seeds (defence-in-depth).
///
/// Combines multiple seeds using XOR to provide redundancy. If one seed
/// is compromised, the others still provide security. This follows the
/// "defence-in-depth" philosophy.
///
/// Note: This is an optional enhancement. The standard derive_keys() uses
/// a single seed from L1, which is already high-entropy (from 12 sources).
/// Multi-source derivation provides additional redundancy for high-security
/// deployments.
pub fn derive_keys_multi_source(seeds: &[Seed]) -> Result<EphemeralKeys, VeilError> {
    if seeds.is_empty() {
        return Err(VeilError::Crypto);
    }
    
    // Combine multiple seeds using XOR
    let mut combined_seed = [0u8; 64];
    for seed in seeds {
        for (i, byte) in seed.as_bytes().iter().enumerate() {
            combined_seed[i] ^= byte;
        }
    }
    
    let combined = Seed::from_bytes(&combined_seed);
    zeroize_bytes(&mut combined_seed);
    
    derive_keys(&combined)
}

/// Validate that generated keys are valid before use.
///
/// This prevents silent failures and follows the "refuse > guess" philosophy.
/// Returns Ok(()) if keys are valid, Err(InvalidKey) otherwise.
pub fn validate_keys(keys: &EphemeralKeys) -> Result<(), VeilError> {
    // Validate ML-KEM-768 public key
    let pk_bytes = libcrux_backend::kem_pk_bytes(&keys.kem_kp);
    if !libcrux_backend::validate_kem_pk(pk_bytes) {
        return Err(VeilError::Crypto);
    }
    
    // Validate ML-DSA-65 verification key
    let vk_bytes = libcrux_backend::dsa_vk_bytes(&keys.dsa_kp);
    if !libcrux_backend::validate_dsa_vk(vk_bytes) {
        return Err(VeilError::Crypto);
    }
    
    Ok(())
}

/// Validate that key strength meets FIPS requirements.
///
/// This verifies that keys have the correct size for their security level.
/// ML-KEM-768 and ML-DSA-65 both provide 192-bit security (Category 3).
/// Returns Ok(()) if key strength is valid, Err(Crypto) otherwise.
pub fn validate_key_strength(keys: &EphemeralKeys) -> Result<(), VeilError> {
    // ML-KEM-768 should have 1184-byte public key
    let pk_bytes = libcrux_backend::kem_pk_bytes(&keys.kem_kp);
    if pk_bytes.len() != 1184 {
        return Err(VeilError::Crypto);
    }
    
    // ML-DSA-65 should have 1952-byte verification key
    let vk_bytes = libcrux_backend::dsa_vk_bytes(&keys.dsa_kp);
    if vk_bytes.len() != 1952 {
        return Err(VeilError::Crypto);
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l1_entropy::harvest;

    #[test]
    fn derives_keys_from_seed() {
        let seed = harvest(b"l2").unwrap();
        let keys = derive_keys(&seed).expect("keygen ok");
        // Verify keys are real by accessing their bytes.
        let _vk_bytes = libcrux_backend::dsa_vk_bytes(&keys.dsa_kp);
        let _pk_bytes = libcrux_backend::kem_pk_bytes(&keys.kem_kp);
    }

    #[test]
    fn keygen_is_deterministic_per_seed() {
        let seed1 = harvest(b"det").unwrap();
        let raw = *seed1.as_bytes();
        let seed2 = Seed::from_bytes(&raw);

        let k1 = derive_keys(&seed1).unwrap();
        let k2 = derive_keys(&seed2).unwrap();

        assert_eq!(
            libcrux_backend::dsa_vk_bytes(&k1.dsa_kp),
            libcrux_backend::dsa_vk_bytes(&k2.dsa_kp),
            "deterministic sig keygen"
        );
        assert_eq!(
            libcrux_backend::kem_pk_bytes(&k1.kem_kp),
            libcrux_backend::kem_pk_bytes(&k2.kem_kp),
            "deterministic kem keygen"
        );
    }

    #[test]
    fn different_seeds_produce_different_keys() {
        let seed_a = harvest(b"a").unwrap();
        let seed_b = harvest(b"b").unwrap();
        let k_a = derive_keys(&seed_a).unwrap();
        let k_b = derive_keys(&seed_b).unwrap();
        assert_ne!(
            libcrux_backend::dsa_vk_bytes(&k_a.dsa_kp),
            libcrux_backend::dsa_vk_bytes(&k_b.dsa_kp),
            "different seeds must produce different verifying keys"
        );
        assert_ne!(
            libcrux_backend::kem_pk_bytes(&k_a.kem_kp),
            libcrux_backend::kem_pk_bytes(&k_b.kem_kp),
            "different seeds must produce different encapsulation keys"
        );
    }

    #[test]
    fn kem_and_sig_subseeds_are_domain_separated() {
        let seed = harvest(b"domain").unwrap();
        let keys = derive_keys(&seed).unwrap();
        let kem_bytes = libcrux_backend::kem_pk_bytes(&keys.kem_kp);
        let sig_vk_bytes = libcrux_backend::dsa_vk_bytes(&keys.dsa_kp);
        // ML-KEM-768 pk is 1184 bytes; ML-DSA-65 vk is 1952 bytes.
        assert_eq!(kem_bytes.len(), 1184, "KEM-768 pk length");
        assert_eq!(sig_vk_bytes.len(), 1952, "ML-DSA-65 vk length");
        assert_ne!(
            &kem_bytes[..16],
            &sig_vk_bytes[..16],
            "KEM and SIG sub-seed prefixes must be uncorrelated"
        );
    }

    #[test]
    fn derive_keys_does_not_leak_master_seed_via_subseeds() {
        let seed = harvest(b"leak").unwrap();
        let keys = derive_keys(&seed).unwrap();
        let kem = libcrux_backend::kem_pk_bytes(&keys.kem_kp);
        let sig_vk = libcrux_backend::dsa_vk_bytes(&keys.dsa_kp);
        let master = seed.as_bytes();
        for window in 0..(kem.len() - master.len()) {
            assert_ne!(
                &kem[window..window + master.len()],
                master,
                "KEM pk at window {window} equals master seed (KDF leak)"
            );
        }
        for window in 0..(sig_vk.len() - master.len()) {
            assert_ne!(
                &sig_vk[window..window + master.len()],
                master,
                "ML-DSA vk at window {window} equals master seed (KDF leak)"
            );
        }
    }

    #[test]
    fn derive_keys_validates_keys() {
        let seed = harvest(b"validate").unwrap();
        let keys = derive_keys(&seed).unwrap();
        // If we get here, validation passed
        let _vk_bytes = libcrux_backend::dsa_vk_bytes(&keys.dsa_kp);
        let _pk_bytes = libcrux_backend::kem_pk_bytes(&keys.kem_kp);
    }

    #[test]
    fn derive_keys_validates_key_strength() {
        let seed = harvest(b"strength").unwrap();
        let keys = derive_keys(&seed).unwrap();
        // If we get here, key strength validation passed
        let pk_bytes = libcrux_backend::kem_pk_bytes(&keys.kem_kp);
        let vk_bytes = libcrux_backend::dsa_vk_bytes(&keys.dsa_kp);
        assert_eq!(pk_bytes.len(), 1184, "ML-KEM-768 pk must be 1184 bytes");
        assert_eq!(vk_bytes.len(), 1952, "ML-DSA-65 vk must be 1952 bytes");
    }

    #[test]
    fn derive_keys_multi_source_single_seed() {
        let seed = harvest(b"multi").unwrap();
        let keys = derive_keys_multi_source(&[seed]).unwrap();
        // Should work with a single seed
        let _vk_bytes = libcrux_backend::dsa_vk_bytes(&keys.dsa_kp);
        let _pk_bytes = libcrux_backend::kem_pk_bytes(&keys.kem_kp);
    }

    #[test]
    fn derive_keys_multi_source_two_seeds() {
        let seed1 = harvest(b"multi1").unwrap();
        let seed2 = harvest(b"multi2").unwrap();
        let keys = derive_keys_multi_source(&[seed1, seed2]).unwrap();
        // Should work with two seeds
        let _vk_bytes = libcrux_backend::dsa_vk_bytes(&keys.dsa_kp);
        let _pk_bytes = libcrux_backend::kem_pk_bytes(&keys.kem_kp);
    }

    #[test]
    fn derive_keys_multi_source_empty_fails() {
        let result = derive_keys_multi_source(&[]);
        assert!(result.is_err(), "empty seeds should fail");
    }

    #[test]
    fn derive_hkdf_works() {
        let seed = harvest(b"hkdf").unwrap();
        let result = derive_hkdf::<64>(&seed, b"test");
        assert!(result.is_ok(), "HKDF should succeed");
        let output = result.unwrap();
        assert_eq!(output.len(), 64, "HKDF output should be 64 bytes");
        // Output should not be all zeros
        assert!(!output.iter().all(|&b| b == 0), "HKDF output should not be all zeros");
    }

    #[test]
    fn crypto_agility_key_generator_trait() {
        let seed = harvest(b"agility").unwrap();
        
        // Test ML-KEM-768 generator
        let kem_kp = MlKem768Generator::generate(&seed).unwrap();
        let _pk_bytes = libcrux_backend::kem_pk_bytes(&kem_kp);
        
        // Test ML-DSA-65 generator
        let dsa_kp = MlDsa65Generator::generate(&seed).unwrap();
        let _vk_bytes = libcrux_backend::dsa_vk_bytes(&dsa_kp);
    }
}
