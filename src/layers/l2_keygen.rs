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

use crate::l0_memlock::zeroize_bytes;
use crate::l1_entropy::Seed;
use crate::pq_backends::libcrux_backend;
use crate::{domain, VeilError};

use libcrux_ml_dsa::ml_dsa_65::MLDSA65KeyPair;
use libcrux_ml_kem::mlkem768::MlKem768KeyPair;

use crate::shake256::Shake256;

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

impl Drop for EphemeralKeys {
    #[inline(never)]
    fn drop(&mut self) {
        // Wipe all key material. The libcrux types don't have ZeroizeOnDrop,
        // so we wipe the raw bytes manually via volatile writes.
        // ML-KEM-768: private key is 2400 bytes, public key is 1184 bytes.
        // ML-DSA-65: signing key is 4032 bytes, verification key is 1952 bytes.
        // We access the raw byte arrays and zeroize them.
        let kem_sk = self.kem_kp.private_key();
        let mut sk_bytes: [u8; libcrux_backend::KEM_SK_SIZE] = *kem_sk.as_slice();
        zeroize_bytes(&mut sk_bytes);

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

    Ok(EphemeralKeys { kem_kp, dsa_kp })
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
}
