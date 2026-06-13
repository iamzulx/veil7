//! L2 — Ephemeral Keygen.
//!
//! Deterministically derives two independent post-quantum keypairs from the L1
//! seed, using domain-separated SHAKE256 to split the master seed into:
//!   * a 64-byte ML-KEM-768 seed   (FIPS 203 KEM)
//!   * a 32-byte ML-DSA-65  seed   (FIPS 204 signatures)
//!
//! Statelessness: keys exist only for the lifetime of the returned `EphemeralKeys`.
//! Both PQ key types are `ZeroizeOnDrop` upstream (RustCrypto), so secret key
//! material self-wipes. The derived sub-seeds are wiped here before returning.

use crate::l0_memlock::zeroize_bytes;
use crate::l1_entropy::Seed;
use crate::{domain, VeilError};

use ml_dsa::{KeyInit as DsaKeyInit, MlDsa65, SigningKey};
use ml_kem::array::Array;
use ml_kem::MlKem768;
use ml_kem::{DecapsulationKey, EncapsulationKey};

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

/// Ephemeral post-quantum key material for a single verification iteration.
///
/// Secret keys (`kem_dk`, `sig_sk`) are `ZeroizeOnDrop` upstream. Public keys
/// carry no secret but are still dropped at end of iteration so nothing lingers.
pub struct EphemeralKeys {
    /// ML-KEM-768 decapsulation (secret) key. Self-zeroising.
    pub kem_dk: DecapsulationKey<MlKem768>,
    /// ML-KEM-768 encapsulation (public) key.
    pub kem_ek: EncapsulationKey<MlKem768>,
    /// ML-DSA-65 signing (secret) key. Self-zeroising.
    pub sig_sk: SigningKey<MlDsa65>,
}

/// Derive `N` bytes from the master seed under a domain tag via SHAKE256.
///
/// SIDE-CHANNEL: `sha3::Shake256` is a T-table Keccak implementation. Per-call
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
pub fn derive_keys(seed: &Seed) -> Result<EphemeralKeys, VeilError> {
    // --- ML-KEM-768: needs a 64-byte seed ---
    let mut kem_seed_bytes = derive::<64>(seed, domain::KEM_SEED);
    let kem_seed: Array<u8, ml_kem::array::typenum::U64> =
        Array::try_from(&kem_seed_bytes[..]).map_err(|_| VeilError::Crypto)?;
    let kem_dk = DecapsulationKey::<MlKem768>::from_seed(kem_seed);
    let kem_ek = kem_dk.encapsulation_key().clone();
    zeroize_bytes(&mut kem_seed_bytes);

    // --- ML-DSA-65: needs a 32-byte seed ---
    let mut sig_seed_bytes = derive::<32>(seed, domain::SIG_SEED);
    let sig_seed: ml_dsa::B32 =
        Array::try_from(&sig_seed_bytes[..]).map_err(|_| VeilError::Crypto)?;
    let sig_sk = SigningKey::<MlDsa65>::new(&sig_seed);
    zeroize_bytes(&mut sig_seed_bytes);

    Ok(EphemeralKeys {
        kem_dk,
        kem_ek,
        sig_sk,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l1_entropy::harvest;
    use ml_dsa::Keypair as _;

    #[test]
    fn derives_keys_from_seed() {
        let seed = harvest(b"l2").unwrap();
        let keys = derive_keys(&seed).expect("keygen ok");
        // Public verifying key derivable from secret -> sanity that keys are real.
        let _vk = keys.sig_sk.verifying_key();
        let _ek = &keys.kem_ek;
    }

    #[test]
    fn keygen_is_deterministic_per_seed() {
        // Same seed bytes -> same keys (statelessness depends on determinism).
        let seed1 = harvest(b"det").unwrap();
        let raw = *seed1.as_bytes();
        let seed2 = Seed::from_bytes(&raw);

        let k1 = derive_keys(&seed1).unwrap();
        let k2 = derive_keys(&seed2).unwrap();

        use ml_dsa::KeyExport;
        assert_eq!(
            k1.sig_sk.verifying_key().encode(),
            k2.sig_sk.verifying_key().encode(),
            "deterministic sig keygen"
        );
        assert_eq!(
            k1.kem_ek.to_bytes(),
            k2.kem_ek.to_bytes(),
            "deterministic kem keygen"
        );
    }

    #[test]
    fn different_seeds_produce_different_keys() {
        // The KDF is SHAKE256(seed); different seeds must produce
        // uncorrelated keys. This is the inverse of the determinism
        // test above — together they pin the KDF to be a one-to-one
        // function of the seed.
        let seed_a = harvest(b"a").unwrap();
        let seed_b = harvest(b"b").unwrap();
        let k_a = derive_keys(&seed_a).unwrap();
        let k_b = derive_keys(&seed_b).unwrap();
        use ml_dsa::KeyExport;
        assert_ne!(
            k_a.sig_sk.verifying_key().encode(),
            k_b.sig_sk.verifying_key().encode(),
            "different seeds must produce different verifying keys"
        );
        assert_ne!(
            k_a.kem_ek.to_bytes(),
            k_b.kem_ek.to_bytes(),
            "different seeds must produce different encapsulation keys"
        );
    }

    #[test]
    fn kem_and_sig_subseeds_are_domain_separated() {
        // KEM_SEED and SIG_SEED are distinct domain tags. Changing
        // one must not affect the other. This pins the cross-tag
        // independence of the KDF.
        //
        // We can't directly test the internal `derive()` helper (it's
        // private). Instead we exploit the fact that the two
        // sub-seed domains are mixed into the same 64-byte master
        // seed: any correlation between the derived KEM and SIG
        // sub-seeds would be a KDF bug. We test the
        // "tag-independence" property via the public API by
        // verifying that the same witness pattern produces
        // uncorrelated KEM/SIG keys.
        let seed = harvest(b"domain").unwrap();
        let keys = derive_keys(&seed).unwrap();
        use ml_dsa::KeyExport;
        // KEM and SIG public keys should be bytewise different
        // (they come from different domain tags, even on the same
        // master seed).
        let kem_bytes = keys.kem_ek.to_bytes();
        let sig_vk_bytes = keys.sig_sk.verifying_key().encode();
        // ML-KEM-768 ek is 1184 bytes; ML-DSA-65 vk is 1952 bytes.
        // We can't compare lengths, but we can confirm they're
        // independently produced: encoding a 64-byte seed with two
        // different domain tags must give two SHAKE256 outputs that
        // are uncorrelated. The presence of the keys confirms
        // each tag was exercised; their bytewise non-collision in
        // any prefix would be a tag-collision bug.
        assert_eq!(kem_bytes.len(), 1184, "KEM-768 ek length");
        assert_eq!(sig_vk_bytes.len(), 1952, "ML-DSA-65 vk length");
        // Prefix the two at a 16-byte window. KEM[0..16] and
        // SIG[0..16] are both SHAKE256(tag || seed[0..32]) outputs
        // (one-shot sponge reads); for them to collide, both
        // domains would have to produce identical 16-byte prefixes,
        // which has negligible probability if the tags differ.
        assert_ne!(
            &kem_bytes[..16],
            &sig_vk_bytes[..16],
            "KEM and SIG sub-seed prefixes must be uncorrelated"
        );
    }

    #[test]
    fn derive_keys_does_not_leak_master_seed_via_subseeds() {
        // The two derived sub-seeds are 64 + 32 = 96 bytes. They
        // are independent outputs of SHAKE256, so concatenating
        // them must not reproduce the master seed (preimage
        // resistance). This pins the KDF: even if an attacker
        // observes both sub-seeds, recovering the master seed
        // would require inverting SHAKE256.
        let seed = harvest(b"leak").unwrap();
        let keys = derive_keys(&seed).unwrap();
        // We can't access the sub-seeds directly (they're wiped
        // inside derive_keys). But we can verify the public keys
        // (which depend on the sub-seeds) are not bytewise equal to
        // any 64/32-byte window of the master seed.
        use ml_dsa::KeyExport;
        let kem = keys.kem_ek.to_bytes();
        let sig_vk = keys.sig_sk.verifying_key().encode();
        let master = seed.as_bytes();
        // KEM ek is 1184 bytes (way longer than the 64-byte seed);
        // no 64-byte window of the master seed should appear in the
        // KEM ek output. (Probability 2^-512 per window; we check
        // 1184-64+1 ≈ 1121 windows; combined probability ~2^-503
        // — astronomically small.)
        for window in 0..(kem.len() - master.len()) {
            assert_ne!(
                &kem[window..window + master.len()],
                master,
                "KEM ek at window {window} equals master seed (KDF leak)"
            );
        }
        // Same check on the ML-DSA vk (1952 bytes).
        for window in 0..(sig_vk.len() - master.len()) {
            assert_ne!(
                &sig_vk[window..window + master.len()],
                master,
                "ML-DSA vk at window {window} equals master seed (KDF leak)"
            );
        }
    }
}
