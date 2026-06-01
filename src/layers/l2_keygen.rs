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

use crate::l1_entropy::Seed;
use crate::{domain, VeilError};

use ml_dsa::{KeyInit as DsaKeyInit, MlDsa65, SigningKey};
use ml_kem::array::Array;
use ml_kem::MlKem768;
use ml_kem::{DecapsulationKey, EncapsulationKey};

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use zeroize::Zeroize;

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
    kem_seed_bytes.zeroize();

    // --- ML-DSA-65: needs a 32-byte seed ---
    let mut sig_seed_bytes = derive::<32>(seed, domain::SIG_SEED);
    let sig_seed: ml_dsa::B32 =
        Array::try_from(&sig_seed_bytes[..]).map_err(|_| VeilError::Crypto)?;
    let sig_sk = SigningKey::<MlDsa65>::new(&sig_seed);
    sig_seed_bytes.zeroize();

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
}
