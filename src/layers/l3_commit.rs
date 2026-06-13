//! L3 — Commitment (libcrux backend).
//!
//! Binds the claim to the ephemeral identity. Produces a domain-separated
//! SHAKE256 commitment over:
//!     tag || kem_pk_bytes || dsa_vk_bytes || claim
//!
//! This commitment is what gets signed in L4 and re-derived by the verifier in
//! L5. Because it includes both public keys, a signature over it is bound to
//! this exact ephemeral identity — it cannot be replayed against another key.
//!
//! No secret material enters the commitment; it is safe to expose as the
//! transcript hash in L7.

use crate::domain;
use crate::l2_keygen::EphemeralKeys;
use crate::pq_backends::libcrux_backend;

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

/// Length of the commitment digest in bytes (256-bit).
pub const COMMITMENT_LEN: usize = 32;

/// A public, metadata-free commitment to (ephemeral identity + claim).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Commitment(pub [u8; COMMITMENT_LEN]);

impl Commitment {
    #[inline]
    pub fn as_bytes(&self) -> &[u8; COMMITMENT_LEN] {
        &self.0
    }
}

/// Compute the commitment for a claim under the given ephemeral keys.
///
/// SIDE-CHANNEL: `sha3::Shake256` is a T-table Keccak. The absorbed `claim`
/// is a **secret** for the engine (only the commitment leaks). On shared-cache
/// hardware an attacker can recover `claim` bytes from the T-table access
/// pattern. See `SPEC-HARDENING.md` §"Cache timing and T-table side channels".
/// Risk class for this call: **MEDIUM** (private claim bytes).
pub fn commit(keys: &EphemeralKeys, claim: &[u8]) -> Commitment {
    let kem_pk_bytes = libcrux_backend::kem_pk_bytes(&keys.kem_kp);
    let dsa_vk_bytes = libcrux_backend::dsa_vk_bytes(&keys.dsa_kp);

    let mut xof = Shake256::default();
    xof.update(domain::COMMITMENT);
    xof.update(kem_pk_bytes.as_slice());
    xof.update(dsa_vk_bytes.as_slice());
    xof.update(claim);

    let mut out = [0u8; COMMITMENT_LEN];
    let mut reader = xof.finalize_xof();
    reader.read(&mut out);
    Commitment(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l1_entropy::harvest;
    use crate::l2_keygen::derive_keys;

    #[test]
    fn commitment_is_stable_for_same_inputs() {
        let seed = harvest(b"l3").unwrap();
        let keys = derive_keys(&seed).unwrap();
        let c1 = commit(&keys, b"claim-A");
        let c2 = commit(&keys, b"claim-A");
        assert_eq!(c1, c2);
    }

    #[test]
    fn commitment_changes_with_claim() {
        let seed = harvest(b"l3b").unwrap();
        let keys = derive_keys(&seed).unwrap();
        let c1 = commit(&keys, b"claim-A");
        let c2 = commit(&keys, b"claim-B");
        assert_ne!(c1, c2);
    }

    #[test]
    fn commitment_changes_when_kem_pk_changes() {
        let seed_a = harvest(b"k1").unwrap();
        let seed_b = harvest(b"k2").unwrap();
        let keys_a = derive_keys(&seed_a).unwrap();
        let keys_b = derive_keys(&seed_b).unwrap();
        let c_a = commit(&keys_a, b"claim");
        let c_b = commit(&keys_b, b"claim");
        assert_ne!(c_a, c_b, "commitment must bind to the KEM public key");
    }

    #[test]
    fn commitment_changes_when_dsa_vk_changes() {
        let seed_a = harvest(b"s1").unwrap();
        let seed_b = harvest(b"s2").unwrap();
        let keys_a = derive_keys(&seed_a).unwrap();
        let keys_b = derive_keys(&seed_b).unwrap();
        let c_a = commit(&keys_a, b"claim");
        let c_b = commit(&keys_b, b"claim");
        assert_ne!(c_a, c_b, "commitment must bind to the ML-DSA verifying key");
    }

    #[test]
    fn commitment_binds_all_three_fields() {
        let seed = harvest(b"binding").unwrap();
        let keys = derive_keys(&seed).unwrap();
        let c1 = commit(&keys, b"X");
        let c2 = commit(&keys, b"Y");
        let seed2 = harvest(b"binding-other").unwrap();
        let keys2 = derive_keys(&seed2).unwrap();
        let c3 = commit(&keys2, b"X");
        assert_ne!(c1, c2, "claim-only change should change commitment");
        assert_ne!(c1, c3, "key-only change should change commitment");
        assert_ne!(c2, c3, "key+claim change should change commitment");
    }
}
