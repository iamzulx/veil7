//! L3 — Commitment.
//!
//! Binds the claim to the ephemeral identity. Produces a domain-separated
//! SHAKE256 commitment over:
//!     tag || kem_ek_bytes || sig_vk_bytes || claim
//!
//! This commitment is what gets signed in L4 and re-derived by the verifier in
//! L5. Because it includes both public keys, a signature over it is bound to
//! this exact ephemeral identity — it cannot be replayed against another key.
//!
//! No secret material enters the commitment; it is safe to expose as the
//! transcript hash in L7.

use crate::domain;
use crate::l2_keygen::EphemeralKeys;

use ml_dsa::{KeyExport as _, Keypair as _};

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
pub fn commit(keys: &EphemeralKeys, claim: &[u8]) -> Commitment {
    let kem_ek_bytes = keys.kem_ek.to_bytes();
    let sig_vk = keys.sig_sk.verifying_key();
    let sig_vk_bytes = sig_vk.encode();

    let mut xof = Shake256::default();
    xof.update(domain::COMMITMENT);
    xof.update(kem_ek_bytes.as_slice());
    xof.update(sig_vk_bytes.as_slice());
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
}
