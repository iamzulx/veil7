//! L4 — Proof Generation.
//!
//! Produces a post-quantum proof that the holder of the ephemeral secret key
//! attests to the commitment. The default prover is ML-DSA-65 (FIPS 204), using
//! *deterministic* signing so the whole pipeline is reproducible from entropy
//! alone (no extra RNG draw, no hidden state).
//!
//! Pluggability: the `Prover` trait lets a caller swap in a different PQ scheme
//! (e.g. SLH-DSA, FN-DSA) without touching L5's verification dispatch, as long
//! as the matching `Verifier` is provided. This is the "universal" hook.

use crate::l2_keygen::EphemeralKeys;
use crate::l3_commit::Commitment;
use crate::VeilError;

use ml_dsa::{MlDsa65, Signature};

/// Context string bound into the ML-DSA signature (FIPS 204 ctx field).
/// Acts as an additional domain separator at the signature layer.
const SIG_CTX: &[u8] = b"veil7:proof:v1";

/// A scheme-agnostic proof. Carries only opaque bytes — no scheme tag is
/// emitted into any output; the scheme is fixed at compile time per pipeline
/// instantiation, so there is nothing to leak.
pub struct Proof {
    pub(crate) sig: Signature<MlDsa65>,
}

/// Pluggable proof generator. Implemented by a concrete PQ signature scheme.
pub trait Prover {
    /// Generate a proof binding `keys` to `commitment`.
    fn prove(keys: &EphemeralKeys, commitment: &Commitment) -> Result<Proof, VeilError>;
}

/// Default prover: ML-DSA-65, deterministic.
pub struct MlDsaProver;

impl Prover for MlDsaProver {
    fn prove(keys: &EphemeralKeys, commitment: &Commitment) -> Result<Proof, VeilError> {
        let sig = keys
            .sig_sk
            .expanded_key()
            .sign_deterministic(commitment.as_bytes(), SIG_CTX)
            .map_err(|_| VeilError::Crypto)?;
        Ok(Proof { sig })
    }
}

/// Re-export so L5 can bind to the same context constant.
pub(crate) const fn sig_ctx() -> &'static [u8] {
    SIG_CTX
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l1_entropy::harvest;
    use crate::l2_keygen::derive_keys;
    use crate::l3_commit::commit;

    #[test]
    fn proof_generates() {
        let seed = harvest(b"l4").unwrap();
        let keys = derive_keys(&seed).unwrap();
        let c = commit(&keys, b"claim");
        let _proof = MlDsaProver::prove(&keys, &c).expect("prove ok");
    }

    #[test]
    fn proof_is_deterministic() {
        let seed = harvest(b"l4det").unwrap();
        let keys = derive_keys(&seed).unwrap();
        let c = commit(&keys, b"claim");
        let p1 = MlDsaProver::prove(&keys, &c).unwrap();
        let p2 = MlDsaProver::prove(&keys, &c).unwrap();
        assert_eq!(p1.sig.encode(), p2.sig.encode(), "deterministic signing");
    }
}
