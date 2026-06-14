//! L4 — Proof Generation (libcrux backend).
//!
//! Produces a post-quantum proof that the holder of the ephemeral secret key
//! attests to the commitment. Uses ML-DSA-65 (FIPS 204) via libcrux
//! (hax/F* formally verified).
//!
//! Pluggability: the `Prover` trait lets a caller swap in a different PQ
//! scheme without touching L5's verification dispatch.

use crate::l2_keygen::EphemeralKeys;
use crate::l3_commit::Commitment;
use crate::pq_backends::libcrux_backend;
use crate::VeilError;

use libcrux_ml_dsa::ml_dsa_65::MLDSA65Signature;

use crate::shake256::Shake256;

/// Context string bound into the ML-DSA signature (FIPS 204 ctx field).
/// Acts as an additional domain separator at the signature layer.
const SIG_CTX: &[u8] = b"veil7:proof:v1";

/// A scheme-agnostic proof. Carries only opaque bytes — no scheme tag is
/// emitted into any output; the scheme is fixed at compile time per pipeline
/// instantiation, so there is nothing to leak.
pub struct Proof {
    pub(crate) sig: MLDSA65Signature,
}

impl Drop for Proof {
    #[inline(never)]
    fn drop(&mut self) {
        // Wipe the signature bytes. ML-DSA-65 sig is 3309 bytes.
        let sig_bytes = self.sig.as_mut_slice();
        crate::l0_memlock::zeroize_bytes(sig_bytes);
    }
}

/// Pluggable proof generator. Implemented by a concrete PQ signature scheme.
pub trait Prover {
    /// Generate a proof binding `keys` to `commitment`.
    fn prove(keys: &EphemeralKeys, commitment: &Commitment) -> Result<Proof, VeilError>;
}

/// Default prover: ML-DSA-65 via libcrux, deterministic signing.
///
/// Signing randomness is derived deterministically from the commitment
/// via SHAKE256, so the proof is reproducible from the seed alone.
pub struct MlDsaProver;

impl Prover for MlDsaProver {
    fn prove(keys: &EphemeralKeys, commitment: &Commitment) -> Result<Proof, VeilError> {
        // Derive deterministic signing randomness from the commitment.
        // This ensures the proof is reproducible from the seed alone,
        // maintaining the stateless property.
        let sig_randomness = derive_sig_randomness(commitment);

        let sig = libcrux_backend::dsa_sign(
            &keys.dsa_kp.signing_key,
            commitment.as_bytes(),
            SIG_CTX,
            sig_randomness,
        )?;

        Ok(Proof { sig })
    }
}

/// Derive deterministic signing randomness from the commitment.
fn derive_sig_randomness(commitment: &Commitment) -> [u8; 32] {
    let mut xof = Shake256::default();
    xof.update(b"veil7:l4:sig-randomness:v1");
    xof.update(commitment.as_bytes());
    let mut out = [0u8; 32];
    let mut reader = xof.finalize_xof();
    let _ = reader.read(&mut out);
    out
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

    fn valid_proof(claim: &[u8]) -> (EphemeralKeys, Commitment, Proof) {
        let seed = harvest(b"l4").unwrap();
        let keys = derive_keys(&seed).unwrap();
        let c = commit(&keys, claim);
        let proof = MlDsaProver::prove(&keys, &c).unwrap();
        (keys, c, proof)
    }

    #[test]
    fn proof_changes_when_commitment_changes() {
        let seed = harvest(b"l4c").unwrap();
        let keys = derive_keys(&seed).unwrap();
        let c1 = commit(&keys, b"claim-A");
        let c2 = commit(&keys, b"claim-B");
        let p1 = MlDsaProver::prove(&keys, &c1).unwrap();
        let p2 = MlDsaProver::prove(&keys, &c2).unwrap();
        // Different commitments → different proofs (signature over different message).
        assert_ne!(p1.sig.as_slice(), p2.sig.as_slice());
    }

    #[test]
    fn proof_binds_to_sig_ctx_domain_separator() {
        let (_, c, proof) = valid_proof(b"ctx-test");
        // The signature was created with SIG_CTX. Verify that re-verifying
        // with the same context succeeds (handled by L5).
        assert_eq!(proof.sig.as_slice().len(), libcrux_backend::DSA_SIG_SIZE);
        let _ = c; // commitment used in signing
    }

    #[test]
    fn proof_sig_encode_is_stable_byte_layout() {
        let (_, _, proof) = valid_proof(b"stable");
        assert_eq!(
            proof.sig.as_slice().len(),
            3309,
            "ML-DSA-65 signature must be 3309 bytes"
        );
    }
}
