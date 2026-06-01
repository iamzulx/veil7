//! Pipeline — stateless orchestration of L1 → L7.
//!
//! One call to [`verify_once`] runs a complete, self-contained iteration:
//!
//!   L1 harvest entropy ─► L2 ephemeral PQ keygen ─► L3 commit(claim)
//!        ─► L4 prove ─► L5 universal verify ─► (capture verdict)
//!        ─► L6 scrub (auto-zeroise all key material) ─► L7 emit verdict
//!
//! Nothing persists between calls. Every iteration regenerates its entire
//! cryptographic context from freshly harvested entropy and destroys it before
//! returning. The function is generic over the `Prover`/`Verifier` pair so the
//! PQ scheme is pluggable ("universal verification").
//!
//! Ordering note: the verdict is built from the commitment (public) and the
//! validity Choice (computed in L5) BEFORE L6 scrubs the keys, then the keys
//! are wiped, and only then is the verdict returned. Secrets never coexist with
//! the returned value.

use crate::l1_entropy::harvest;
use crate::l2_keygen::derive_keys;
use crate::l3_commit::commit;
use crate::l4_prove::{MlDsaProver, Prover};
use crate::l5_verify::{MlDsaVerifier, Verifier};
use crate::l6_zeroise::scrub;
use crate::l7_emit::Verdict;
use crate::VeilError;

/// A claim to be verified. Borrowed bytes — the pipeline never copies the claim
/// into any persistent or emitted structure.
pub struct Claim<'a> {
    pub bytes: &'a [u8],
    /// Optional context binding for entropy personalization. `&[]` if unused.
    pub personalization: &'a [u8],
}

impl<'a> Claim<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Claim {
            bytes,
            personalization: &[],
        }
    }
}

/// Run one full stateless verification iteration with the default PQ scheme
/// (ML-DSA-65 + ML-KEM-768).
pub fn verify_once(claim: &Claim<'_>) -> Result<Verdict, VeilError> {
    verify_once_with::<MlDsaProver, MlDsaVerifier>(claim)
}

/// Run one full stateless iteration with a caller-chosen `Prover`/`Verifier`
/// pair. This is the universal hook: swap the PQ scheme without touching the
/// orchestration.
pub fn verify_once_with<P, V>(claim: &Claim<'_>) -> Result<Verdict, VeilError>
where
    P: Prover,
    V: Verifier,
{
    // L1 — harvest fresh entropy. Seed self-wipes on drop at end of scope.
    let seed = harvest(claim.personalization)?;

    // L2 — derive ephemeral PQ keypairs. Secret keys are ZeroizeOnDrop.
    let keys = derive_keys(&seed)?;
    // Seed no longer needed once keys are derived — drop (and wipe) it now.
    drop(seed);

    // L3 — commit to the claim under the ephemeral identity.
    let commitment = commit(&keys, claim.bytes);

    // L4 — generate the PQ proof.
    let proof = P::prove(&keys, &commitment)?;

    // L5 — universal verification (constant-time Choice).
    let valid = V::verify(&keys, claim.bytes, &proof)?;

    // Build the verdict from public material BEFORE wiping secrets.
    let verdict = Verdict::new(valid, &commitment);

    // L6 — explicit auto-zeroise barrier: consume and wipe all key material.
    scrub(keys);
    // `proof` and `commitment` carry no secret. `proof` owns heap buffers, so an
    // explicit drop is a meaningful early release; `commitment` is a plain
    // `Copy`/non-`Drop` byte array, so dropping it is a no-op and is left to scope end.
    drop(proof);

    // L7 — emit the traceless verdict. Only public, metadata-free data leaves.
    Ok(verdict)
}

// ─────────────────────────────────────────────────────────────────────────────
// Generic relation pipeline (Fiat-Shamir, "universal verification")
// ─────────────────────────────────────────────────────────────────────────────

use crate::common::Transcript;
use crate::relations::Relation;

/// Run one stateless prove→verify iteration for an arbitrary [`Relation`].
///
/// This is the universal entry point: the witness defines the statement, the
/// relation produces a non-interactive proof over a Fiat-Shamir transcript, the
/// same machinery verifies it, the witness is scrubbed, and a traceless
/// [`Verdict`] is emitted — identical output contract to [`verify_once`].
///
/// `entropy_personalization` feeds L1 so the prover's commitment randomness is
/// freshly harvested and memory-locked each call.
pub fn prove_and_verify<R: Relation>(
    witness: &R::Witness,
    entropy_personalization: &[u8],
) -> Result<Verdict, VeilError> {
    // L1 — harvest fresh, memory-locked entropy for the prover's coins.
    let seed = harvest(entropy_personalization)?;

    // Prove: witness + entropy -> (statement, proof) via Fiat-Shamir.
    let (stmt, proof) = R::prove(witness, seed.as_bytes())?;
    drop(seed); // entropy no longer needed; wipe + munlock now.

    // Verify with the same relation (constant-time Choice).
    let valid = R::verify(&stmt, &proof)?;

    // Public statement digest for verdict correlation (no secret material).
    let mut t = Transcript::new(R::protocol_label());
    R::bind_statement(&stmt, &mut t);
    let digest: [u8; 32] = t.challenge_array(b"verdict:statement-digest");

    // Build verdict from public material; witness is dropped (and zeroised) as
    // it falls out of the caller's scope. Proof/statement carry no secret.
    let verdict = Verdict::from_statement_digest(valid, &digest);
    drop(proof);
    drop(stmt);

    Ok(verdict)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn end_to_end_valid_claim() {
        let claim = Claim::new(b"the sky is blue");
        let verdict = verify_once(&claim).expect("pipeline ok");
        assert!(verdict.is_valid_bool(), "honest claim must verify");
        assert_eq!(verdict.transcript().len(), 32);
    }

    #[test]
    fn statelessness_two_runs_independent_transcripts() {
        // Same claim, two runs -> different ephemeral identities -> different
        // transcripts (because keys differ), proving no shared state.
        let claim = Claim::new(b"same claim");
        let v1 = verify_once(&claim).unwrap();
        let v2 = verify_once(&claim).unwrap();
        assert!(v1.is_valid_bool() && v2.is_valid_bool());
        assert_ne!(
            v1.transcript(),
            v2.transcript(),
            "each iteration is a fresh, independent identity"
        );
    }

    #[test]
    fn many_iterations_all_valid() {
        // Stress the zeroise-per-iteration path.
        for i in 0..16u8 {
            let data = [i; 8];
            let claim = Claim::new(&data);
            let v = verify_once(&claim).unwrap();
            assert!(v.is_valid_bool());
        }
    }

    #[test]
    fn generic_relation_hash_preimage_verifies() {
        use crate::relations::hash_preimage::{HashPreimage, Witness};
        let w = Witness { seed: [0x9Au8; 32] };
        let verdict = prove_and_verify::<HashPreimage>(&w, b"demo").expect("relation ok");
        assert!(
            verdict.is_valid_bool(),
            "honest hash-preimage proof must verify through the generic pipeline"
        );
        assert_eq!(verdict.transcript().len(), 32);
    }

    #[test]
    fn generic_relation_statement_digest_is_stable() {
        // Same witness -> same statement -> same verdict transcript digest,
        // regardless of entropy (the relation here is deterministic).
        use crate::relations::hash_preimage::{HashPreimage, Witness};
        let v1 = prove_and_verify::<HashPreimage>(&Witness { seed: [7u8; 32] }, b"a").unwrap();
        let v2 = prove_and_verify::<HashPreimage>(&Witness { seed: [7u8; 32] }, b"b").unwrap();
        assert_eq!(
            v1.transcript(),
            v2.transcript(),
            "statement digest binds to the statement, not to entropy"
        );
    }
}
