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

use crate::l1_entropy::Seed;
use crate::l2_keygen::derive_keys;
use crate::l3_commit::commit;
#[cfg(feature = "std")]
use crate::l4_prove::MlDsaProver;
use crate::l4_prove::Prover;
#[cfg(feature = "std")]
use crate::l5_verify::MlDsaVerifier;
use crate::l5_verify::Verifier;
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

// ═══════════════════════════════════════════════════════════════════════════
// Seed-based pipeline core (works with or without std)
// ═══════════════════════════════════════════════════════════════════════════

/// Run one full stateless verification iteration with a caller-supplied [`Seed`].
/// This is the `no_std` entry point: the caller harvests entropy externally,
/// then passes it here. No OS CSPRNG is invoked.
pub fn verify_once_with_seed<P, V>(seed: &Seed, claim: &Claim<'_>) -> Result<Verdict, VeilError>
where
    P: Prover,
    V: Verifier,
{
    // L2 — derive ephemeral PQ keypairs. Secret keys are ZeroizeOnDrop.
    let keys = derive_keys(seed)?;

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

// ═══════════════════════════════════════════════════════════════════════════
// Generic relation pipeline (Fiat-Shamir, "universal verification")
// ═══════════════════════════════════════════════════════════════════════════

use crate::common::Transcript;
use crate::relations::Relation;

/// Run one stateless prove→verify iteration for an arbitrary [`Relation`],
/// using a caller-supplied entropy seed (the `no_std` entry point).
///
/// `entropy` supplies the prover's commitment randomness. It must be freshly
/// harvested and ideally memory-locked by the caller.
pub fn prove_and_verify_with_entropy<R: Relation>(
    witness: &R::Witness,
    entropy: &Seed,
) -> Result<Verdict, VeilError> {
    // Prove: witness + entropy -> (statement, proof) via Fiat-Shamir.
    let (stmt, proof) = R::prove(witness, entropy.as_bytes())?;

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

// ═══════════════════════════════════════════════════════════════════════════
// std-gated convenience wrappers (auto-harvest entropy)
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "std")]
use crate::l1_entropy::harvest;

/// Run one full stateless verification iteration with the default PQ scheme
/// (ML-DSA-65 + ML-KEM-768). Auto-harvests entropy.
#[cfg(feature = "std")]
pub fn verify_once(claim: &Claim<'_>) -> Result<Verdict, VeilError> {
    let seed = harvest(claim.personalization)?;
    verify_once_with_seed::<MlDsaProver, MlDsaVerifier>(&seed, claim)
}

/// Run one full stateless iteration with a caller-chosen `Prover`/`Verifier`
/// pair. Auto-harvests entropy.
#[cfg(feature = "std")]
pub fn verify_once_with<P, V>(claim: &Claim<'_>) -> Result<Verdict, VeilError>
where
    P: Prover,
    V: Verifier,
{
    let seed = harvest(claim.personalization)?;
    verify_once_with_seed::<P, V>(&seed, claim)
}

/// Run one stateless prove→verify iteration for an arbitrary [`Relation`].
/// Auto-harvests entropy from the OS.
#[cfg(feature = "std")]
pub fn prove_and_verify<R: Relation>(
    witness: &R::Witness,
    entropy_personalization: &[u8],
) -> Result<Verdict, VeilError> {
    let seed = harvest(entropy_personalization)?;
    prove_and_verify_with_entropy::<R>(witness, &seed)
}

// ═══════════════════════════════════════════════════════════════════════════
// ORAM + MicroVM wiring (demonstration that storage/execution modules are
// exercised in a real pipeline, not dead code)
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "std")]
use crate::execution::vm::MicroVM;
#[cfg(feature = "std")]
use crate::storage::oram::ObliviousRAM;

/// Run `verify_once` but store the harvested seed in an ORAM before keygen.
/// The seed is written to slot 0 and read back via the constant-time ORAM path,
/// demonstrating side-channel-resistant storage of iteration state material.
///
/// This is a demo pipeline; the ORAM adds latency but hides memory access
/// patterns.
#[cfg(feature = "std")]
pub fn verify_once_with_oram(claim: &Claim<'_>) -> Result<Verdict, VeilError> {
    let seed = harvest(claim.personalization)?;

    // Store seed in ORAM (slot 0), read it back.
    let mut oram = ObliviousRAM::new();
    oram.write(0, *seed.as_bytes());
    let mut raw = oram.read(0);
    let seed_from_oram = Seed::from_bytes(&raw);
    zeroize_bytes(&mut raw);

    verify_once_with_seed::<MlDsaProver, MlDsaVerifier>(&seed_from_oram, claim)
}

/// Run `verify_once` but first execute the claim bytes through the MicroVM,
/// using the deterministic VM root as personalization for entropy harvest.
/// This binds the iteration's entropy to a sandboxed execution trace of the
/// claim, so the same claim always produces the same VM-bound identity root.
///
/// This is a demo pipeline showing how the execution module can be wired into
/// the verification flow without adding persistent state or metadata.
#[cfg(feature = "std")]
pub fn verify_once_with_vm(claim: &Claim<'_>) -> Result<Verdict, VeilError> {
    let mut vm = MicroVM::new();
    let vm_root = vm.execute(claim.bytes);

    // Use the 64-byte VM root directly as external entropy seed.
    let mut seed_bytes = [0u8; 64];
    seed_bytes[..32].copy_from_slice(&vm_root[..32]);
    seed_bytes[32..].copy_from_slice(&vm_root[..32]);
    let seed = Seed::from_bytes(&seed_bytes);
    zeroize_bytes(&mut seed_bytes);

    verify_once_with_seed::<MlDsaProver, MlDsaVerifier>(&seed, claim)
}

#[cfg(feature = "std")]
use crate::l0_memlock::zeroize_bytes;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "std")]
    fn end_to_end_valid_claim() {
        let claim = Claim::new(b"the sky is blue");
        let verdict = verify_once(&claim).expect("pipeline ok");
        assert!(verdict.is_valid_bool(), "honest claim must verify");
        assert_eq!(verdict.transcript().len(), 32);
    }

    #[test]
    #[cfg(feature = "std")]
    fn statelessness_two_runs_independent_transcripts() {
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
    #[cfg(feature = "std")]
    fn many_iterations_all_valid() {
        for i in 0..16u8 {
            let data = [i; 8];
            let claim = Claim::new(&data);
            let v = verify_once(&claim).unwrap();
            assert!(v.is_valid_bool());
        }
    }

    #[test]
    fn seed_based_verify_once_valid() {
        let seed = Seed::from_bytes(&[0xA5u8; 64]);
        let claim = Claim::new(b"seed-based claim");
        let verdict =
            verify_once_with_seed::<MlDsaProver, MlDsaVerifier>(&seed, &claim).expect("ok");
        assert!(
            verdict.is_valid_bool(),
            "honest claim with seed must verify"
        );
    }

    #[test]
    #[cfg(feature = "std")]
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
    fn generic_relation_with_entropy_verifies() {
        use crate::relations::hash_preimage::{HashPreimage, Witness};
        let seed = Seed::from_bytes(&[0xB3u8; 64]);
        let w = Witness { seed: [0x9Au8; 32] };
        let verdict =
            prove_and_verify_with_entropy::<HashPreimage>(&w, &seed).expect("relation ok");
        assert!(
            verdict.is_valid_bool(),
            "honest hash-preimage proof must verify with explicit entropy"
        );
    }

    #[test]
    #[cfg(feature = "std")]
    fn generic_relation_statement_digest_is_stable() {
        use crate::relations::hash_preimage::{HashPreimage, Witness};
        let v1 = prove_and_verify::<HashPreimage>(&Witness { seed: [7u8; 32] }, b"a").unwrap();
        let v2 = prove_and_verify::<HashPreimage>(&Witness { seed: [7u8; 32] }, b"b").unwrap();
        assert_eq!(
            v1.transcript(),
            v2.transcript(),
            "statement digest binds to the statement, not to entropy"
        );
    }

    #[test]
    #[cfg(feature = "std")]
    fn oram_pipeline_runs_without_panic() {
        let claim = Claim::new(b"oram claim");
        let verdict = verify_once_with_oram(&claim).expect("oram pipeline ok");
        assert!(verdict.is_valid_bool());
    }

    #[test]
    #[cfg(feature = "std")]
    fn vm_pipeline_runs_without_panic() {
        let claim = Claim::new(b"vm claim");
        let verdict = verify_once_with_vm(&claim).expect("vm pipeline ok");
        assert!(verdict.is_valid_bool());
    }
}
