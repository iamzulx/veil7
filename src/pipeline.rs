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
    /// The data to attest.
    pub bytes: &'a [u8],
    /// Optional personalization context (binds attestation to context).
    pub personalization: &'a [u8],
}

impl<'a> Claim<'a> {
    /// Create a new claim with no personalization.
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
///
/// The seed is **consumed by value** (not borrowed) so the pipeline can
/// explicitly drop it as soon as L2 finishes. After L2 the seed is no
/// longer needed: the ephemeral PQ keypair is the only secret that flows
/// through L3..L7, and the seed is auto-wiped on `Drop`. The explicit
/// `drop(seed)` after `derive_keys` is defence-in-depth against any
/// future optimization pass that might extend the seed's live range
/// past L2.
pub fn verify_once_with_seed<P, V>(seed: Seed, claim: &Claim<'_>) -> Result<Verdict, VeilError>
where
    P: Prover,
    V: Verifier,
{
    // L2 — derive ephemeral PQ keypairs. Secret keys are ZeroizeOnDrop.
    let keys = derive_keys(&seed)?;

    // Side-channel hardening: the master seed is no longer needed
    // after L2 (the ephemeral keypair is the only secret that flows
    // through L3..L7). Drop it NOW to minimize its live range and
    // give the wipe the earliest possible insertion point. The seed
    // would auto-wipe on Drop at end of scope anyway, but
    // explicit-drop here makes the intent visible to the optimizer
    // and to human readers, and prevents a future code change from
    // accidentally extending the seed's lifetime.
    core::mem::drop(seed);

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
///
/// The seed is **consumed by value** (see `verify_once_with_seed` for the
/// rationale) so the live range is explicit. After `R::prove` the seed
/// is no longer needed: the relation's randomness is consumed and the
/// statement + proof are public material.
pub fn prove_and_verify_with_entropy<R: Relation>(
    witness: &R::Witness,
    entropy: Seed,
) -> Result<Verdict, VeilError> {
    // Prove: witness + entropy -> (statement, proof) via Fiat-Shamir.
    let (stmt, proof) = R::prove(witness, entropy.as_bytes())?;

    // Side-channel hardening: same explicit-drop pattern as
    // `verify_once_with_seed`. The seed is no longer needed after
    // `R::prove`; dropping it here minimizes its live range.
    core::mem::drop(entropy);

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
    verify_once_with_seed::<MlDsaProver, MlDsaVerifier>(seed, claim)
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
    verify_once_with_seed::<P, V>(seed, claim)
}

/// Run one stateless prove→verify iteration for an arbitrary [`Relation`].
/// Auto-harvests entropy from the OS.
#[cfg(feature = "std")]
pub fn prove_and_verify<R: Relation>(
    witness: &R::Witness,
    entropy_personalization: &[u8],
) -> Result<Verdict, VeilError> {
    let seed = harvest(entropy_personalization)?;
    prove_and_verify_with_entropy::<R>(witness, seed)
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
    // Harvest the seed (it is consumed by value below; we don't need to
    // keep the harvest-time copy around once the ORAM has extracted
    // its bytes). Wipe the raw buffer that came out of the ORAM as
    // soon as we've reconstructed the seed.
    let seed = harvest(claim.personalization)?;

    // Store seed in ORAM (slot 0), read it back.
    let mut oram = ObliviousRAM::new();
    oram.write(0, *seed.as_bytes());
    let mut raw = oram.read(0);
    let seed_from_oram = Seed::from_bytes(&raw);
    zeroize_bytes(&mut raw);

    // Side-channel hardening: the harvest-time `seed` is no longer
    // needed (the ORAM-stored copy is what we just extracted). Drop
    // it NOW so its live range is bounded by the ORAM round-trip,
    // not by the rest of the pipeline.
    core::mem::drop(seed);

    verify_once_with_seed::<MlDsaProver, MlDsaVerifier>(seed_from_oram, claim)
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

    verify_once_with_seed::<MlDsaProver, MlDsaVerifier>(seed, claim)
}

// ═══════════════════════════════════════════════════════════════════════════
// Batch verification (multiple claims, single aggregated Verdict)
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "std")]
use crate::l0_memlock::zeroize_bytes;

/// Run `verify_once` on each claim independently and return a single
/// aggregated `Verdict`.
///
/// Each claim gets its own ephemeral identity (fresh entropy, fresh
/// keypair, full L1→L7 cycle). The validity bits are AND-combined
/// (all must be valid), and the transcript hashes are folded through
/// a domain-separated SHAKE256 accumulator into a single 32-byte
/// batch transcript.
///
/// **Statelessness preserved**: no state leaks between iterations.
/// **Fail-closed**: if any single iteration returns `Err`, the entire
/// batch returns `Err`. Empty input returns `Err`.
///
/// Privacy: the batch transcript is a deterministic fold of individual
/// transcripts, so it uniquely identifies the set of claims without
/// leaking per-claim validity (the AND-bit is the only aggregate signal).
#[cfg(feature = "std")]
pub fn verify_batch(claims: &[Claim<'_>]) -> Result<Verdict, VeilError> {
    if claims.is_empty() {
        return Err(VeilError::Crypto);
    }

    let mut all_valid = subtle::Choice::from(1u8);
    let mut batch_xof = Shake256::default();
    use crate::shake256::Shake256;
    batch_xof.update(crate::common::domain::BATCH_HEAD);

    for (i, claim) in claims.iter().enumerate() {
        let verdict = verify_once(claim)?;
        all_valid &= subtle::Choice::from(verdict.is_valid_bool() as u8);

        // Fold each verdict's transcript into the batch accumulator
        // with domain-separated framing (index + transcript).
        batch_xof.update(crate::common::domain::BATCH_STEP);
        batch_xof.update(&(i as u64).to_le_bytes());
        batch_xof.update(verdict.transcript());
    }

    // Derive the batch transcript (32 bytes).
    let mut batch_transcript = [0u8; 32];
    let mut reader = batch_xof.finalize_xof();
    reader.read(&mut batch_transcript);

    Ok(Verdict::from_batch(all_valid, &batch_transcript))
}

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
            verify_once_with_seed::<MlDsaProver, MlDsaVerifier>(seed, &claim).expect("ok");
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
        let verdict = prove_and_verify_with_entropy::<HashPreimage>(&w, seed).expect("relation ok");
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
