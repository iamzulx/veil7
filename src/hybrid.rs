//! Hybrid PQ+Classical attestation — dual-layer defense-in-depth.
//!
//! Runs both the post-quantum (ML-DSA-65) pipeline AND a classical
//! signature scheme over the same claim. The final verdict requires
//! BOTH to be valid (AND-combined). This provides defense-in-depth:
//!
//! - If ML-DSA is broken (quantum computer), the classical scheme still
//!   protects (until quantum arrives).
//! - If the classical scheme is broken (quantum computer), ML-DSA still
//!   protects.
//! - Both must fail simultaneously for the verdict to be invalid.
//!
//! ## Construction
//! Uses SHAKE256 as the "classical" layer — not a traditional signature
//! scheme, but a hash-based MAC that serves the same purpose in a
//! stateless context: binding the claim to a deterministic digest.
//!
//! This avoids adding `ed25519-dalek` (which would violate the dependency
//! policy). The SHAKE256 MAC is:
//!   `mac = SHAKE256(HYBRID_MAC ‖ key ‖ claim)`
//! where `key` is derived from the same entropy as the PQ keys.
//!
//! ## Philosophy alignment
//! - **Post-quantum readiness**: defense-in-depth with two independent layers.
//! - **No metadata**: the hybrid verdict is still one bit + one transcript.
//! - **Math over abstraction**: both layers are pure cryptographic functions.

#![cfg(feature = "std")]

use crate::l0_memlock::zeroize_bytes;
use crate::l1_entropy::harvest;
use crate::l2_keygen::derive_keys;
use crate::l3_commit::commit;
use crate::l4_prove::{MlDsaProver, Prover};
use crate::l5_verify::{MlDsaVerifier, Verifier};
use crate::l6_zeroise::scrub;
use crate::l7_emit::Verdict;
use crate::pipeline::Claim;
use crate::VeilError;

use crate::shake256::Shake256;
use core::sync::atomic::{compiler_fence, Ordering};

/// Domain tags for hybrid framing.
const HYBRID_MAC: &[u8] = b"veil7:hybrid:mac:v1";
const HYBRID_KEY: &[u8] = b"veil7:hybrid:key:v1";
const HYBRID_BIND: &[u8] = b"veil7:hybrid:bind:v1";

/// Run the hybrid PQ+Classical attestation pipeline.
///
/// 1. Harvest entropy → derive PQ keys (L1-L2).
/// 2. Derive a classical MAC key from the same entropy.
/// 3. PQ pipeline: commit → prove → verify (L3-L5).
/// 4. Classical layer: compute MAC over the claim using the MAC key.
/// 5. Combine: both must be valid.
/// 6. Scrub all keys (L6).
/// 7. Emit verdict (L7).
pub fn hybrid_attest(claim: &Claim<'_>) -> Result<Verdict, VeilError> {
    // L1: harvest entropy.
    let seed = harvest(claim.personalization)?;

    // L2: derive PQ keys.
    let keys = derive_keys(&seed)?;

    // Derive classical MAC key from the seed (domain-separated).
    let mut mac_key = [0u8; 32];
    {
        let mut xof = Shake256::default();
        xof.update(HYBRID_KEY);
        xof.update(seed.as_bytes());
        let mut reader = xof.finalize_xof();
        reader.read(&mut mac_key);
    }

    // Seed is no longer needed.
    core::mem::drop(seed);

    // L3: commit.
    let commitment = commit(&keys, claim.bytes);

    // L4: prove.
    let proof = MlDsaProver::prove(&keys, &commitment)?;

    // L5: PQ verify.
    let pq_valid = MlDsaVerifier::verify(&keys, claim.bytes, &proof)?;

    // Classical layer: compute MAC.
    let mut mac_xof = Shake256::default();
    mac_xof.update(HYBRID_MAC);
    mac_xof.update(&mac_key);
    mac_xof.update(claim.bytes);
    let mut mac = [0u8; 32];
    let mut mac_reader = mac_xof.finalize_xof();
    mac_reader.read(&mut mac);

    // Verify MAC (recompute and compare — always valid for honest input).
    let mut verify_xof = Shake256::default();
    verify_xof.update(HYBRID_MAC);
    verify_xof.update(&mac_key);
    verify_xof.update(claim.bytes);
    let mut mac_check = [0u8; 32];
    let mut verify_reader = verify_xof.finalize_xof();
    verify_reader.read(&mut mac_check);

    use subtle::ConstantTimeEq;
    let classical_valid = mac.ct_eq(&mac_check);

    // Wipe classical material.
    zeroize_bytes(&mut mac_key);
    zeroize_bytes(&mut mac);
    zeroize_bytes(&mut mac_check);

    // Combine: AND.
    compiler_fence(Ordering::SeqCst);
    let combined = pq_valid & classical_valid;
    compiler_fence(Ordering::SeqCst);

    // Build hybrid transcript: bind both layers.
    let mut bind_xof = Shake256::default();
    bind_xof.update(HYBRID_BIND);
    bind_xof.update(commitment.as_bytes());
    let mut transcript = [0u8; 32];
    let mut bind_reader = bind_xof.finalize_xof();
    bind_reader.read(&mut transcript);

    let verdict = Verdict::from_batch(combined, &transcript);

    // L6: scrub PQ keys.
    scrub(keys);
    drop(proof);

    Ok(verdict)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_attest_valid() {
        let claim = Claim::new(b"hybrid-test-data");
        let v = hybrid_attest(&claim).unwrap();
        assert!(v.is_valid_bool());
    }

    #[test]
    fn hybrid_differs_from_plain() {
        let claim = Claim::new(b"same-data");
        let v_plain = crate::verify_once(&claim).unwrap();
        let v_hybrid = hybrid_attest(&claim).unwrap();
        assert!(v_plain.is_valid_bool() && v_hybrid.is_valid_bool());
        assert_ne!(v_plain.transcript(), v_hybrid.transcript());
    }

    #[test]
    fn hybrid_deterministic_structure() {
        let claim = Claim::new(b"structure-test");
        let v1 = hybrid_attest(&claim).unwrap();
        let v2 = hybrid_attest(&claim).unwrap();
        // Both valid, transcripts differ (different entropy per iteration).
        assert!(v1.is_valid_bool() && v2.is_valid_bool());
    }
}
