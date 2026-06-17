// Author: Iamzulx
// Copyright (c) 2026
// License: MIT
//! Audit-side verification — pure math, no secrets, no engine.
//!
//! These functions let anyone verify attestations offline using only
//! public inputs. No entropy harvest, no ephemeral keygen, no PQ
//! operations — just SHAKE256 math over the public transcript.
//!
//! This is the "audit side" of veil7's universal verification:
//! the engine attests (L1→L7), but anyone can verify the result
//! using only the published Verdict and the original inputs.

use crate::chain::chain_verify;
use crate::common::domain;
use crate::shake256::Shake256;
use subtle::{Choice, ConstantTimeEq};

/// Re-derive the expected transcript hash from a claim's bytes.
///
/// Given the original claim bytes, recompute what the transcript
/// should be. Compare with `verdict.transcript()` to verify the
/// claim was attested by the engine.
///
/// **Limitation**: The full ML-DSA pipeline transcript includes the
/// ephemeral public key (which is wiped at L6), so this function
/// can only verify the chain-root path — not the full PQ signature.
/// For full PQ verification, the Verifier side (L5) must be used.
///
/// Returns `Choice::from(1)` if the recomputed root matches.
pub fn verify_chain_attestation(events: &[&[u8]], expected_root: &[u8; 32]) -> Choice {
    chain_verify(events, expected_root)
}

/// Verify that a batch of claim transcripts matches the expected
/// batch transcript hash.
///
/// Recomputes the batch fold from individual transcripts and
/// compares with the batch verdict's transcript.
pub fn verify_batch_transcripts(
    individual_transcripts: &[[u8; 32]],
    expected_batch_transcript: &[u8; 32],
) -> Choice {
    if individual_transcripts.is_empty() {
        return Choice::from(0u8);
    }
    let mut xof = Shake256::default();
    xof.update(domain::BATCH_HEAD);
    for (i, t) in individual_transcripts.iter().enumerate() {
        xof.update(domain::BATCH_STEP);
        xof.update(&(i as u64).to_le_bytes());
        xof.update(t);
    }
    let mut computed = [0u8; 32];
    xof.finalize_xof().read(&mut computed);
    computed.ct_eq(expected_batch_transcript)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::chain_root;

    #[test]
    fn test_verify_chain_attestation_valid() {
        let events: &[&[u8]] = &[b"login:alice", b"read:/data", b"logout:alice"];
        let root = chain_root(events).expect("non-empty");
        let result = verify_chain_attestation(events, &root);
        assert_eq!(
            result.unwrap_u8(),
            1,
            "valid chain must verify against its own root"
        );
    }

    #[test]
    fn test_verify_chain_attestation_tampered() {
        let events: &[&[u8]] = &[b"login:alice", b"read:/data", b"logout:alice"];
        let tampered: &[&[u8]] = &[b"login:alice", b"read:/SECRETS", b"logout:alice"];
        let root = chain_root(events).expect("non-empty");
        let result = verify_chain_attestation(tampered, &root);
        assert_eq!(
            result.unwrap_u8(),
            0,
            "tampered events must not verify against original root"
        );
    }

    #[test]
    fn test_verify_batch_transcripts_valid() {
        // Build individual transcripts
        let t0 = [0xAAu8; 32];
        let t1 = [0xBBu8; 32];
        let t2 = [0xCCu8; 32];
        let transcripts: &[[u8; 32]] = &[t0, t1, t2];

        // Compute the expected batch fold (same logic as verify_batch_transcripts)
        let mut xof = Shake256::default();
        xof.update(domain::BATCH_HEAD);
        for (i, t) in transcripts.iter().enumerate() {
            xof.update(domain::BATCH_STEP);
            xof.update(&(i as u64).to_le_bytes());
            xof.update(t);
        }
        let mut expected = [0u8; 32];
        xof.finalize_xof().read(&mut expected);

        let result = verify_batch_transcripts(transcripts, &expected);
        assert_eq!(
            result.unwrap_u8(),
            1,
            "batch transcripts must verify against correct fold"
        );
    }
}
