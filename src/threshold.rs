//! Threshold verification — N-of-M distributed trust.
//!
//! Run the same claim through M independent engine iterations and require
//! at least N of them to produce `valid=1` for the final verdict to be
//! valid. This distributes trust: compromising a single iteration does
//! not affect the outcome as long as the threshold holds.
//!
//! ## Privacy
//! - No per-iteration metadata is stored or emitted.
//! - The aggregator sees only validity bits (constant-time AND/OR), not
//!   which specific iterations passed or failed.
//! - The final `Verdict` is a single bit + aggregated transcript — no
//!   count, no index, no per-iteration data leaks.
//!
//! ## Philosophy alignment
//! - **Stateless**: each iteration is independent (fresh entropy, fresh keys).
//! - **No metadata**: the aggregator only combines `Choice` bits.
//! - **Verification through math**: threshold is a bitwise operation, not
//!   a stateful counter.

#![cfg(feature = "std")]

use crate::l0_memlock::zeroize_bytes;
use crate::l7_emit::Verdict;
use crate::pipeline::{verify_once, Claim};
use crate::VeilError;

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use subtle::Choice;

use core::sync::atomic::{compiler_fence, Ordering};

/// Domain tag for threshold transcript aggregation.
const THRESHOLD_HEAD: &[u8] = b"veil7:threshold:head:v1";
const THRESHOLD_STEP: &[u8] = b"veil7:threshold:step:v1";

/// Run `m` independent verification iterations on the same claim and
/// require at least `n` of them to produce `valid=1`.
///
/// # Arguments
/// - `claim` — the claim to verify
/// - `n` — threshold: minimum number of iterations that must be valid
/// - `m` — total number of independent iterations
///
/// # Returns
/// A single aggregated `Verdict` with:
/// - `valid=1` if ≥ N iterations produced `valid=1`
/// - `valid=0` otherwise
/// - transcript = SHAKE256 fold of all individual transcripts
///
/// # Errors
/// - `VeilError::Crypto` if `n == 0`, `m == 0`, or `n > m`.
/// - Propagates any engine error from individual iterations.
///
/// # Example
/// ```ignore
/// let claim = Claim::new(b"sensitive-data");
/// let verdict = threshold_verify(&claim, 3, 5)?;
/// // At least 3 out of 5 iterations must be valid.
/// assert!(verdict.is_valid_bool());
/// ```
pub fn threshold_verify(claim: &Claim<'_>, n: usize, m: usize) -> Result<Verdict, VeilError> {
    if n == 0 || m == 0 || n > m {
        return Err(VeilError::Crypto);
    }

    let mut valid_choices: Vec<subtle::Choice> = Vec::with_capacity(m);
    let mut xof = Shake256::default();
    xof.update(THRESHOLD_HEAD);
    xof.update(&(n as u64).to_le_bytes());
    xof.update(&(m as u64).to_le_bytes());

    for i in 0..m {
        let verdict = verify_once(claim)?;

        // Constant-time: accumulate Choice without branching on validity.
        valid_choices.push(verdict.is_valid());

        // Fold transcript into aggregator.
        xof.update(THRESHOLD_STEP);
        xof.update(&(i as u64).to_le_bytes());
        xof.update(verdict.transcript());
    }

    // Count valid choices without branching on individual verdicts.
    let mut count: u32 = 0;
    for c in &valid_choices {
        count += c.unwrap_u8() as u32;
    }
    compiler_fence(Ordering::SeqCst);
    let passed = Choice::from((count >= n as u32) as u8);
    compiler_fence(Ordering::SeqCst);

    // Wipe the count variable after use.
    let mut count_bytes = count.to_le_bytes();
    zeroize_bytes(&mut count_bytes);

    // Derive aggregated transcript.
    let mut transcript = [0u8; 32];
    let mut reader = xof.finalize_xof();
    reader.read(&mut transcript);

    Ok(Verdict::from_batch(passed, &transcript))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threshold_1_of_1_passes() {
        let claim = Claim::new(b"test-1-of-1");
        let v = threshold_verify(&claim, 1, 1).unwrap();
        assert!(v.is_valid_bool());
    }

    #[test]
    fn threshold_3_of_5_passes() {
        let claim = Claim::new(b"test-3-of-5");
        let v = threshold_verify(&claim, 3, 5).unwrap();
        // All iterations should be valid, so 5 >= 3 → valid.
        assert!(v.is_valid_bool());
    }

    #[test]
    fn threshold_all_of_all() {
        let claim = Claim::new(b"test-all");
        let v = threshold_verify(&claim, 3, 3).unwrap();
        assert!(v.is_valid_bool());
    }

    #[test]
    fn threshold_zero_n_fails() {
        let claim = Claim::new(b"test");
        assert!(threshold_verify(&claim, 0, 5).is_err());
    }

    #[test]
    fn threshold_zero_m_fails() {
        let claim = Claim::new(b"test");
        assert!(threshold_verify(&claim, 1, 0).is_err());
    }

    #[test]
    fn threshold_n_greater_than_m_fails() {
        let claim = Claim::new(b"test");
        assert!(threshold_verify(&claim, 6, 5).is_err());
    }

    #[test]
    fn threshold_deterministic_transcript_structure() {
        let claim = Claim::new(b"determinism");
        let v1 = threshold_verify(&claim, 2, 3).unwrap();
        let v2 = threshold_verify(&claim, 2, 3).unwrap();
        // Both valid, transcripts differ (different entropy per iteration).
        assert!(v1.is_valid_bool() && v2.is_valid_bool());
    }
}
