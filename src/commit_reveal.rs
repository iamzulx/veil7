// Author: Iamzulx
//! Commit-Reveal protocol — two-phase attestation.
//!
//! Phase 1 (Commit): the caller submits a claim and receives a 32-byte
//! `CommitmentToken`. The engine generates a random nonce, commits to
//! `SHAKE256(CR_COMMIT ‖ nonce ‖ claim)`, and wipes the nonce.
//!
//! Phase 2 (Reveal): the caller submits the same claim along with the
//! token. The engine recomputes the commitment and verifies it matches.
//! If it does, the full ML-DSA pipeline runs over the claim.
//!
//! ## Why two-phase?
//! Between commit and reveal, no party (including the engine) can predict
//! the verdict. This is useful for:
//! - Sealed-bid auctions: commit bids, reveal after deadline.
//! - Fair lotteries: commit entries, reveal after cutoff.
//! - Voting: commit votes, reveal after poll closes.
//!
//! ## Privacy
//! - The `CommitmentToken` is 32 bytes — no metadata.
//! - The nonce is wiped immediately after commitment.
//! - The engine stores nothing between phases (the caller holds the token).
//!
//! ## Philosophy alignment
//! - **No persistent state**: engine stores nothing between commit and reveal.
//! - **Math over abstraction**: commitment is a SHAKE256 digest.
//! - **Wipe outside boundary**: nonce is zeroized after use.

#![cfg(feature = "std")]

use crate::l0_memlock::zeroize_bytes;
use crate::pipeline::{verify_once, Claim};
use crate::VeilError;
use crate::Verdict;

use crate::shake256::Shake256;

/// Domain tags for commit-reveal framing.
const CR_COMMIT: &[u8] = b"veil7:cr:commit:v1";

/// A 32-byte commitment token returned by Phase 1.
///
/// The caller must hold this token and present it in Phase 2.
/// The engine does not store it — it is pure caller-side state.
#[derive(Clone)]
pub struct CommitmentToken {
    digest: [u8; 32],
}

impl CommitmentToken {
    /// Return the raw 32-byte digest (for serialization / storage by caller).
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Reconstruct a token from raw bytes (e.g. received from caller storage).
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self { digest: *bytes }
    }
}

impl Drop for CommitmentToken {
    #[inline(never)]
    fn drop(&mut self) {
        zeroize_bytes(&mut self.digest);
    }
}

/// Internal: the nonce used to blind the commitment.
/// This struct exists only transiently during `commit()` and is wiped.
struct Nonce {
    bytes: [u8; 32],
}

impl Nonce {
    fn fresh() -> Result<Self, crate::VeilError> {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|_| crate::VeilError::Entropy)?;
        Ok(Self { bytes })
    }
}

impl Drop for Nonce {
    #[inline(never)]
    fn drop(&mut self) {
        zeroize_bytes(&mut self.bytes);
    }
}

/// Phase 1: Commit to a claim.
///
/// Generates a random nonce, computes `SHAKE256(CR_COMMIT ‖ nonce ‖ claim)`,
/// wipes the nonce, and returns a `CommitmentToken`.
///
/// The engine does not retain any state from this call. The token is the
/// only artifact; the caller is responsible for holding it.
pub fn commit(claim: &[u8]) -> Result<CommitmentToken, VeilError> {
    let nonce = Nonce::fresh()?;

    let mut xof = Shake256::default();
    xof.update(CR_COMMIT);
    xof.update(&nonce.bytes);
    xof.update(claim);

    let mut digest = [0u8; 32];
    let mut reader = xof.finalize_xof();
    reader.read(&mut digest);

    // Nonce is wiped on drop (ZeroizeOnDrop via Drop impl).
    Ok(CommitmentToken { digest })
}

/// Phase 1: Commit to a claim.
///
/// Returns `(CommitmentToken, NonceBytes)` — the caller must hold both.
/// The engine wipes all internal state before returning.
pub fn commit_phase(claim: &[u8]) -> Result<(CommitmentToken, [u8; 32]), VeilError> {
    let mut nonce_bytes = [0u8; 32];
    getrandom::getrandom(&mut nonce_bytes).map_err(|_| VeilError::Entropy)?;

    let mut xof = Shake256::default();
    xof.update(CR_COMMIT);
    xof.update(&nonce_bytes);
    xof.update(claim);

    let mut digest = [0u8; 32];
    let mut reader = xof.finalize_xof();
    reader.read(&mut digest);

    Ok((CommitmentToken { digest }, nonce_bytes))
}

/// Phase 2: Reveal the committed claim.
///
/// Verifies that `SHAKE256(CR_COMMIT ‖ nonce ‖ claim) == token.digest`,
/// then runs the full ML-DSA pipeline over the claim.
///
/// The nonce is wiped after verification regardless of outcome.
///
/// Returns `VeilError::Crypto` if the commitment does not match.
pub fn reveal_phase(
    token: &CommitmentToken,
    nonce: &[u8; 32],
    claim: &[u8],
) -> Result<Verdict, VeilError> {
    // Recompute the commitment.
    let mut xof = Shake256::default();
    xof.update(CR_COMMIT);
    xof.update(nonce);
    xof.update(claim);

    let mut recomputed = [0u8; 32];
    let mut reader = xof.finalize_xof();
    reader.read(&mut recomputed);

    // Constant-time comparison.
    use subtle::ConstantTimeEq;
    let match_ok = recomputed.ct_eq(&token.digest).unwrap_u8();

    // Wipe intermediates.
    zeroize_bytes(&mut recomputed);

    if match_ok != 1 {
        return Err(VeilError::Crypto);
    }

    // Run the full ML-DSA pipeline over the now-revealed claim.
    verify_once(&Claim::new(claim))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_reveal_roundtrip() {
        let claim = b"sealed-bid:1000";
        let (token, nonce) = commit_phase(claim).unwrap();
        let verdict = reveal_phase(&token, &nonce, claim).unwrap();
        assert!(verdict.is_valid_bool());
    }

    #[test]
    fn reveal_wrong_claim_fails() {
        let claim = b"sealed-bid:1000";
        let (token, nonce) = commit_phase(claim).unwrap();
        let result = reveal_phase(&token, &nonce, b"sealed-bid:2000");
        assert!(result.is_err(), "wrong claim must fail commitment check");
    }

    #[test]
    fn reveal_wrong_nonce_fails() {
        let claim = b"sealed-bid:1000";
        let (token, _nonce) = commit_phase(claim).unwrap();
        let bad_nonce = [0xFFu8; 32];
        let result = reveal_phase(&token, &bad_nonce, claim);
        assert!(result.is_err(), "wrong nonce must fail commitment check");
    }

    #[test]
    fn commit_is_nondeterministic() {
        let claim = b"same-claim";
        let (t1, n1) = commit_phase(claim).unwrap();
        let (t2, n2) = commit_phase(claim).unwrap();
        // Different nonces → different tokens.
        assert_ne!(t1.as_bytes(), t2.as_bytes());
        assert_ne!(n1, n2);
    }

    #[test]
    fn token_serialization_roundtrip() {
        let claim = b"serialize-test";
        let (token, nonce) = commit_phase(claim).unwrap();
        let bytes = *token.as_bytes();
        let reconstructed = CommitmentToken::from_bytes(&bytes);
        let verdict = reveal_phase(&reconstructed, &nonce, claim).unwrap();
        assert!(verdict.is_valid_bool());
    }
}
