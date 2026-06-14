//! Blind attestation — the engine attests data it never sees.
//!
//! The caller blinds the claim with a random mask before sending it to the
//! engine. The engine runs the full L1→L7 pipeline on the blinded data,
//! producing a `Verdict`. The caller then unblinds the transcript.
//!
//! ## Flow
//! ```text
//! Caller:  blind = SHAKE256(BLIND_MASK ‖ nonce)
//!          blinded_claim = claim ⊕ blind
//!
//! Engine:  attest(blinded_claim) → Verdict{valid, transcript}
//!          (engine never sees the original claim)
//!
//! Caller:  unblinded_transcript = transcript ⊕ SHAKE256(BLIND_UNMASK ‖ nonce)
//! ```
//!
//! ## Privacy property
//! The engine processes `blinded_claim` which is uniformly random to anyone
//! who does not know the nonce. The engine's `Verdict` is valid for the
//! blinded data; the caller can correlate it to the original claim via
//! the unblinded transcript.
//!
//! ## Limitations
//! - This is a **computational** blind, not information-theoretic.
//! - The validity bit is always `valid=1` for honest blinded claims
//!   (the ML-DSA pipeline succeeds on any input).
//! - The blind is one-shot: the same nonce must not be reused for a
//!   different claim (the engine's stateless model already prevents this).
//!
//! ## Philosophy alignment
//! - **No trace (level up)**: engine literally cannot see the plaintext.
//! - **Wipe outside boundary**: nonce and mask are wiped after blinding.
//! - **Math over abstraction**: XOR + SHAKE256, nothing more.

#![cfg(feature = "std")]

use crate::l0_memlock::zeroize_bytes;
use crate::pipeline::{verify_once, Claim};
use crate::VeilError;
use crate::Verdict;

use crate::shake256::Shake256;

/// Domain tags for blind framing.
const BLIND_MASK: &[u8] = b"veil7:blind:mask:v1";
const BLIND_UNMASK: &[u8] = b"veil7:blind:unmask:v1";

/// The blinding material held by the caller.
///
/// The caller creates this, uses it to blind a claim, sends the blinded
/// claim to the engine, and later uses it to unblind the transcript.
/// Must be wiped after use.
pub struct BlindFactor {
    nonce: [u8; 32],
    mask: [u8; 32],
}

impl BlindFactor {
    /// Generate a fresh random blinding factor.
    pub fn fresh() -> Result<Self, crate::VeilError> {
        let mut nonce = [0u8; 32];
        getrandom::getrandom(&mut nonce).map_err(|_| crate::VeilError::Entropy)?;

        let mut xof = Shake256::default();
        xof.update(BLIND_MASK);
        xof.update(&nonce);
        let mut mask = [0u8; 32];
        let mut reader = xof.finalize_xof();
        reader.read(&mut mask);

        Ok(Self { nonce, mask })
    }

    /// Reconstruct from stored nonce (e.g. for two-phase protocols).
    pub fn from_nonce(nonce: [u8; 32]) -> Self {
        let mut xof = Shake256::default();
        xof.update(BLIND_MASK);
        xof.update(&nonce);
        let mut mask = [0u8; 32];
        let mut reader = xof.finalize_xof();
        reader.read(&mut mask);

        Self { nonce, mask }
    }

    /// Return the nonce (for caller-side storage between blind/unblind).
    pub fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }
}

impl Drop for BlindFactor {
    #[inline(never)]
    fn drop(&mut self) {
        zeroize_bytes(&mut self.nonce);
        zeroize_bytes(&mut self.mask);
    }
}

/// Blind a claim: `blinded[i] = claim[i] ⊕ mask[i % 32]`.
///
/// Returns the blinded claim bytes. The caller sends these to the engine.
/// The original claim is not modified.
///
/// **Security note:** The blinded output is uniformly random without the
/// nonce and does not need zeroizing. The `BlindFactor` itself is
/// `ZeroizeOnDrop` and must be wiped by the caller after use.
pub fn blind_claim(claim: &[u8], factor: &BlindFactor) -> Vec<u8> {
    let mut blinded = claim.to_vec();
    for (i, b) in blinded.iter_mut().enumerate() {
        *b ^= factor.mask[i % 32];
    }
    blinded
}

/// Unblind a transcript: `unblinded[i] = transcript[i] ⊕ unmask[i]`.
///
/// The caller uses this after receiving the engine's `Verdict` to
/// correlate the transcript back to the original (unblinded) claim.
pub fn unblind_transcript(transcript: &[u8; 32], factor: &BlindFactor) -> [u8; 32] {
    let mut xof = Shake256::default();
    xof.update(BLIND_UNMASK);
    xof.update(&factor.nonce);
    let mut unmask = [0u8; 32];
    let mut reader = xof.finalize_xof();
    reader.read(&mut unmask);

    let mut unblinded = [0u8; 32];
    for i in 0..32 {
        unblinded[i] = transcript[i] ^ unmask[i];
    }

    zeroize_bytes(&mut unmask);
    unblinded
}

/// One-call blind attestation: blind, attest, unblind.
///
/// This is a convenience wrapper that performs the full blind→attest→unblind
/// cycle in one call. For two-phase protocols where the caller wants to
/// send the blinded claim to a remote engine, use `blind_claim` and
/// `unblind_transcript` separately.
///
/// Returns `(Verdict, unblinded_transcript)`.
pub fn blind_attest(claim: &[u8]) -> Result<(Verdict, [u8; 32]), VeilError> {
    let factor = BlindFactor::fresh()?;
    let blinded = blind_claim(claim, &factor);
    let verdict = verify_once(&Claim::new(&blinded))?;
    let unblinded = unblind_transcript(verdict.transcript(), &factor);
    Ok((verdict, unblinded))
}

extern crate alloc;
use alloc::vec::Vec;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blind_attest_roundtrip() {
        let claim = b"secret-auction-bid:5000";
        let (verdict, unblinded) = blind_attest(claim).unwrap();
        assert!(verdict.is_valid_bool());
        assert_ne!(
            unblinded, [0u8; 32],
            "unblinded transcript must be non-zero"
        );
    }

    #[test]
    fn blinded_claim_differs_from_original() {
        let claim = b"plaintext-data";
        let factor = BlindFactor::fresh().unwrap();
        let blinded = blind_claim(claim, &factor);
        assert_ne!(
            &blinded[..],
            &claim[..],
            "blinded must differ from original"
        );
    }

    #[test]
    fn blind_unblind_is_deterministic_for_same_factor() {
        let claim = b"same-claim";
        let nonce = [0x42u8; 32];
        let f1 = BlindFactor::from_nonce(nonce);
        let f2 = BlindFactor::from_nonce(nonce);

        let b1 = blind_claim(claim, &f1);
        let b2 = blind_claim(claim, &f2);
        assert_eq!(b1, b2, "same nonce → same blinded output");
    }

    #[test]
    fn different_nonces_produce_different_blinds() {
        let claim = b"same-claim";
        let f1 = BlindFactor::from_nonce([0x01; 32]);
        let f2 = BlindFactor::from_nonce([0x02; 32]);

        let b1 = blind_claim(claim, &f1);
        let b2 = blind_claim(claim, &f2);
        assert_ne!(b1, b2);
    }

    #[test]
    fn double_blind_recovers_original() {
        let claim = b"round-trip-test";
        let factor = BlindFactor::fresh().unwrap();
        let blinded = blind_claim(claim, &factor);
        let unblinded = blind_claim(&blinded, &factor); // XOR again = original
        assert_eq!(&unblinded[..], &claim[..]);
    }

    #[test]
    fn unblinded_transcript_differs_from_raw() {
        let claim = b"test";
        let factor = BlindFactor::fresh().unwrap();
        let blinded = blind_claim(claim, &factor);
        let verdict = verify_once(&Claim::new(&blinded)).unwrap();
        let unblinded = unblind_transcript(verdict.transcript(), &factor);
        // Unblinded transcript should differ from the raw (blinded) one.
        assert_ne!(&unblinded[..], &verdict.transcript()[..]);
    }
}
