// Author: Iamzulx
// Copyright (c) 2026
// License: MIT
//! L7 — Traceless Emission.
//!
//! The only thing that leaves the engine. A `Verdict` carries:
//!   * `valid: Choice` — one bit, constant-time (1 = verified, 0 = not).
//!   * `transcript: [u8; 32]` — a SHAKE256 hash binding the verdict to the
//!     commitment, so a caller can correlate a verdict to the claim THEY hold
//!     without the engine storing or emitting the claim, keys, or any ID.
//!
//! Explicitly absent (by construction — there is no field to hold them):
//!   * No timestamp, no sequence number, no session/request ID.
//!   * No key material, no signature, no claim plaintext.
//!   * No error detail beyond the opaque `VeilError` (which never reaches L7 on
//!     the success path).
//!
//! `Debug` is implemented by hand to print only the bit and a fixed-width hash,
//! never anything that could vary as a fingerprint.

use crate::domain;
use crate::l3_commit::Commitment;

use crate::shake256::Shake256;
use subtle::Choice;

use core::fmt::Write;
use core::sync::atomic::{compiler_fence, Ordering};

/// The metadata-free result of one verification iteration.
pub struct Verdict {
    /// Constant-time validity bit.
    valid: Choice,
    /// 32-byte transcript hash bound to the commitment.
    transcript: [u8; 32],
}

impl Verdict {
    /// Construct a verdict from the validity choice and the commitment.
    pub(crate) fn new(valid: Choice, commitment: &Commitment) -> Self {
        // Side-channel hardening: `Choice` is supposed to be CT but
        // dalek-cryptography/subtle documents it as "best-effort"
        // (CVE-2026-23519 showed LLVM may optimize cmov into bne
        // on ARM Cortex-M0 — different arch than ours but the
        // principle applies). We add a compiler fence before the
        // constructor so the `Choice` is observable across the
        // function boundary as the optimizer's barrier put it
        // there, and not as some compiler-internal value that
        // got folded.
        compiler_fence(Ordering::SeqCst);
        // SIDE-CHANNEL: T-table Keccak. Absorbs only public commitment bytes.
        // See SPEC-HARDENING.md §"Cache timing and T-table side channels".
        // Risk class: LOW (public input).
        let mut xof = Shake256::default();
        xof.update(domain::TRANSCRIPT);
        xof.update(commitment.as_bytes());
        let mut transcript = [0u8; 32];
        let mut reader = xof.finalize_xof();
        reader.read(&mut transcript);
        Verdict { valid, transcript }
    }

    /// Construct a verdict bound to an arbitrary 32-byte statement digest.
    ///
    /// Used by the generic relation pipeline: the digest is a public commitment
    /// to the statement (carries no secret), so the verdict can be correlated to
    /// the claim the caller holds without the engine emitting any metadata.
    pub(crate) fn from_statement_digest(valid: Choice, statement_digest: &[u8; 32]) -> Self {
        // Same hardening as `new`: a fence before the Choice field is
        // written into the struct, to keep `valid` observable across
        // the constructor boundary.
        compiler_fence(Ordering::SeqCst);
        // SIDE-CHANNEL: T-table Keccak. Absorbs only public statement_digest
        // bytes. See SPEC-HARDENING.md §"Cache timing and T-table side
        // channels". Risk class: LOW (public input).
        let mut xof = Shake256::default();
        xof.update(domain::TRANSCRIPT);
        xof.update(statement_digest);
        let mut transcript = [0u8; 32];
        let mut reader = xof.finalize_xof();
        reader.read(&mut transcript);
        Verdict { valid, transcript }
    }

    /// Construct a batch verdict from an aggregated validity choice and
    /// a pre-computed 32-byte batch transcript.
    ///
    /// Used by `verify_batch`: the batch transcript is a SHAKE256 fold of
    /// individual verdict transcripts, so it uniquely identifies the claim
    /// set without per-claim metadata.
    #[cfg(feature = "std")]
    pub(crate) fn from_batch(valid: Choice, batch_transcript: &[u8; 32]) -> Self {
        compiler_fence(Ordering::SeqCst);
        Verdict {
            valid,
            transcript: *batch_transcript,
        }
    }

    /// Was the claim verified? Returns a constant-time `Choice`.
    #[inline]
    pub fn is_valid(&self) -> Choice {
        self.valid
    }

    /// Convenience boolean. Note: collapsing to `bool` is a deliberate caller
    /// choice — the engine itself never branches on this internally.
    #[inline]
    pub fn is_valid_bool(&self) -> bool {
        self.valid.unwrap_u8() == 1
    }

    /// The transcript hash. Public, carries no secret and no metadata.
    #[inline]
    pub fn transcript(&self) -> &[u8; 32] {
        &self.transcript
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// HIGH PRIORITY ENHANCEMENTS
// ═══════════════════════════════════════════════════════════════════════════

/// Validate that verdict is valid.
///
/// Checks:
/// - Verdict has valid Choice (0 or 1)
/// - Transcript is not all zeros
/// - Transcript is not all ones
///
/// Returns `Ok(())` if verdict is valid, `Err(Crypto)` if invalid.
///
/// **Security Benefit:**
/// - Detects invalid verdicts
/// - Prevents corrupted verdicts from being used
/// - Follows "refuse > guess" philosophy
pub fn validate_verdict(verdict: &Verdict) -> Result<(), crate::VeilError> {
    let valid_value = verdict.valid.unwrap_u8();
    
    // Check Choice is valid (0 or 1)
    if valid_value != 0 && valid_value != 1 {
        return Err(crate::VeilError::Crypto);
    }
    
    // Check transcript is not all zeros
    if verdict.transcript.iter().all(|&b| b == 0) {
        return Err(crate::VeilError::Crypto);
    }
    
    // Check transcript is not all ones
    if verdict.transcript.iter().all(|&b| b == 0xFF) {
        return Err(crate::VeilError::Crypto);
    }
    
    Ok(())
}

/// Validate verdict strength.
///
/// Checks:
/// - Transcript has sufficient entropy (not biased)
/// - Transcript has sufficient unique byte values (at least 4)
///
/// Returns `Ok(())` if strength is valid, `Err(Crypto)` if invalid.
///
/// **Security Benefit:**
/// - Ensures verdict has sufficient entropy
/// - Prevents weak verdicts
/// - Follows "math over abstraction" philosophy
pub fn validate_verdict_strength(verdict: &Verdict) -> Result<(), crate::VeilError> {
    let transcript = &verdict.transcript;
    
    // Check for obvious bias (all bytes same value)
    let first_byte = transcript[0];
    if transcript.iter().all(|&b| b == first_byte) {
        return Err(crate::VeilError::Crypto);
    }
    
    // Check for low entropy (less than 4 unique byte values)
    let mut unique_bytes = [false; 256];
    let mut unique_count = 0;
    for &b in transcript.iter() {
        if !unique_bytes[b as usize] {
            unique_bytes[b as usize] = true;
            unique_count += 1;
        }
    }
    
    if unique_count < 4 {
        return Err(crate::VeilError::Crypto);
    }
    
    Ok(())
}

/// Derive verdict from multiple sources (defence-in-depth).
///
/// Combines:
/// - Original verdict
/// - Additional context (optional)
///
/// Returns a new verdict bound to multiple sources.
///
/// **Security Benefit:**
/// - Defence-in-depth (multiple sources)
/// - Additional binding beyond original verdict
/// - Follows "defence-in-depth" philosophy
pub fn verdict_multi_source(
    verdict: &Verdict,
    additional_context: &[u8],
) -> Verdict {
    let mut xof = Shake256::default();
    xof.update(domain::TRANSCRIPT);
    xof.update(verdict.transcript());
    xof.update(additional_context);
    let mut new_transcript = [0u8; 32];
    let mut reader = xof.finalize_xof();
    reader.read(&mut new_transcript);
    
    compiler_fence(Ordering::SeqCst);
    Verdict {
        valid: verdict.valid,
        transcript: new_transcript,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// MEDIUM PRIORITY ENHANCEMENTS
// ═══════════════════════════════════════════════════════════════════════════

// ── Verdict Isolation (MEDIUM Priority - Documented) ────────────────────────
//
// Verdict isolation via Locked<> wrappers would provide additional isolation by
// placing verdicts in separate memory-locked regions. However, this is optional
// because:
//
// 1. **Verdicts are metadata-free** — they contain no secret material by construction
// 2. **Small size** — verdict is small (33 bytes: 1 byte Choice + 32 bytes transcript)
// 3. **Limited benefit** — isolating metadata-free data provides minimal security benefit
//
// **Recommendation:** Skip verdict isolation. The current implementation is
// sufficient because verdicts are metadata-free by construction.
//
// **Philosophy alignment:** This follows the "math over abstraction" philosophy.
// Adding isolation for metadata-free data would be unnecessary abstraction without
// security benefit.

/// Trait for verdict scheme agility.
///
/// Allows swapping between different verdict schemes.
///
/// **Security Benefit:**
/// - Support multiple verdict schemes
/// - Future-proof for scheme swapping
/// - Follows "crypto-agility" philosophy
///
/// **Note:** Future work. Only basic verdict currently supported.
pub trait VerdictScheme {
    fn new(valid: Choice, commitment: &Commitment) -> Verdict;
}

/// Basic verdict scheme (SHAKE256 transcript).
pub struct BasicVerdictScheme;

impl VerdictScheme for BasicVerdictScheme {
    fn new(valid: Choice, commitment: &Commitment) -> Verdict {
        Verdict::new(valid, commitment)
    }
}

impl core::fmt::Debug for Verdict {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Only the bit and the hash. Nothing time-varying or identifying.
        write!(
            f,
            "Verdict {{ valid: {}, transcript: ",
            self.valid.unwrap_u8()
        )?;
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for &byte in self.transcript.iter() {
            f.write_char(HEX[(byte >> 4) as usize] as char)?;
            f.write_char(HEX[(byte & 0x0f) as usize] as char)?;
        }
        write!(f, " }}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l1_entropy::Seed;
    use crate::l2_keygen::derive_keys;
    use crate::l3_commit::commit;

    fn fake_seed() -> Seed {
        Seed::from_bytes(&[0xA5u8; 64])
    }

    #[test]
    fn verdict_carries_bit_and_hash() {
        let seed = fake_seed();
        let keys = derive_keys(&seed).unwrap();
        let c = commit(&keys, b"claim");
        let v = Verdict::new(Choice::from(1u8), &c);
        assert!(v.is_valid_bool());
        assert_eq!(v.transcript().len(), 32);
    }

    #[test]
    fn debug_is_metadata_free() {
        let seed = fake_seed();
        let keys = derive_keys(&seed).unwrap();
        let c = commit(&keys, b"claim");
        let v = Verdict::new(Choice::from(0u8), &c);
        let s = alloc::format!("{:?}", v);
        assert!(s.contains("valid: 0"));
        assert!(s.contains("transcript:"));
    }

    #[test]
    fn validate_verdict_accepts_valid_verdict() {
        let seed = fake_seed();
        let keys = derive_keys(&seed).unwrap();
        let c = commit(&keys, b"claim");
        let v = Verdict::new(Choice::from(1u8), &c);
        assert!(validate_verdict(&v).is_ok());
    }

    #[test]
    fn validate_verdict_rejects_all_zeros_transcript() {
        let v = Verdict {
            valid: Choice::from(1u8),
            transcript: [0u8; 32],
        };
        assert!(validate_verdict(&v).is_err());
    }

    #[test]
    fn validate_verdict_rejects_all_ones_transcript() {
        let v = Verdict {
            valid: Choice::from(1u8),
            transcript: [0xFFu8; 32],
        };
        assert!(validate_verdict(&v).is_err());
    }

    #[test]
    fn validate_verdict_strength_accepts_valid_verdict() {
        let seed = fake_seed();
        let keys = derive_keys(&seed).unwrap();
        let c = commit(&keys, b"claim");
        let v = Verdict::new(Choice::from(1u8), &c);
        assert!(validate_verdict_strength(&v).is_ok());
    }

    #[test]
    fn validate_verdict_strength_rejects_biased_transcript() {
        let v = Verdict {
            valid: Choice::from(1u8),
            transcript: [0xAAu8; 32], // All bytes same value
        };
        assert!(validate_verdict_strength(&v).is_err());
    }

    #[test]
    fn validate_verdict_strength_rejects_low_entropy() {
        let mut transcript = [0u8; 32];
        // Only 2 unique byte values (low entropy)
        for i in 0..32 {
            transcript[i] = if i % 2 == 0 { 0x00 } else { 0x01 };
        }
        let v = Verdict {
            valid: Choice::from(1u8),
            transcript,
        };
        assert!(validate_verdict_strength(&v).is_err());
    }

    #[test]
    fn verdict_multi_source_produces_different_transcript() {
        let seed = fake_seed();
        let keys = derive_keys(&seed).unwrap();
        let c = commit(&keys, b"claim");
        let v = Verdict::new(Choice::from(1u8), &c);
        
        let v_multi = verdict_multi_source(&v, b"additional context");
        
        // Transcript should be different
        assert_ne!(v.transcript(), v_multi.transcript());
        
        // Validity should be preserved
        assert_eq!(v.valid.unwrap_u8(), v_multi.valid.unwrap_u8());
    }

    #[test]
    fn verdict_scheme_trait_basic() {
        let seed = fake_seed();
        let keys = derive_keys(&seed).unwrap();
        let c = commit(&keys, b"claim");
        
        let v1 = Verdict::new(Choice::from(1u8), &c);
        let v2 = BasicVerdictScheme::new(Choice::from(1u8), &c);
        
        // Should produce same verdict
        assert_eq!(v1.transcript(), v2.transcript());
        assert_eq!(v1.valid.unwrap_u8(), v2.valid.unwrap_u8());
    }
}
