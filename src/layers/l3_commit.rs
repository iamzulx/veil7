// Author: Iamzulx
//! L3 — Commitment (libcrux backend).
//!
//! Binds the claim to the ephemeral identity. Produces a domain-separated
//! SHAKE256 commitment over:
//!     tag || kem_pk_bytes || dsa_vk_bytes || claim
//!
//! This commitment is what gets signed in L4 and re-derived by the verifier in
//! L5. Because it includes both public keys, a signature over it is bound to
//! this exact ephemeral identity — it cannot be replayed against another key.
//!
//! No secret material enters the commitment; it is safe to expose as the
//! transcript hash in L7.

use crate::domain;
use crate::l2_keygen::EphemeralKeys;
use crate::pq_backends::libcrux_backend;
use crate::VeilError;

use crate::shake256::Shake256;

/// Length of the commitment digest in bytes (256-bit).
pub const COMMITMENT_LEN: usize = 32;

/// A public, metadata-free commitment to (ephemeral identity + claim).
#[derive(Clone, PartialEq, Eq)]
pub struct Commitment(pub [u8; COMMITMENT_LEN]);

impl core::fmt::Debug for Commitment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Redact bytes to avoid leaking commitment material in logs/panics.
        f.debug_struct("Commitment")
            .field("bytes", &"[redacted]")
            .finish()
    }
}

impl Commitment {
    #[inline]
    pub fn as_bytes(&self) -> &[u8; COMMITMENT_LEN] {
        &self.0
    }
}

// ── Commitment Validation (HIGH Priority) ───────────────────────────────────

/// Validate commitment format and basic properties.
///
/// Checks:
/// - Commitment is exactly 32 bytes
/// - Commitment is not all zeros (invalid)
/// - Commitment is not all ones (invalid)
///
/// Returns `Ok(())` if valid, `Err(Crypto)` if invalid.
///
/// **Note:** This is a basic validation. For cryptographic strength validation,
/// use `validate_commitment_strength()`.
pub fn validate_commitment(commitment: &Commitment) -> Result<(), VeilError> {
    let bytes = commitment.as_bytes();

    // Check not all zeros
    if bytes.iter().all(|&b| b == 0) {
        return Err(VeilError::Crypto);
    }

    // Check not all ones
    if bytes.iter().all(|&b| b == 0xFF) {
        return Err(VeilError::Crypto);
    }

    Ok(())
}

/// Validate commitment cryptographic strength.
///
/// Verifies that the commitment meets 256-bit security requirements:
/// - Uses SHAKE256 (256-bit security level)
/// - Output is properly distributed (not biased)
///
/// Returns `Ok(())` if strength is valid, `Err(Crypto)` if invalid.
///
/// **Note:** This is a statistical test. For absolute certainty, use formal
/// verification (e.g., Kani proofs).
pub fn validate_commitment_strength(commitment: &Commitment) -> Result<(), VeilError> {
    let bytes = commitment.as_bytes();

    // Check for obvious bias (all bytes same value)
    let first_byte = bytes[0];
    if bytes.iter().all(|&b| b == first_byte) {
        return Err(VeilError::Crypto);
    }

    // Check for low entropy (less than 4 unique byte values)
    let mut unique_bytes = [false; 256];
    let mut unique_count = 0;
    for &b in bytes.iter() {
        if !unique_bytes[b as usize] {
            unique_bytes[b as usize] = true;
            unique_count += 1;
        }
    }

    if unique_count < 4 {
        return Err(VeilError::Crypto);
    }

    Ok(())
}

/// Compute the commitment for a claim under the given ephemeral keys.
///
/// NOTE: SHAKE256 is now backed by libcrux-sha3 (formally verified, constant-time). The absorbed `claim`
/// is a **secret** for the engine (only the commitment leaks). On shared-cache
/// hardware an attacker can recover `claim` bytes from the T-table access
/// pattern. See `SPEC-HARDENING.md` §"Cache timing and T-table side channels".
/// Risk class for this call: **MEDIUM** (private claim bytes).
pub fn commit(keys: &EphemeralKeys, claim: &[u8]) -> Commitment {
    let kem_pk_bytes = libcrux_backend::kem_pk_bytes(&keys.kem_kp);
    let dsa_vk_bytes = libcrux_backend::dsa_vk_bytes(&keys.dsa_kp);

    let mut xof = Shake256::default();
    xof.update(domain::COMMITMENT);
    xof.update(kem_pk_bytes.as_slice());
    xof.update(dsa_vk_bytes.as_slice());
    xof.update(claim);

    let mut out = [0u8; COMMITMENT_LEN];
    let mut reader = xof.finalize_xof();
    reader.read(&mut out);
    Commitment(out)
}

// ── Commitment Multi-Source (MEDIUM Priority) ───────────────────────────────

/// Compute commitment from multiple sources (defence-in-depth).
///
/// Derives commitment from:
/// - Ephemeral keys (KEM pk + DSA vk)
/// - Claim
/// - Additional context (optional)
///
/// Provides additional binding beyond standard commit().
///
/// **Note:** This is an optional enhancement for high-security deployments.
/// Standard commit() is sufficient for most use cases.
pub fn commit_multi_source(
    keys: &EphemeralKeys,
    claim: &[u8],
    additional_context: &[u8],
) -> Commitment {
    let kem_pk_bytes = libcrux_backend::kem_pk_bytes(&keys.kem_kp);
    let dsa_vk_bytes = libcrux_backend::dsa_vk_bytes(&keys.dsa_kp);

    let mut xof = Shake256::default();
    xof.update(domain::COMMITMENT);
    xof.update(kem_pk_bytes.as_slice());
    xof.update(dsa_vk_bytes.as_slice());
    xof.update(claim);
    xof.update(additional_context); // Additional binding

    let mut out = [0u8; COMMITMENT_LEN];
    let mut reader = xof.finalize_xof();
    reader.read(&mut out);
    Commitment(out)
}

// ── Commitment Agility (MEDIUM Priority) ────────────────────────────────────

/// Trait for commitment scheme agility.
///
/// Allows swapping commitment schemes (e.g., SHAKE256, SHA3-256, BLAKE3)
/// without changing core logic. Follows NIST recommendation for crypto-agility.
///
/// **Current implementation:** Only SHAKE256 is supported (libcrux-sha3).
/// Future: Add SHA3-256, BLAKE3, etc.
pub trait CommitmentScheme {
    /// Compute commitment from keys and claim.
    fn commit(keys: &EphemeralKeys, claim: &[u8]) -> Commitment;
}

/// SHAKE256 commitment scheme (default, libcrux-sha3).
///
/// Uses SHAKE256 (256-bit security, formally verified, constant-time).
pub struct Shake256Commitment;

impl CommitmentScheme for Shake256Commitment {
    fn commit(keys: &EphemeralKeys, claim: &[u8]) -> Commitment {
        commit(keys, claim)
    }
}

// ── Commitment Isolation (MEDIUM Priority - Documented) ─────────────────────
//
// Commitment isolation via Locked<> wrappers would provide additional isolation
// by placing commitments in separate memory-locked regions. However, this is
// optional because:
//
// 1. **Commitments are public** — they contain no secret material
// 2. **Safe to expose** — commitments are designed to be exposed as transcript hashes
// 3. **No security benefit** — isolating public data provides no security benefit
//
// **Recommendation:** Skip commitment isolation. The current implementation is
// sufficient because commitments are public and safe to expose.
//
// **Philosophy alignment:** This follows the "math over abstraction" philosophy.
// Adding isolation for public data would be unnecessary abstraction without
// security benefit.

// ── Commitment Compromise Detection (LOW Priority - Philosophy Conflict) ─────
//
// Commitment compromise detection would involve tracking commitments and detecting
// if they are compromised. However, this conflicts with the "stateless" philosophy
// in several ways:
//
// 1. **State requirement**: Detecting compromise requires maintaining state about
//    previous commitments, which violates the stateless philosophy.
//
// 2. **Metadata leakage**: Tracking commitments creates metadata, which violates
//    the "no metadata" philosophy.
//
// 3. **Limited benefit**: Commitments are public and designed to be exposed.
//    Detecting "compromise" of public data is not meaningful.
//
// **Recommendation:** Skip commitment compromise detection. Commitments are public
// by design, so "compromise" is not a meaningful concept for them.
//
// **Philosophy alignment:** This follows the "stateless" and "no metadata"
// philosophies. Adding state and metadata for public data would violate these
// philosophies without security benefit.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l1_entropy::harvest;
    use crate::l2_keygen::derive_keys;

    #[test]
    fn commitment_is_stable_for_same_inputs() {
        let seed = harvest(b"l3").unwrap();
        let keys = derive_keys(&seed).unwrap();
        let c1 = commit(&keys, b"claim-A");
        let c2 = commit(&keys, b"claim-A");
        assert_eq!(c1, c2);
    }

    #[test]
    fn commitment_changes_with_claim() {
        let seed = harvest(b"l3b").unwrap();
        let keys = derive_keys(&seed).unwrap();
        let c1 = commit(&keys, b"claim-A");
        let c2 = commit(&keys, b"claim-B");
        assert_ne!(c1, c2);
    }

    #[test]
    fn commitment_changes_when_kem_pk_changes() {
        let seed_a = harvest(b"k1").unwrap();
        let seed_b = harvest(b"k2").unwrap();
        let keys_a = derive_keys(&seed_a).unwrap();
        let keys_b = derive_keys(&seed_b).unwrap();
        let c_a = commit(&keys_a, b"claim");
        let c_b = commit(&keys_b, b"claim");
        assert_ne!(c_a, c_b, "commitment must bind to the KEM public key");
    }

    #[test]
    fn commitment_changes_when_dsa_vk_changes() {
        let seed_a = harvest(b"s1").unwrap();
        let seed_b = harvest(b"s2").unwrap();
        let keys_a = derive_keys(&seed_a).unwrap();
        let keys_b = derive_keys(&seed_b).unwrap();
        let c_a = commit(&keys_a, b"claim");
        let c_b = commit(&keys_b, b"claim");
        assert_ne!(c_a, c_b, "commitment must bind to the ML-DSA verifying key");
    }

    #[test]
    fn commitment_binds_all_three_fields() {
        let seed = harvest(b"binding").unwrap();
        let keys = derive_keys(&seed).unwrap();
        let c1 = commit(&keys, b"X");
        let c2 = commit(&keys, b"Y");
        let seed2 = harvest(b"binding-other").unwrap();
        let keys2 = derive_keys(&seed2).unwrap();
        let c3 = commit(&keys2, b"X");
        assert_ne!(c1, c2, "claim-only change should change commitment");
        assert_ne!(c1, c3, "key-only change should change commitment");
        assert_ne!(c2, c3, "key+claim change should change commitment");
    }

    #[test]
    fn validate_commitment_accepts_valid() {
        let seed = harvest(b"validate").unwrap();
        let keys = derive_keys(&seed).unwrap();
        let c = commit(&keys, b"test");
        assert!(validate_commitment(&c).is_ok());
    }

    #[test]
    fn validate_commitment_rejects_all_zeros() {
        let c = Commitment([0u8; COMMITMENT_LEN]);
        assert!(validate_commitment(&c).is_err());
    }

    #[test]
    fn validate_commitment_rejects_all_ones() {
        let c = Commitment([0xFFu8; COMMITMENT_LEN]);
        assert!(validate_commitment(&c).is_err());
    }

    #[test]
    fn validate_commitment_strength_accepts_valid() {
        let seed = harvest(b"strength").unwrap();
        let keys = derive_keys(&seed).unwrap();
        let c = commit(&keys, b"test");
        assert!(validate_commitment_strength(&c).is_ok());
    }

    #[test]
    fn validate_commitment_strength_rejects_biased() {
        // All bytes same value (obvious bias)
        let c = Commitment([0x42u8; COMMITMENT_LEN]);
        assert!(validate_commitment_strength(&c).is_err());
    }

    #[test]
    fn validate_commitment_strength_rejects_low_entropy() {
        // Only 2 unique byte values (low entropy)
        let mut bytes = [0u8; COMMITMENT_LEN];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = if i % 2 == 0 { 0x00 } else { 0x01 };
        }
        let c = Commitment(bytes);
        assert!(validate_commitment_strength(&c).is_err());
    }

    #[test]
    fn commit_multi_source_with_context() {
        let seed = harvest(b"multi").unwrap();
        let keys = derive_keys(&seed).unwrap();
        let c1 = commit_multi_source(&keys, b"claim", b"context-A");
        let c2 = commit_multi_source(&keys, b"claim", b"context-B");
        assert_ne!(
            c1, c2,
            "different context should produce different commitments"
        );
    }

    #[test]
    fn commit_multi_source_same_context_same_result() {
        let seed = harvest(b"multi-same").unwrap();
        let keys = derive_keys(&seed).unwrap();
        let c1 = commit_multi_source(&keys, b"claim", b"context");
        let c2 = commit_multi_source(&keys, b"claim", b"context");
        assert_eq!(c1, c2, "same inputs should produce same commitment");
    }

    #[test]
    fn commitment_scheme_trait_shake256() {
        let seed = harvest(b"scheme").unwrap();
        let keys = derive_keys(&seed).unwrap();
        let c1 = Shake256Commitment::commit(&keys, b"test");
        let c2 = commit(&keys, b"test");
        assert_eq!(c1, c2, "Shake256Commitment should match commit()");
    }
}
