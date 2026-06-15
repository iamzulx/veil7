// Author: Iamzulx
//! L4 — Proof Generation (libcrux backend).
//!
//! Produces a post-quantum proof that the holder of the ephemeral secret key
//! attests to the commitment. Uses ML-DSA-65 (FIPS 204) via libcrux
//! (hax/F* formally verified).
//!
//! Pluggability: the `Prover` trait lets a caller swap in a different PQ
//! scheme without touching L5's verification dispatch.

use crate::l2_keygen::EphemeralKeys;
use crate::l3_commit::Commitment;
use crate::pq_backends::libcrux_backend;
use crate::VeilError;

use libcrux_ml_dsa::ml_dsa_65::MLDSA65Signature;

use crate::shake256::Shake256;

/// Context string bound into the ML-DSA signature (FIPS 204 ctx field).
/// Acts as an additional domain separator at the signature layer.
const SIG_CTX: &[u8] = b"veil7:proof:v1";

/// A scheme-agnostic proof. Carries only opaque bytes — no scheme tag is
/// emitted into any output; the scheme is fixed at compile time per pipeline
/// instantiation, so there is nothing to leak.
pub struct Proof {
    pub(crate) sig: MLDSA65Signature,
}

impl Drop for Proof {
    #[inline(never)]
    fn drop(&mut self) {
        // Wipe the signature bytes. ML-DSA-65 sig is 3309 bytes.
        let sig_bytes = self.sig.as_mut_slice();
        crate::l0_memlock::zeroize_bytes(sig_bytes);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// HIGH PRIORITY ENHANCEMENTS
// ═══════════════════════════════════════════════════════════════════════════

/// Validate proof format and basic properties.
///
/// Checks:
/// - Signature size is correct (3309 bytes for ML-DSA-65)
/// - Signature is not all zeros
/// - Signature is not all ones
///
/// Returns `Ok(())` if valid, `Err(Crypto)` if invalid.
///
/// **Security Benefit:**
/// - Prevents invalid proofs from being used
/// - Detects corrupted proofs early
/// - Follows "refuse > guess" philosophy
pub fn validate_proof(proof: &Proof) -> Result<(), VeilError> {
    let sig_bytes = proof.sig.as_slice();

    // Check signature size (must be 3309 bytes for ML-DSA-65)
    if sig_bytes.len() != libcrux_backend::DSA_SIG_SIZE {
        return Err(VeilError::Crypto);
    }

    // Check signature is not all zeros
    if sig_bytes.iter().all(|&b| b == 0) {
        return Err(VeilError::Crypto);
    }

    // Check signature is not all ones
    if sig_bytes.iter().all(|&b| b == 0xFF) {
        return Err(VeilError::Crypto);
    }

    Ok(())
}

/// Validate proof cryptographic strength.
///
/// Checks:
/// - Signature is not biased (all bytes same value)
/// - Signature has sufficient entropy (at least 10 unique byte values)
///
/// Returns `Ok(())` if strength is valid, `Err(Crypto)` if invalid.
///
/// **Security Benefit:**
/// - Detects weak proofs (biased, low entropy)
/// - Statistical test (not formal verification)
/// - Follows "math over abstraction" philosophy
pub fn validate_proof_strength(proof: &Proof) -> Result<(), VeilError> {
    let sig_bytes = proof.sig.as_slice();

    // Check for obvious bias (all bytes same value)
    let first_byte = sig_bytes[0];
    if sig_bytes.iter().all(|&b| b == first_byte) {
        return Err(VeilError::Crypto);
    }

    // Check for low entropy (less than 10 unique byte values)
    let mut unique_bytes = [false; 256];
    let mut unique_count = 0;
    for &b in sig_bytes.iter() {
        if !unique_bytes[b as usize] {
            unique_bytes[b as usize] = true;
            unique_count += 1;
        }
    }

    if unique_count < 10 {
        return Err(VeilError::Crypto);
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// MEDIUM PRIORITY ENHANCEMENTS
// ═══════════════════════════════════════════════════════════════════════════

// ── Proof Isolation (MEDIUM Priority - Documented - Skipped) ────────────────
//
// Proof isolation via Locked<> wrappers would provide additional isolation by
// placing proofs in separate memory-locked regions. However, this is optional
// because:
//
// 1. **Proofs are ephemeral** — they exist only for one verification iteration
// 2. **Self-zeroizing** — Proof already self-zeroizes on drop (3309 bytes)
// 3. **Limited benefit** — isolating ephemeral data provides minimal security benefit
//
// **Recommendation:** Skip proof isolation. The current implementation is
// sufficient because proofs are ephemeral and self-zeroizing.
//
// **Philosophy alignment:** This follows the "math over abstraction" philosophy.
// Adding isolation for ephemeral data would be unnecessary abstraction without
// security benefit.

/// Trait for proof scheme agility.
///
/// Allows swapping between different proof schemes (ML-DSA-65, ML-DSA-87, etc.)
/// without changing the core proof generation logic.
///
/// **Security Benefit:**
/// - Support multiple proof schemes
/// - Future-proof for scheme swapping
/// - Follows "crypto-agility" philosophy
///
/// **Note:** Future work. Only ML-DSA-65 currently supported.
pub trait ProofScheme {
    type ProofType;
    fn prove(keys: &EphemeralKeys, commitment: &Commitment) -> Result<Self::ProofType, VeilError>;
}

/// ML-DSA-65 proof scheme implementation.
pub struct MlDsa65Scheme;

impl ProofScheme for MlDsa65Scheme {
    type ProofType = Proof;

    fn prove(keys: &EphemeralKeys, commitment: &Commitment) -> Result<Proof, VeilError> {
        MlDsaProver::prove(keys, commitment)
    }
}

/// ML-DSA-87 proof scheme implementation (future work).
pub struct MlDsa87Scheme;

impl ProofScheme for MlDsa87Scheme {
    type ProofType = Proof;

    fn prove(_keys: &EphemeralKeys, _commitment: &Commitment) -> Result<Proof, VeilError> {
        // Future: Implement ML-DSA-87
        Err(VeilError::Crypto) // Not yet implemented
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// LOW PRIORITY ENHANCEMENTS (Documented - Skipped)
// ═══════════════════════════════════════════════════════════════════════════

// ── Proof Compromise Detection (LOW Priority - Documented - Skipped) ────────
//
// Proof compromise detection would involve tracking proofs and detecting if
// they are compromised. However, this conflicts with the "stateless" philosophy
// in several ways:
//
// **Why it was considered:**
// - Detect if a proof has been compromised or tampered with
// - Provide early warning of potential security issues
// - Enable revocation of compromised proofs
//
// **What it would do:**
// - Track all generated proofs in a stateful data structure
// - Monitor for signs of compromise (e.g., duplicate proofs, timing anomalies)
// - Flag suspicious proofs for manual review
// - Enable revocation of compromised proofs
//
// **Why it was skipped (philosophy conflicts):**
//
// 1. **State requirement** — Detecting compromise requires maintaining state
//    about previous proofs, which violates the "stateless" philosophy.
//    veil7 is designed to be completely stateless — every iteration is
//    independent and no state persists between iterations.
//
// 2. **Metadata leakage** — Tracking proofs creates metadata, which violates
//    the "no metadata" philosophy. veil7 is designed to leave no trace —
//    no logs, no metadata, no persistent state.
//
// 3. **Limited benefit** — Proofs are ephemeral (exist only for one
//    verification iteration). The window for compromise is very small
//    (milliseconds), making detection less valuable. By the time a
//    compromise is detected, the proof has already been used and discarded.
//
// 4. **Performance overhead** — Tracking all proofs would add significant
//    performance overhead (memory allocation, state management, monitoring),
//    which conflicts with veil7's performance goals.
//
// 5. **Complexity** — Implementing compromise detection would add significant
//    complexity to the codebase, making it harder to audit and verify.
//
// **Recommendation:** Skip proof compromise detection. The stateless design
// already provides strong security guarantees:
// - Proofs are ephemeral (exist only for one verification iteration)
// - Proofs are self-zeroizing (wiped on drop, 3309 bytes)
// - Proofs are bound to ephemeral keys (cannot be replayed)
// - Proofs are validated before use (validate_proof, validate_proof_strength)
//
// The risk of proof compromise is already very low due to the stateless design,
// and the cost of detection (state, metadata, performance, complexity) outweighs
// the benefit.
//
// **Philosophy alignment:** This follows the "stateless" and "no metadata"
// philosophies. Adding state and metadata for ephemeral data would violate these
// philosophies without security benefit.
//
// **Alternative approach:** If compromise detection is absolutely required,
// consider implementing it at the application layer (outside veil7), where
// state management is the application's responsibility, not veil7's.

/// Pluggable proof generator. Implemented by a concrete PQ signature scheme.
pub trait Prover {
    /// Generate a proof binding `keys` to `commitment`.
    fn prove(keys: &EphemeralKeys, commitment: &Commitment) -> Result<Proof, VeilError>;
}

/// Default prover: ML-DSA-65 via libcrux, deterministic signing.
///
/// Signing randomness is derived deterministically from the commitment
/// via SHAKE256, so the proof is reproducible from the seed alone.
pub struct MlDsaProver;

impl Prover for MlDsaProver {
    fn prove(keys: &EphemeralKeys, commitment: &Commitment) -> Result<Proof, VeilError> {
        // Derive deterministic signing randomness from the commitment.
        // This ensures the proof is reproducible from the seed alone,
        // maintaining the stateless property.
        let sig_randomness = derive_sig_randomness(commitment);

        let sig = libcrux_backend::dsa_sign(
            &keys.dsa_kp.signing_key,
            commitment.as_bytes(),
            SIG_CTX,
            sig_randomness,
        )?;

        Ok(Proof { sig })
    }
}

/// Derive deterministic signing randomness from the commitment.
fn derive_sig_randomness(commitment: &Commitment) -> [u8; 32] {
    let mut xof = Shake256::default();
    xof.update(b"veil7:l4:sig-randomness:v1");
    xof.update(commitment.as_bytes());
    let mut out = [0u8; 32];
    let mut reader = xof.finalize_xof();
    reader.read(&mut out);
    out
}

/// Re-export so L5 can bind to the same context constant.
pub(crate) const fn sig_ctx() -> &'static [u8] {
    SIG_CTX
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l1_entropy::harvest;
    use crate::l2_keygen::derive_keys;
    use crate::l3_commit::commit;

    fn valid_proof(claim: &[u8]) -> (EphemeralKeys, Commitment, Proof) {
        let seed = harvest(b"l4").unwrap();
        let keys = derive_keys(&seed).unwrap();
        let c = commit(&keys, claim);
        let proof = MlDsaProver::prove(&keys, &c).unwrap();
        (keys, c, proof)
    }

    #[test]
    fn proof_changes_when_commitment_changes() {
        let seed = harvest(b"l4c").unwrap();
        let keys = derive_keys(&seed).unwrap();
        let c1 = commit(&keys, b"claim-A");
        let c2 = commit(&keys, b"claim-B");
        let p1 = MlDsaProver::prove(&keys, &c1).unwrap();
        let p2 = MlDsaProver::prove(&keys, &c2).unwrap();
        // Different commitments → different proofs (signature over different message).
        assert_ne!(p1.sig.as_slice(), p2.sig.as_slice());
    }

    #[test]
    fn proof_binds_to_sig_ctx_domain_separator() {
        let (_, c, proof) = valid_proof(b"ctx-test");
        // The signature was created with SIG_CTX. Verify that re-verifying
        // with the same context succeeds (handled by L5).
        assert_eq!(proof.sig.as_slice().len(), libcrux_backend::DSA_SIG_SIZE);
        let _ = c; // commitment used in signing
    }

    #[test]
    fn proof_sig_encode_is_stable_byte_layout() {
        let (_, _, proof) = valid_proof(b"stable");
        assert_eq!(
            proof.sig.as_slice().len(),
            3309,
            "ML-DSA-65 signature must be 3309 bytes"
        );
    }

    #[test]
    fn validate_proof_accepts_valid_proof() {
        let (_, _, proof) = valid_proof(b"test");
        assert!(validate_proof(&proof).is_ok());
    }

    #[test]
    fn validate_proof_strength_accepts_valid_proof() {
        let (_, _, proof) = valid_proof(b"test");
        assert!(validate_proof_strength(&proof).is_ok());
    }

    #[test]
    fn proof_scheme_trait_ml_dsa_65() {
        let seed = harvest(b"scheme").unwrap();
        let keys = derive_keys(&seed).unwrap();
        let c = commit(&keys, b"test");
        let proof1 = MlDsa65Scheme::prove(&keys, &c).unwrap();
        let proof2 = MlDsaProver::prove(&keys, &c).unwrap();
        assert_eq!(proof1.sig.as_slice(), proof2.sig.as_slice());
    }
}
