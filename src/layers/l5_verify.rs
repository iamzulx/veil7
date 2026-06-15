//! L5 — Universal Verification (libcrux backend).
//!
//! The "universal" core: a scheme-agnostic `Verifier` trait that re-derives the
//! commitment independently and checks the proof against it. Pairing it with
//! the `Prover` trait from L4 means any PQ signature scheme can be slotted in
//! without changing the pipeline.
//!
//! Two independent checks must BOTH pass:
//!   1. PQ signature verifies over the re-derived commitment (ML-DSA-65, libcrux).
//!   2. PQ KEM round-trip succeeds: encapsulate to the ephemeral public key,
//!      decapsulate with the secret key, shared secrets match in constant time.
//!
//! The boolean result is combined with `subtle::Choice` to avoid early-exit
//! timing leaks between the two checks.

use crate::l2_keygen::EphemeralKeys;
use crate::l3_commit::{commit, Commitment};
use crate::l4_prove::{sig_ctx, Proof};
use crate::pq_backends::libcrux_backend;
use crate::VeilError;

use crate::shake256::Shake256;
use subtle::{Choice, ConstantTimeEq};

/// Pluggable verification scheme. Mirror of `Prover`.
pub trait Verifier {
    /// Verify `proof` attests to `claim` under `keys`. Returns a constant-time
    /// `Choice` (1 = valid, 0 = invalid) — never a short-circuiting bool.
    fn verify(keys: &EphemeralKeys, claim: &[u8], proof: &Proof) -> Result<Choice, VeilError>;
}

// ═══════════════════════════════════════════════════════════════════════════
// HIGH PRIORITY ENHANCEMENTS
// ═══════════════════════════════════════════════════════════════════════════

/// Validate verification result before use.
///
/// Checks:
/// - Result is valid (0 or 1)
///
/// Returns `Ok(())` if valid, `Err(Crypto)` if invalid.
///
/// **Security Benefit:**
/// - Prevents invalid verification results from being used
/// - Detects corrupted results early
/// - Follows "refuse > guess" philosophy
pub fn validate_verification_result(result: &Choice) -> Result<(), VeilError> {
    let value = result.unwrap_u8();
    
    // Check result is valid (0 or 1)
    if value != 0 && value != 1 {
        return Err(VeilError::Crypto);
    }
    
    Ok(())
}

/// Multi-check verification with defence-in-depth.
///
/// Performs multiple checks:
/// 1. Validate proof format and strength
/// 2. Standard verification (signature + KEM round-trip)
///
/// Returns `Choice` (1 = valid, 0 = invalid).
///
/// **Security Benefit:**
/// - Defence-in-depth (multiple checks)
/// - Detects invalid proofs early
/// - Follows "defence-in-depth" philosophy
pub fn verify_multi_check(
    keys: &EphemeralKeys,
    claim: &[u8],
    proof: &Proof,
) -> Result<Choice, VeilError> {
    // Check 1: Validate proof
    crate::l4_prove::validate_proof(proof)?;
    crate::l4_prove::validate_proof_strength(proof)?;
    
    // Check 2: Standard verification
    let standard_result = MlDsaVerifier::verify(keys, claim, proof)?;
    
    // Check 3: Validate verification result
    validate_verification_result(&standard_result)?;
    
    Ok(standard_result)
}

// ═══════════════════════════════════════════════════════════════════════════
// MEDIUM PRIORITY ENHANCEMENTS
// ═══════════════════════════════════════════════════════════════════════════

// ── Verification Isolation (MEDIUM Priority - Documented - Skipped) ─────────
//
// Verification isolation via Locked<> wrappers would provide additional isolation
// by placing verification results in separate memory-locked regions. However,
// this is optional because:
//
// 1. **Verification results are ephemeral** — they exist only for one iteration
// 2. **Small size** — verification result is small (1 byte)
// 3. **Limited benefit** — isolating ephemeral 1-byte data provides minimal security benefit
//
// **Recommendation:** Skip verification isolation. The current implementation is
// sufficient because verification results are ephemeral and small.
//
// **Philosophy alignment:** This follows the "math over abstraction" philosophy.
// Adding isolation for ephemeral 1-byte data would be unnecessary abstraction
// without security benefit.

/// Trait for verification scheme agility.
///
/// Allows swapping between different verification schemes (ML-DSA-65, ML-DSA-87, etc.)
/// without changing the core verification logic.
///
/// **Security Benefit:**
/// - Support multiple verification schemes
/// - Future-proof for scheme swapping
/// - Follows "crypto-agility" philosophy
///
/// **Note:** Future work. Only ML-DSA-65 currently supported.
pub trait VerificationScheme {
    type ProofType;
    fn verify(
        keys: &EphemeralKeys,
        claim: &[u8],
        proof: &Self::ProofType,
    ) -> Result<Choice, VeilError>;
}

/// ML-DSA-65 verification scheme implementation.
pub struct MlDsa65VerificationScheme;

impl VerificationScheme for MlDsa65VerificationScheme {
    type ProofType = Proof;
    
    fn verify(
        keys: &EphemeralKeys,
        claim: &[u8],
        proof: &Proof,
    ) -> Result<Choice, VeilError> {
        MlDsaVerifier::verify(keys, claim, proof)
    }
}

/// ML-DSA-87 verification scheme implementation (future work).
pub struct MlDsa87VerificationScheme;

impl VerificationScheme for MlDsa87VerificationScheme {
    type ProofType = Proof;
    
    fn verify(
        _keys: &EphemeralKeys,
        _claim: &[u8],
        _proof: &Proof,
    ) -> Result<Choice, VeilError> {
        // Future: Implement ML-DSA-87 verification
        Err(VeilError::Crypto) // Not yet implemented
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// LOW PRIORITY ENHANCEMENTS (Documented - Skipped)
// ═══════════════════════════════════════════════════════════════════════════

// ── Verification Compromise Detection (LOW Priority - Documented - Skipped) ─
//
// Verification compromise detection would involve tracking verifications and
// detecting if they are compromised. However, this conflicts with the
// "stateless" philosophy in several ways:
//
// **Why it was considered:**
// - Detect if a verification has been compromised or tampered with
// - Provide early warning of potential security issues
// - Enable revocation of compromised verifications
//
// **What it would do:**
// - Track all verification results in a stateful data structure
// - Monitor for signs of compromise (e.g., timing anomalies, unexpected patterns)
// - Flag suspicious verifications for manual review
// - Enable revocation of compromised verifications
//
// **Why it was skipped (philosophy conflicts):**
//
// 1. **State requirement** — Detecting compromise requires maintaining state
//    about previous verifications, which violates the "stateless" philosophy.
//    veil7 is designed to be completely stateless — every iteration is
//    independent and no state persists between iterations.
//
// 2. **Metadata leakage** — Tracking verifications creates metadata, which
//    violates the "no metadata" philosophy. veil7 is designed to leave no
//    trace — no logs, no metadata, no persistent state.
//
// 3. **Limited benefit** — Verification results are ephemeral (exist only
//    for one iteration). The window for compromise is very small (milliseconds),
//    making detection less valuable. By the time a compromise is detected,
//    the verification has already been completed and the result discarded.
//
// 4. **Performance overhead** — Tracking all verifications would add significant
//    performance overhead (memory allocation, state management, monitoring),
//    which conflicts with veil7's performance goals.
//
// 5. **Complexity** — Implementing compromise detection would add significant
//    complexity to the codebase, making it harder to audit and verify.
//
// **Recommendation:** Skip verification compromise detection. The stateless
// design already provides strong security guarantees:
// - Verification results are ephemeral (exist only for one iteration)
// - Verification results are small (1 byte, Choice)
// - Verification uses dual checks (signature + KEM round-trip)
// - Verification is constant-time (no timing leaks)
// - Verification results are validated (validate_verification_result)
//
// The risk of verification compromise is already very low due to the stateless
// design and dual checks, and the cost of detection (state, metadata, performance,
// complexity) outweighs the benefit.
//
// **Philosophy alignment:** This follows the "stateless" and "no metadata"
// philosophies. Adding state and metadata for ephemeral 1-byte data would
// violate these philosophies without security benefit.
//
// **Alternative approach:** If compromise detection is absolutely required,
// consider implementing it at the application layer (outside veil7), where
// state management is the application's responsibility, not veil7's.

/// Default verifier: ML-DSA-65 signature + ML-KEM-768 round-trip consistency.
/// Both via libcrux (hax/F* formally verified).
pub struct MlDsaVerifier;

impl Verifier for MlDsaVerifier {
    fn verify(keys: &EphemeralKeys, claim: &[u8], proof: &Proof) -> Result<Choice, VeilError> {
        // (1) Re-derive the commitment from scratch — verifier trusts nothing
        //     it was handed except the claim and the keys.
        let recommitment: Commitment = commit(keys, claim);

        // (2) PQ signature check over the re-derived commitment (libcrux).
        let sig_ok: bool = libcrux_backend::dsa_verify(
            &keys.dsa_kp.verification_key,
            recommitment.as_bytes(),
            sig_ctx(),
            &proof.sig,
        )
        .is_ok();

        // (3) PQ KEM round-trip: derive deterministic encapsulation coins from
        //     the commitment so this step is reproducible and bound to the
        //     transcript, then check decapsulation matches (libcrux).
        let kem_ok = kem_roundtrip(keys, &recommitment)?;

        // Combine in constant time — no early exit between the two checks.
        let result = {
            use core::sync::atomic::{compiler_fence, Ordering};
            compiler_fence(Ordering::SeqCst);
            let sig_choice = Choice::from(sig_ok as u8);
            compiler_fence(Ordering::SeqCst);
            let combined = sig_choice & kem_ok;
            compiler_fence(Ordering::SeqCst);
            combined
        };
        Ok(result)
    }
}

/// Encapsulate to the ephemeral KEM public key using deterministic coins
/// derived from the commitment, then decapsulate with the secret key and check
/// the two shared secrets are equal in constant time.
///
/// Uses libcrux (hax/F* verified) for both encapsulate and decapsulate.
fn kem_roundtrip(keys: &EphemeralKeys, commitment: &Commitment) -> Result<Choice, VeilError> {
    // Derive 32-byte encapsulation coins from the commitment.
    // SIDE-CHANNEL: T-table Keccak. `commitment` is a public value, `m` is a
    // derived encapsulation coin. Both are public by construction. See
    // SPEC-HARDENING.md §"Cache timing and T-table side channels".
    // Risk class: LOW (public values).
    let mut xof = Shake256::default();
    xof.update(crate::domain::KEM_ENCAP_COINS);
    xof.update(commitment.as_bytes());
    let mut m = [0u8; 32];
    let mut reader = xof.finalize_xof();
    reader.read(&mut m);

    // Encapsulate (deterministic) -> (ciphertext, shared secret sender side).
    let (ct, ss_send) = libcrux_backend::kem_encapsulate(keys.kem_kp.public_key(), m);

    // Decapsulate with the secret key -> shared secret receiver side.
    let ss_recv = libcrux_backend::kem_decapsulate(keys.kem_kp.private_key(), &ct);

    // Constant-time comparison of the two 32-byte shared secrets.
    Ok(ss_send.as_slice().ct_eq(ss_recv.as_slice()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l1_entropy::harvest;
    use crate::l2_keygen::derive_keys;
    use crate::l4_prove::{MlDsaProver, Prover};

    fn valid_setup(claim: &[u8]) -> (EphemeralKeys, Proof) {
        let seed = harvest(b"l5").unwrap();
        let keys = derive_keys(&seed).unwrap();
        let c = crate::l3_commit::commit(&keys, claim);
        let proof = MlDsaProver::prove(&keys, &c).unwrap();
        (keys, proof)
    }

    #[test]
    fn valid_proof_verifies() {
        let (keys, proof) = valid_setup(b"hello");
        let ok = MlDsaVerifier::verify(&keys, b"hello", &proof).unwrap();
        assert_eq!(ok.unwrap_u8(), 1);
    }

    #[test]
    fn wrong_claim_fails() {
        let (keys, proof) = valid_setup(b"hello");
        let ok = MlDsaVerifier::verify(&keys, b"goodbye", &proof).unwrap();
        assert_eq!(ok.unwrap_u8(), 0, "tampered claim must fail");
    }

    #[test]
    fn tampered_signature_fails() {
        let (keys, mut proof) = valid_setup(b"hello");
        // Corrupt one byte of the signature.
        let sig_bytes = proof.sig.as_slice();
        let mut corrupted = [0u8; libcrux_backend::DSA_SIG_SIZE];
        corrupted.copy_from_slice(sig_bytes);
        corrupted[0] ^= 0xFF;
        proof.sig = libcrux_ml_dsa::ml_dsa_65::MLDSA65Signature::new(corrupted);
        let ok = MlDsaVerifier::verify(&keys, b"hello", &proof).unwrap();
        assert_eq!(ok.unwrap_u8(), 0, "tampered signature must fail");
    }

    #[test]
    fn verify_accumulates_constant_time_even_with_signature_failure() {
        let (keys, mut proof) = valid_setup(b"hello");
        let sig_bytes = proof.sig.as_slice();
        let mut corrupted = [0u8; libcrux_backend::DSA_SIG_SIZE];
        corrupted.copy_from_slice(sig_bytes);
        corrupted[0] ^= 0xFF;
        proof.sig = libcrux_ml_dsa::ml_dsa_65::MLDSA65Signature::new(corrupted);

        for claim in &[
            b"hello" as &[u8],
            b"",
            b"\x00\xff\x80",
            b"a-longer-claim-for-variety",
        ] {
            let ok = MlDsaVerifier::verify(&keys, claim, &proof).unwrap();
            assert_eq!(
                ok.unwrap_u8(),
                0,
                "tampered signature must yield 0 for any claim"
            );
        }
    }

    #[test]
    fn kem_roundtrip_legitimate_path_produces_matching_secrets() {
        let seed = harvest(b"l5legit").unwrap();
        let keys = derive_keys(&seed).unwrap();
        let c = crate::l3_commit::commit(&keys, b"hello");

        // Reproduce the KEM round-trip from the verifier.
        let mut xof = Shake256::default();
        xof.update(crate::domain::KEM_ENCAP_COINS);
        xof.update(c.as_bytes());
        let mut m = [0u8; 32];
        xof.finalize_xof().read(&mut m);

        let (ct, ss_send) = libcrux_backend::kem_encapsulate(keys.kem_kp.public_key(), m);
        let ss_recv = libcrux_backend::kem_decapsulate(keys.kem_kp.private_key(), &ct);

        assert_eq!(
            ss_send.as_slice().ct_eq(ss_recv.as_slice()).unwrap_u8(),
            1,
            "legitimate KEM round-trip must produce matching shared secrets"
        );
    }

    #[test]
    fn validate_verification_result_accepts_valid_result() {
        let valid_choice = Choice::from(1);
        assert!(validate_verification_result(&valid_choice).is_ok());
        
        let invalid_choice = Choice::from(0);
        assert!(validate_verification_result(&invalid_choice).is_ok());
    }

    #[test]
    fn verify_multi_check_valid_proof() {
        let (keys, proof) = valid_setup(b"hello");
        let ok = verify_multi_check(&keys, b"hello", &proof).unwrap();
        assert_eq!(ok.unwrap_u8(), 1);
    }

    #[test]
    fn verification_scheme_trait_ml_dsa_65() {
        let (keys, proof) = valid_setup(b"test");
        let ok1 = MlDsa65VerificationScheme::verify(&keys, b"test", &proof).unwrap();
        let ok2 = MlDsaVerifier::verify(&keys, b"test", &proof).unwrap();
        assert_eq!(ok1.unwrap_u8(), ok2.unwrap_u8());
    }
}
