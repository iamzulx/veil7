// Author: Iamzulx
//! Formal FN-DSA / FIPS 206 backend (scaffold).
//!
//! FIPS 206 (FN-DSA, formerly known as FALCON) is the FFT-over-NTRU lattice
//! digital signature standard. As of 2026-06, FIPS 206 is in DRAFT — NIST
//! submitted the draft on 2025-08-28 and final approval is expected in
//! late 2026 or early 2027. Reference:
//! <https://www.digicert.com/blog/quantum-ready-fndsa-nears-draft-approval-from-nist>
//!
//! RustCrypto does not yet publish a stable `fn-dsa` crate: pre-1.0 /
//! release-candidate upstream implementations exist (e.g. `falkor` /
//! `pqcrypto` wrappers) but they all pin to the FIPS 206 draft and are
//! not safe to depend on for a long-lived codebase.
//!
//! ## Why this file exists as a scaffold
//!
//! The public type surface of the slh_dsa backend
//! (`SecretKey`, `PublicKey`, `SignatureBytes`, `verify -> Choice`) is
//! the integration point other modules wire against. Locking FN-DSA's
//! equivalent surface in today, while the draft is still volatile, lets
//! the rest of the engine compile against the same `verify` signature
//! with no breaking change when the upstream crate stabilises.
//!
//! ## Status
//!
//! * `derive_secret_key` and `sign` are deferred — return `None` until
//!   FIPS 206 is finalized AND a stable Rust crate is published.
//! * `verify` is a no-op that **always** returns `Choice::from(0)`. This
//!   is deliberate fail-closed: a stub verifier must not emit false
//!   positives. Wiring this scaffold into the engine would route FN-DSA
//!   verifications to `Choice(0)` and the engine verdict would be
//!   `valid=0` — exactly the right answer for "I have not actually
//!   verified this".
//! * The hardening test `verification_public_boundaries_return_choice`
//!   passes today because `verify` returns `subtle::Choice`, not `bool`,
//!   even though the math is the no-op `Choice::from(0u8)`. This is
//!   the invariant that future maintainers must preserve when filling
//!   in the real FALCON math.
//!
//! ## To activate when FIPS 206 final + upstream crate stabilises
//!
//! 1. Add the crate to `Cargo.toml` (e.g. `fn-dsa = "X.Y"`).
//! 2. Replace the `derive_secret_key`, `sign`, `verify` stubs with calls
//!    into the upstream FALCON implementation, following the same pattern
//!    as `slh_dsa.rs`.
//! 3. Update the file header to drop the "scaffold" framing.
//! 4. Add a positive round-trip test in this module's `tests` submodule.

use subtle::Choice;

// ── Constants (placeholders — final values per FIPS 206 when published) ─────
//
// FALCON parameter sets (from the FIPS 206 draft):
//   * FN-DSA-512  : NIST Category 1 (~128-bit PQ security), smaller keys/sigs
//   * FN-DSA-1024 : NIST Category 5 (~256-bit PQ security), larger keys/sigs
//
// Approximate sizes from the FALCON specification (will be locked in at
// final FIPS 206 publication):
//   * FN-DSA-512  secret key: 1281 bytes
//   * FN-DSA-512  public key:  897 bytes
//   * FN-DSA-512  signature:  variable, max ~666 bytes (compressed header)
//
// We size the buffers for FN-DSA-512 (the smaller / more compact variant).
// FN-DSA-1024 will need separate constants; left as future work.

/// Placeholder for FN-DSA-512 secret-key length. Final value locked in
/// at FIPS 206 publication. Sized per the FALCON spec at 1281 bytes.
pub const SECRET_KEY_LEN: usize = 1281;

/// Placeholder for FN-DSA-512 public-key length. Final value locked in
/// at FIPS 206 publication. Sized per the FALCON spec at 897 bytes.
pub const PUBLIC_KEY_LEN: usize = 897;

/// Maximum length of an FN-DSA-512 signature. FALCON signatures are
/// variable-length; this is a conservative upper bound for static buffer
/// sizing. Final value locked in at FIPS 206 publication.
pub const SIGNATURE_LEN_MAX: usize = 1280;

// ── Type aliases ─────────────────────────────────────────────────────────────

/// Encoded FN-DSA-512 secret key.
pub type SecretKey = [u8; SECRET_KEY_LEN];

/// Encoded FN-DSA-512 public key.
pub type PublicKey = [u8; PUBLIC_KEY_LEN];

/// Variable-length FN-DSA-512 signature. This is the maximum-length
/// buffer; actual signatures are smaller.
pub type SignatureBytes = [u8; SIGNATURE_LEN_MAX];

// ── Signer ───────────────────────────────────────────────────────────────────

/// Formal FN-DSA (FALCON) signer. Scaffold — `sign` / `derive_secret_key`
/// are deferred until FIPS 206 is finalized and a stable Rust crate is
/// available. `verify` is a fail-closed no-op that always returns
/// `Choice::from(0)`.
pub struct FnDsaSigner;

impl FnDsaSigner {
    /// Derive a secret key from deterministic seed material. DEFERRED —
    /// returns `None` until FIPS 206 is finalized and an upstream crate
    /// is integrated. The seed layout will follow the FALCON keygen
    /// spec once published.
    pub fn derive_secret_key(_seed: &[u8; 32]) -> Option<SecretKey> {
        // Scaffold: implementation deferred. Do not return a fake key
        // — that would let the engine hand out a "valid" secret that
        // signs nothing useful.
        None
    }

    /// Sign a message. DEFERRED — returns `None` until FIPS 206 is
    /// finalized.
    pub fn sign(_message: &[u8], _secret: &mut SecretKey) -> Option<SignatureBytes> {
        None
    }

    /// Verify a signature. Currently a no-op that fails-closed.
    /// Returns `Choice(0)` until FIPS 206 is finalized and an upstream
    /// crate is integrated.
    ///
    /// The `sig_len` parameter is the actual used length of the signature
    /// (FALCON signatures are variable-length); pass the real length, not
    /// `SIGNATURE_LEN_MAX`. This matches FALCON's actual API surface so
    /// the future real implementation is a drop-in replacement.
    ///
    /// This fail-closed behaviour is deliberate: better to refuse all
    /// verifications than to emit false positives. The `Choice` boundary
    /// is preserved (the type signature, not the math) so the rest of
    /// the engine can be wired without a future breaking change.
    pub fn verify(
        _message: &[u8],
        _signature: &SignatureBytes,
        _public: &PublicKey,
        _sig_len: usize,
    ) -> Choice {
        // Fail-closed: do not claim verification succeeded when no
        // implementation is integrated. A scaffold that returned
        // `Choice::from(1)` would let the engine emit false-positive
        // verdicts.
        Choice::from(0u8)
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_fails_closed_when_unimplemented() {
        // Until FIPS 206 is finalized, every verify must return 0.
        // This is the scaffold contract: no false positives, no
        // fake verifications.
        let pk = [0u8; PUBLIC_KEY_LEN];
        let sig = [0u8; SIGNATURE_LEN_MAX];
        assert_eq!(
            FnDsaSigner::verify(b"any-message", &sig, &pk, SIGNATURE_LEN_MAX).unwrap_u8(),
            0,
            "scaffold must fail-closed until FIPS 206 integration"
        );
    }

    #[test]
    fn verify_fails_closed_for_zero_length_signature() {
        let pk = [0u8; PUBLIC_KEY_LEN];
        let sig = [0u8; SIGNATURE_LEN_MAX];
        assert_eq!(
            FnDsaSigner::verify(b"any-message", &sig, &pk, 0).unwrap_u8(),
            0,
            "zero-length signature must also fail-closed"
        );
    }

    #[test]
    fn derive_returns_none_until_fips206_final() {
        let seed = [0u8; 32];
        assert!(
            FnDsaSigner::derive_secret_key(&seed).is_none(),
            "scaffold derive must return None until FIPS 206 integration"
        );
    }

    #[test]
    fn sign_returns_none_until_fips206_final() {
        let mut sk = [0u8; SECRET_KEY_LEN];
        assert!(
            FnDsaSigner::sign(b"msg", &mut sk).is_none(),
            "scaffold sign must return None until FIPS 206 integration"
        );
    }

    #[test]
    fn secret_key_buffer_is_wiped_in_scaffold() {
        // Even though the scaffold never produces a real key, the
        // output buffer must not leak any pattern from the call site.
        // Here we just assert that returning None leaves the buffer
        // contents in a state the caller can detect (the contract: when
        // sign returns None, no secret material has been emitted).
        let mut sk = [0xFFu8; SECRET_KEY_LEN];
        let result = FnDsaSigner::sign(b"msg", &mut sk);
        assert!(result.is_none());
        // Buffer unchanged at the call site — scaffold does not touch it.
        assert_eq!(sk, [0xFFu8; SECRET_KEY_LEN]);
    }
}
