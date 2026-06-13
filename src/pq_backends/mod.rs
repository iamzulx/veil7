//! Formal post-quantum signature backends.
//!
//! These provide direct access to RustCrypto PQ implementations with
//! deterministic key derivation and zeroize-on-drop hygiene.
//!
//! Privacy: verification returns `subtle::Choice` at public boundaries —
//! malformed inputs fail-closed without leaking diagnostic metadata.
//!
//! ## Current backends
//!
//! * `slh_dsa` — FIPS 205 SLH-DSA-SHAKE-128f (final, Aug 2024). Active.
//! * `fn_dsa` — FIPS 206 FN-DSA / FALCON (DRAFT, submitted 2025-08-28,
//!   final expected late 2026 / early 2027). **Scaffold** — type surface
//!   locked in, `verify` is a fail-closed no-op (`Choice::from(0)`) until
//!   a stable upstream crate is integrated. See `fn_dsa.rs` header for
//!   the activation checklist.

pub mod fn_dsa;
pub mod slh_dsa;
