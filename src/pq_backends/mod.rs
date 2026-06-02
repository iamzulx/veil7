//! Formal post-quantum signature backends.
//!
//! These provide direct access to RustCrypto PQ implementations with
//! deterministic key derivation and zeroize-on-drop hygiene.
//!
//! Privacy: all backends return compact `bool`/`Option` at verification
//! boundaries — malformed inputs fail-closed without leaking diagnostic
//! metadata.

pub mod slh_dsa;
