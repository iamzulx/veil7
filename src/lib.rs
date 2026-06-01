//! veil7 — stateless 7-layer universal post-quantum verification engine.
//!
//! Invariants (enforced by construction, not by policy):
//!   * NO LOG      — no logging crate is a dependency; nothing is ever written to stdout/stderr/files.
//!   * NO METADATA — verdicts carry a single bit + a transient public transcript hash, no IDs/timestamps/counters.
//!   * NO TRACE    — release profile: panic=abort, strip, no debuginfo. No global/static mutable state.
//!   * STATELESS   — every iteration derives everything from freshly harvested entropy; nothing persists.
//!   * POST-QUANTUM— ML-KEM-768 (FIPS 203) + ML-DSA-65 (FIPS 204) + SHAKE256.
//!   * AUTO-ZEROISE— all secrets wiped on Drop (ZeroizeOnDrop) AND explicitly at end of each iteration.
//!   * MEMORY-LOCK — owned seed material is mlock'd (no swap to disk) and wiped-then-unlocked on drop.
//
// `deny` rather than `forbid`: the entire engine is safe Rust EXCEPT the single
// `layers::l0_memlock` module, which needs raw mlock/munlock syscalls. That
// module opts back in with a narrowly-scoped `#![allow(unsafe_code)]` and is the
// only place `unsafe` may appear. Everywhere else, unsafe is a hard error.
#![deny(unsafe_code)]

// ── Module groups ───────────────────────────────────────────────────────────
//
//   common/   foundational shared types (domain tags, error)
//   layers/   the verification layers L0..L7, numbered by data-flow position
//   pipeline  orchestrator that wires L1..L7 into one stateless iteration
//
pub mod common;
pub mod layers;
pub mod pipeline;
pub mod relations;

// ── Compatibility bridges ─────────────────────────────────────────────────────
//
// The layers were grouped into `layers/` and shared types into `common/`, but
// internal code and the public API still address them by their short paths
// (`crate::l1_entropy`, `crate::domain`, `crate::VeilError`). These re-exports
// keep every existing path resolving, so grouping the files required no edits to
// the layer modules themselves. They are also the crate's stable public surface.
pub use common::domain;
pub use common::VeilError;

pub use layers::l0_memlock;
pub use layers::l1_entropy;
pub use layers::l2_keygen;
pub use layers::l3_commit;
pub use layers::l4_prove;
pub use layers::l5_verify;
pub use layers::l6_zeroise;
pub use layers::l7_emit;

// ── Primary public API ────────────────────────────────────────────────────────
pub use layers::l7_emit::Verdict;
pub use pipeline::{verify_once, Claim};
