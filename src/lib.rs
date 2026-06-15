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
#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

// ── Module groups ───────────────────────────────────────────────────────────
//
//   common/   foundational shared types (domain tags, error, transcript)
//   layers/   the verification layers L0..L7, numbered by data-flow position
//   pipeline  orchestrator that wires L1..L7 into one stateless iteration
//   relations/  NP-relation trait + concrete relations (hash preimage, merkle, ML-DSA)
//   pq_backends/  formal PQ signature backends (SLH-DSA, …)
//
pub mod blind;
pub mod chain;
pub mod commit_reveal;
pub mod common;
pub mod entropy_health;
pub mod entropy_sources;
pub mod execution;
pub mod hybrid;
pub mod keccak_ct;
pub mod layers;
pub mod pipeline;
pub mod pq_backends;
pub mod relations;
pub mod shake256;
pub mod shamir;
pub mod storage;
pub mod threshold;

#[cfg(feature = "std")]
pub mod interface;

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
pub use chain::ChainState;
pub use chain::{chain_root, chain_verify};
pub use entropy_sources::{
    hw_counter, os_csprng_primary, os_csprng_secondary, stack_addr, thread_id, wall_clock,
    EntropySource,
};
pub use layers::l7_emit::Verdict;
pub use pipeline::Claim;
pub use relations::merkle::{merkle_root, merkle_verify_path};

#[cfg(feature = "std")]
pub use l1_entropy::Seed;

#[cfg(feature = "std")]
pub use pipeline::{
    prove_and_verify, verify_batch, verify_once, verify_once_with, verify_once_with_oram,
    verify_once_with_vm,
};
pub use pipeline::{prove_and_verify_with_entropy, verify_once_with_seed};
