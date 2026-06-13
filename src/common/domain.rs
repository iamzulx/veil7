//! Domain-separation tags.
//!
//! Distinct constants prevent cross-protocol collisions in the single SHAKE256
//! sponge used throughout the engine. Every place that absorbs into SHAKE256
//! prefixes one of these tags so two different protocol steps can never produce
//! the same digest from coincidentally-equal inputs.

// ── Legacy ML-DSA pipeline (L1..L7) ──────────────────────────────────────────
/// Per-iteration full entropy stretch (L1 mix step 1: harvest → SHAKE256).
pub const ENTROPY_MIX: &[u8] = b"veil7:L1:entropy-mix:v1";
/// Per-iteration slice-and-rehash (L1 mix step 2: slice half → SHAKE256).
pub const ENTROPY_FOLD: &[u8] = b"veil7:L1:entropy-fold:v1";
/// Final pool uniformization (L1 mix step 3: XOR-folded pool → SHAKE256).
pub const ENTROPY_FINALIZE: &[u8] = b"veil7:L1:entropy-finalize:v1";
pub const KEM_SEED: &[u8] = b"veil7:L2:kem-seed:v1";
pub const SIG_SEED: &[u8] = b"veil7:L2:sig-seed:v1";
pub const KEM_ENCAP_COINS: &[u8] = b"veil7:L2:kem-encap-coins:v1";
pub const COMMITMENT: &[u8] = b"veil7:L3:commitment:v1";
pub const TRANSCRIPT: &[u8] = b"veil7:L7:transcript:v1";

// ── Fiat-Shamir transcript (common::transcript) ──────────────────────────────
/// Initial protocol binding absorbed by `Transcript::new`.
pub const FS_PROTOCOL: &[u8] = b"veil7:fs:protocol:v1";
/// Frames an `absorb` operation.
pub const FS_ABSORB: &[u8] = b"veil7:fs:absorb:v1";
/// Frames a `challenge` derivation.
pub const FS_CHALLENGE: &[u8] = b"veil7:fs:challenge:v1";
/// Squeeze step that produces challenge bytes from the chained state.
pub const FS_SQUEEZE: &[u8] = b"veil7:fs:squeeze:v1";
/// Folds an emitted challenge back into the state (so the next op differs).
pub const FS_POST_CHALLENGE: &[u8] = b"veil7:fs:post-challenge:v1";

// ── Multi-method entropy sources (l1_entropy::harvest_multi_source) ─────────
// Each method's raw entropy is folded through SHAKE256 with its own domain
// tag before mixing. The tag is public; the raw input is private; SHAKE256
// is preimage-resistant, so the final pool's contribution from each method
// is one-way: an observer who knows all but one method's raw input cannot
// recover the missing input from the final seed (this is the
// "untraceability" property the engine requires from multi-source entropy).
pub const ENTROPY_SOURCE_OS_PRIMARY: &[u8] = b"veil7:L1:src:os-primary:v1";
pub const ENTROPY_SOURCE_OS_SECONDARY: &[u8] = b"veil7:L1:src:os-secondary:v1";
pub const ENTROPY_SOURCE_WALL_CLOCK: &[u8] = b"veil7:L1:src:wall-clock:v1";
pub const ENTROPY_SOURCE_STACK_ADDR: &[u8] = b"veil7:L1:src:stack-addr:v1";
pub const ENTROPY_SOURCE_THREAD_ID: &[u8] = b"veil7:L1:src:thread-id:v1";
pub const ENTROPY_SOURCE_HW_COUNTER: &[u8] = b"veil7:L1:src:hw-counter:v1";

// ── Tamper-evident chain (interface::attest_chain) ──────────────────────────
/// Initial protocol binding for the chained SHAKE256 accumulator.
pub const CHAIN_HEAD: &[u8] = b"veil7:chain:head:v1";
/// Per-step frame absorbed before each event in the chain.
pub const CHAIN_STEP: &[u8] = b"veil7:chain:step:v1";

// ── Relations ────────────────────────────────────────────────────────────────
/// Lamport-style hash one-time relation: secret leaf derivation.
pub const LAMPORT_SECRET: &[u8] = b"veil7:rel:lamport:secret:v1";
/// Lamport-style hash one-time relation: public node (= H(secret)).
pub const LAMPORT_PUBNODE: &[u8] = b"veil7:rel:lamport:pubnode:v1";

/// Merkle inclusion relation: leaf hashing (distinct tag from internal nodes to
/// prevent the second-preimage / node-as-leaf reinterpretation attack).
pub const MERKLE_LEAF: &[u8] = b"veil7:rel:merkle:leaf:v1";
/// Merkle inclusion relation: internal node hashing.
pub const MERKLE_NODE: &[u8] = b"veil7:rel:merkle:node:v1";
