//! Domain-separation tags.
//!
//! Distinct constants prevent cross-protocol collisions in the single SHAKE256
//! sponge used throughout the engine. Every place that absorbs into SHAKE256
//! prefixes one of these tags so two different protocol steps can never produce
//! the same digest from coincidentally-equal inputs.

// ── Legacy ML-DSA pipeline (L1..L7) ──────────────────────────────────────────
pub const ENTROPY_STRETCH: &[u8] = b"veil7:L1:entropy-stretch:v1";
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
