//! The seven verification layers (plus L0, the memory-locking primitive).
//!
//! Files are numbered by their position in the data flow, so reading order
//! matches execution order:
//!
//!   L0 memlock   — mlock'd, self-zeroising buffers (the only `unsafe` module)
//!   L1 entropy   — harvest OS entropy + jitter, stretch into a locked seed
//!   L2 keygen    — derive ephemeral ML-KEM-768 + ML-DSA-65 keys from the seed
//!   L3 commit    — SHAKE256 commitment binding identity + claim
//!   L4 prove     — PQ proof over the commitment (pluggable `Prover`)
//!   L5 verify    — universal verification (pluggable `Verifier`, constant-time)
//!   L6 zeroise   — explicit end-of-iteration secret-wipe barrier
//!   L7 emit      — traceless, metadata-free `Verdict`

pub mod l0_memlock;
pub mod l1_entropy;
pub mod l2_keygen;
pub mod l3_commit;
pub mod l4_prove;
pub mod l5_verify;
pub mod l6_zeroise;
pub mod l7_emit;
