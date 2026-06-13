//! Tamper-evident event chain — domain-separated SHAKE256 accumulator.
//!
//! This module is the engine-level realisation of USE_CASES.md §7
//! (Tamper-Evident Log Append). It folds a sequence of events through a
//! SHAKE256 running state with domain-separated framing and returns a
//! single 32-byte root. Tampering with any event in the chain changes the
//! root, so any pipeline that attests the root covers the whole sequence.
//!
//! The composition is pure SHAKE256 — no OS calls, no allocation, no
//! metadata — so this module is `no_std` available. The returned root is
//! a **public** anchor: it is reproducible by anyone holding the events,
//! and it is not a secret that needs wiping. Callers that subsequently
//! feed the root into the ML-DSA pipeline (e.g. `interface::attest_chain`)
//! get the root scrubbed at the engine's L6 barrier regardless.
//!
//! Two usage shapes are provided:
//! * [`chain_root`] — one-shot fold over a complete event slice.
//! * [`ChainState`] — incremental builder: absorb events one at a time,
//!   finalize to a root. Lets streaming sources (large files, network
//!   feeds) keep their event buffer bounded to one chunk.
//!
//! [`chain_root`]: crate::chain::chain_root

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use subtle::{Choice, ConstantTimeEq};

use crate::common::domain;
use crate::VeilError;

/// Fold `events` through the chain accumulator and return the 32-byte root.
///
/// Framing: `CHAIN_HEAD || CHAIN_STEP || e_0 || CHAIN_STEP || e_1 || …`.
/// The same framing is reproducible by anyone holding the events, so a
/// published root is independently verifiable without the engine.
///
/// Privacy:
/// * No event count, no event order, no per-event output leaks through the
///   returned root.
/// * The root is public — it is the chain anchor — so it is **not** wiped
///   on return. Callers that need it scrubbed (e.g. before exiting a
///   sensitive scope) should run `crate::l0_memlock::zeroize_bytes` on
///   their own copy.
/// * Empty input returns `VeilError::Crypto` — there is no chain to attest.
pub fn chain_root(events: &[&[u8]]) -> Result<[u8; 32], VeilError> {
    if events.is_empty() {
        return Err(VeilError::Crypto);
    }

    let mut xof = Shake256::default();
    xof.update(domain::CHAIN_HEAD);
    for ev in events {
        xof.update(domain::CHAIN_STEP);
        xof.update(ev);
    }
    let mut root = [0u8; 32];
    xof.finalize_xof().read(&mut root);
    Ok(root)
}

/// Verify that `events` folds to `expected_root` under the chain framing.
///
/// Returns `Choice::from(1)` if the chain root of `events` matches
/// `expected_root` byte-for-byte, `Choice::from(0)` otherwise (including
/// the empty-input case, since there is no chain to verify against).
///
/// Universal verification property: this is pure SHAKE256 math. No
/// post-quantum signature operation, no entropy, no ephemeral identity —
/// anyone with the events and the published root can verify offline
/// without the engine, without keys, without side effects. The same
/// function on the same inputs always returns the same `Choice`.
///
/// Use this for the audit side of USE_CASES.md §7 (Tamper-Evident Log
/// Append): given a stored root and a list of events, decide whether the
/// events have been tampered with.
pub fn chain_verify(events: &[&[u8]], expected_root: &[u8; 32]) -> Choice {
    match chain_root(events) {
        Ok(root) => root.ct_eq(expected_root),
        // Empty input has no chain root, so it cannot match any expected
        // root. Return 0 explicitly rather than branching on the empty case.
        Err(_) => Choice::from(0u8),
    }
}

/// Incremental builder for the chain accumulator.
///
/// Holds the running SHAKE256 state across many [`ChainState::absorb`]
/// calls and finalises into the same 32-byte root [`chain_root`] would
/// have produced for the full slice. Lets streaming callers (large files,
/// network feeds, anything that does not have all events in memory at
/// once) keep their buffer bounded to one chunk.
///
/// Privacy / statelessness:
/// * `ChainState` is a pure-math accumulator, not a cryptographic identity
///   — the engine itself stays stateless (no global, no static mut, no
///   cache). The state is local to a single call site and dies when the
///   builder is dropped.
/// * The finalised root is public (reproducible by anyone holding the
///   events) so it is not wiped; callers feeding it into the ML-DSA
///   pipeline get it scrubbed at the engine's L6 barrier.
/// * `absorb` itself never holds a key. It only extends the SHAKE256
///   sponge with `CHAIN_STEP || event` per event.
pub struct ChainState {
    xof: Shake256,
    count: usize,
}

impl ChainState {
    /// Start a new chain accumulator. The first event is absorbed under
    /// the same domain-tagged framing as every subsequent one; no
    /// events have been absorbed yet.
    pub fn new() -> Self {
        let mut xof = Shake256::default();
        xof.update(domain::CHAIN_HEAD);
        ChainState { xof, count: 0 }
    }

    /// Append one event to the running state. May be called any number of
    /// times; the order of `absorb` calls is cryptographically bound by
    /// the sponge's sequential absorb.
    pub fn absorb(&mut self, event: &[u8]) {
        self.xof.update(domain::CHAIN_STEP);
        self.xof.update(event);
        self.count += 1;
    }

    /// Finalise into the 32-byte root. Returns `VeilError::Crypto` if no
    /// events were absorbed (there is no chain to attest).
    pub fn finalize(self) -> Result<[u8; 32], VeilError> {
        if self.count == 0 {
            return Err(VeilError::Crypto);
        }
        let mut root = [0u8; 32];
        self.xof.finalize_xof().read(&mut root);
        Ok(root)
    }

    /// Number of events absorbed so far. Useful for the caller to decide
    /// whether to bother finalising; does not leak anything about event
    /// contents.
    pub fn len(&self) -> usize {
        self.count
    }

    /// True if no events have been absorbed yet.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for ChainState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_root_is_deterministic() {
        let events: &[&[u8]] = &[b"login:alice", b"read:/etc/passwd", b"logout:alice"];
        let r1 = chain_root(events).expect("non-empty");
        let r2 = chain_root(events).expect("non-empty");
        assert_eq!(r1, r2, "same events must produce the same root");
    }

    #[test]
    fn chain_root_changes_on_tamper() {
        let original: &[&[u8]] = &[b"a", b"b", b"c"];
        let tampered: &[&[u8]] = &[b"a", b"B", b"c"]; // case change in the middle
        let r1 = chain_root(original).expect("non-empty");
        let r2 = chain_root(tampered).expect("non-empty");
        assert_ne!(r1, r2, "single-bit change must avalanche the root");
    }

    #[test]
    fn chain_root_rejects_empty() {
        let empty: &[&[u8]] = &[];
        assert!(matches!(chain_root(empty), Err(VeilError::Crypto)));
    }

    #[test]
    fn chain_root_order_matters() {
        let ab: &[&[u8]] = &[b"a", b"b"];
        let ba: &[&[u8]] = &[b"b", b"a"];
        let r1 = chain_root(ab).expect("non-empty");
        let r2 = chain_root(ba).expect("non-empty");
        assert_ne!(r1, r2, "event order must be cryptographically bound");
    }

    // ── chain_verify ──────────────────────────────────────────────────────
    // Universal verification oracle: given events + a claimed root, return
    // 1 if they match, 0 if they don't (or if the events are empty). No
    // entropy, no PQ, no ephemeral identity — pure SHAKE256 math.

    #[test]
    fn chain_verify_matches_chain_root() {
        let events: &[&[u8]] = &[b"login", b"read", b"logout"];
        let root = chain_root(events).expect("non-empty");
        assert_eq!(
            chain_verify(events, &root).unwrap_u8(),
            1,
            "chain_verify(events, chain_root(events)) must be 1"
        );
    }

    #[test]
    fn chain_verify_detects_single_bit_tamper() {
        let original: &[&[u8]] = &[b"event-A", b"event-B", b"event-C"];
        let tampered: &[&[u8]] = &[b"event-A", b"event-B!", b"event-C"];
        let original_root = chain_root(original).expect("non-empty");
        let tampered_root = chain_root(tampered).expect("non-empty");
        assert_eq!(
            chain_verify(original, &original_root).unwrap_u8(),
            1,
            "untampered events verify against their own root"
        );
        assert_eq!(
            chain_verify(tampered, &original_root).unwrap_u8(),
            0,
            "tampered events must not verify against the original root"
        );
        // The tampered chain has its own root — it verifies against that,
        // proving chain_verify is testing mathematical membership, not
        // some global "good vs bad" property of the events themselves.
        assert_eq!(
            chain_verify(tampered, &tampered_root).unwrap_u8(),
            1,
            "tampered events verify against their own (different) root"
        );
    }

    #[test]
    fn chain_verify_rejects_empty_events() {
        let empty: &[&[u8]] = &[];
        let any_root = [0xABu8; 32];
        assert_eq!(
            chain_verify(empty, &any_root).unwrap_u8(),
            0,
            "empty events cannot verify against any root"
        );
    }

    #[test]
    fn chain_verify_rejects_wrong_root_length_is_not_a_panic_path() {
        // 32-byte root is the only legal input. Document the size contract:
        // a wrong-length slice would not compile because of the &[u8; 32]
        // type, but the call here proves the function stays pure (no panic,
        // no abort) for an arbitrary 32-byte pattern.
        let events: &[&[u8]] = &[b"only-one"];
        let root = chain_root(events).expect("non-empty");
        let mut garbage = root;
        garbage[0] ^= 0x01; // single bit flip in the expected root
        assert_eq!(
            chain_verify(events, &garbage).unwrap_u8(),
            0,
            "single bit flip in expected root must produce 0"
        );
    }

    // ── ChainState (streaming) ───────────────────────────────────────────────
    // The incremental builder must produce the same root as the one-shot
    // chain_root for the same event sequence. This is the contract that
    // lets streaming sources (large files, network feeds) keep their
    // event buffer bounded to one chunk.

    #[test]
    fn chain_state_matches_chain_root() {
        let events: &[&[u8]] = &[b"a", b"b", b"c", b"d"];
        let oneshot = chain_root(events).expect("non-empty");

        let mut state = ChainState::new();
        for ev in events {
            state.absorb(ev);
        }
        let streamed = state.finalize().expect("non-empty");

        assert_eq!(oneshot, streamed, "streaming and one-shot must agree");
    }

    #[test]
    fn chain_state_rejects_empty() {
        let state = ChainState::new();
        assert!(state.is_empty());
        assert_eq!(state.len(), 0);
        assert!(matches!(state.finalize(), Err(VeilError::Crypto)));
    }

    #[test]
    fn chain_state_order_matters() {
        let mut s1 = ChainState::new();
        s1.absorb(b"a");
        s1.absorb(b"b");
        let r1 = s1.finalize().expect("ok");

        let mut s2 = ChainState::new();
        s2.absorb(b"b");
        s2.absorb(b"a");
        let r2 = s2.finalize().expect("ok");

        assert_ne!(r1, r2, "absorb order must be cryptographically bound");
    }

    #[test]
    fn chain_state_default_constructor_works() {
        let mut s: ChainState = Default::default();
        s.absorb(b"x");
        assert_eq!(s.len(), 1);
        assert!(!s.is_empty());
        let r = s.finalize().expect("ok");
        let r2 = {
            let events: &[&[u8]] = &[b"x"];
            chain_root(events).expect("ok")
        };
        assert_eq!(r, r2, "default-constructed state matches one-shot");
    }
}
