//! Fiat-Shamir transcript — a SHAKE256-backed public-coin random oracle.
//!
//! This is the heart of the non-interactive proof machinery. A prover and a
//! verifier each build an *identical* transcript by absorbing the same public
//! values in the same order; the challenge derived from that transcript is then
//! the same on both sides. No interaction, no stored state between calls.
//!
//! ## Why length-framing matters (Frozen Heart mitigation)
//! A naive transcript that just concatenates bytes into a hash is vulnerable to
//! ambiguity: `absorb("ab", "c")` and `absorb("a", "bc")` would feed identical
//! bytes to the sponge and collide. An attacker can exploit such collisions to
//! make a proof for one statement validate against another. We prevent this by
//! prefixing every label and every data blob with its little-endian length, so
//! the absorbed byte stream is an unambiguous encoding of the structured input.
//!
//! ## Chaining
//! Each `absorb`/`challenge` updates a running 64-byte `state`. A challenge is
//! `SHAKE256(SQUEEZE_TAG ‖ state ‖ label ‖ len)`, and immediately afterwards the
//! emitted challenge is folded back into `state` (`POST_CHALLENGE_TAG`). This
//! guarantees the transcript is *bound to its full history*: two protocols that
//! absorb different things, or the same things in a different order, can never
//! land on the same challenge.

use crate::common::domain;
use crate::shake256::Shake256;

const STATE_LEN: usize = 64;

/// A running, history-bound Fiat-Shamir transcript.
#[derive(Clone)]
pub struct Transcript {
    state: [u8; STATE_LEN],
}

impl Transcript {
    /// Start a transcript bound to a protocol label. Two protocols with
    /// different labels can never produce the same challenge stream.
    pub fn new(protocol_label: &[u8]) -> Self {
        // SIDE-CHANNEL: T-table Keccak. All `Transcript` absorbs are public.
        // See SPEC-HARDENING.md §"Cache timing and T-table side channels".
        // Risk class: LOW (public Fiat-Shamir).
        let mut xof = Shake256::default();
        xof.update(domain::FS_PROTOCOL);
        framed(&mut xof, protocol_label);
        let mut state = [0u8; STATE_LEN];
        let mut reader = xof.finalize_xof();
        let _ = reader.read(&mut state);
        Transcript { state }
    }

    /// Absorb a labelled public value into the transcript.
    ///
    /// Both `label` and `data` are length-framed, so the mapping from
    /// (label, data) to internal state is injective — no concatenation ambiguity.
    pub fn absorb(&mut self, label: &[u8], data: &[u8]) {
        // SIDE-CHANNEL: T-table Keccak; `data` here is the public value the
        // caller labelled. See SPEC-HARDENING.md §"Cache timing and T-table
        // side channels". Risk class: LOW (public transcript input).
        let mut xof = Shake256::default();
        xof.update(domain::FS_ABSORB);
        xof.update(&self.state);
        framed(&mut xof, label);
        framed(&mut xof, data);
        let mut next = [0u8; STATE_LEN];
        let mut reader = xof.finalize_xof();
        let _ = reader.read(&mut next);
        self.state = next;
    }

    /// Derive `out.len()` challenge bytes bound to everything absorbed so far,
    /// then fold the challenge back into the state so subsequent operations are
    /// distinct from this one.
    pub fn challenge(&mut self, label: &[u8], out: &mut [u8]) {
        // 1. Squeeze challenge bytes from the current chained state.
        // SIDE-CHANNEL: T-table Keccak; challenge is public. See
        // SPEC-HARDENING.md §"Cache timing and T-table side channels".
        // Risk class: LOW (public Fiat-Shamir output).
        let mut xof = Shake256::default();
        xof.update(domain::FS_SQUEEZE);
        xof.update(&self.state);
        framed(&mut xof, label);
        xof.update(&(out.len() as u64).to_le_bytes());
        let mut reader = xof.finalize_xof();
        let _ = reader.read(out);

        // 2. Fold the emitted challenge back into the state.
        let mut xof2 = Shake256::default();
        xof2.update(domain::FS_POST_CHALLENGE);
        xof2.update(&self.state);
        framed(&mut xof2, label);
        framed(&mut xof2, out);
        let mut next = [0u8; STATE_LEN];
        let mut reader2 = xof2.finalize_xof();
        let _ = reader2.read(&mut next);
        self.state = next;
    }

    /// Convenience: derive a fixed-size challenge array.
    pub fn challenge_array<const N: usize>(&mut self, label: &[u8]) -> [u8; N] {
        let mut out = [0u8; N];
        self.challenge(label, &mut out);
        out
    }
}

/// Absorb a length-framed byte string: `len(8 LE) ‖ bytes`.
#[inline]
fn framed(xof: &mut Shake256, bytes: &[u8]) {
    xof.update(&(bytes.len() as u64).to_le_bytes());
    xof.update(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_is_deterministic() {
        let mut a = Transcript::new(b"proto");
        let mut b = Transcript::new(b"proto");
        a.absorb(b"x", b"hello");
        b.absorb(b"x", b"hello");
        let ca: [u8; 32] = a.challenge_array(b"c");
        let cb: [u8; 32] = b.challenge_array(b"c");
        assert_eq!(ca, cb, "same inputs -> same challenge");
    }

    #[test]
    fn different_protocol_label_diverges() {
        let mut a = Transcript::new(b"proto-A");
        let mut b = Transcript::new(b"proto-B");
        let ca: [u8; 32] = a.challenge_array(b"c");
        let cb: [u8; 32] = b.challenge_array(b"c");
        assert_ne!(ca, cb, "protocol label must domain-separate");
    }

    #[test]
    fn different_absorbed_data_diverges() {
        let mut a = Transcript::new(b"p");
        let mut b = Transcript::new(b"p");
        a.absorb(b"x", b"alpha");
        b.absorb(b"x", b"beta");
        let ca: [u8; 32] = a.challenge_array(b"c");
        let cb: [u8; 32] = b.challenge_array(b"c");
        assert_ne!(ca, cb);
    }

    #[test]
    fn length_framing_prevents_concatenation_collision() {
        // The classic ambiguity: ("ab","c") vs ("a","bc"). Framing must split.
        let mut a = Transcript::new(b"p");
        let mut b = Transcript::new(b"p");
        a.absorb(b"ab", b"c");
        b.absorb(b"a", b"bc");
        let ca: [u8; 32] = a.challenge_array(b"c");
        let cb: [u8; 32] = b.challenge_array(b"c");
        assert_ne!(ca, cb, "length framing must disambiguate boundaries");
    }

    #[test]
    fn order_of_absorption_matters() {
        let mut a = Transcript::new(b"p");
        let mut b = Transcript::new(b"p");
        a.absorb(b"l", b"one");
        a.absorb(b"l", b"two");
        b.absorb(b"l", b"two");
        b.absorb(b"l", b"one");
        let ca: [u8; 32] = a.challenge_array(b"c");
        let cb: [u8; 32] = b.challenge_array(b"c");
        assert_ne!(ca, cb, "transcript must be order-sensitive");
    }

    #[test]
    fn successive_challenges_differ() {
        let mut t = Transcript::new(b"p");
        t.absorb(b"x", b"data");
        let c1: [u8; 32] = t.challenge_array(b"c");
        let c2: [u8; 32] = t.challenge_array(b"c");
        assert_ne!(c1, c2, "post-challenge fold must advance the state");
    }
}
