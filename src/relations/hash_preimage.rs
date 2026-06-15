// Author: Iamzulx
//! Hash-preimage relation — a Lamport one-time proof of knowledge, made
//! non-interactive with Fiat-Shamir.
//!
//! ## What is proven
//! Knowledge of a 32-byte master secret `w` whose derived Lamport public key is
//! the statement `x`. Concretely, for `i in 0..256` and `b in {0,1}`:
//!
//!   sk[i][b] = H( LAMPORT_SECRET ‖ w ‖ i ‖ b )         (secret leaves)
//!   pk[i][b] = H( LAMPORT_PUBNODE ‖ sk[i][b] )         (public key, = statement)
//!
//! The prover commits to the entire public key in a [`Transcript`], derives a
//! 256-bit challenge `c` from it (Fiat-Shamir), and reveals exactly one leaf per
//! position: `open[i] = sk[i][c_i]`. The verifier recomputes the challenge from
//! the same public key and checks `H(open[i]) == pk[i][c_i]` for every `i`.
//!
//! ## Why it is sound (pure math, ROM only)
//! Because `c` is derived *after* the full public key is fixed (the transcript
//! binds it), a prover cannot choose the public key to match a known set of
//! preimages for a predictable challenge. To answer an unpredictable 256-bit
//! challenge it must know a preimage of `pk[i][c_i]` at every position; a cheater
//! lacking the witness succeeds only by inverting SHAKE256 (preimage resistance)
//! or guessing the challenge (2^-256). Security rests solely on SHAKE256 being a
//! preimage-resistant random oracle — no number-theoretic assumption, hence
//! plausibly post-quantum.
//!
//! ## One-time caveat (satisfied by construction here)
//! A Lamport key must sign only ONE challenge; revealing openings for two
//! distinct challenges leaks the secret. veil7's stateless model regenerates the
//! witness every iteration, so each key answers exactly one challenge. Do not
//! reuse a witness across iterations.
//!
//! ## Status
//! Research/educational. Correct and tested, but unaudited — not for production.

extern crate alloc;
use alloc::vec::Vec;

use crate::common::{domain, Transcript, VeilError};
use crate::l0_memlock::zeroize_bytes;
use crate::relations::Relation;

use crate::shake256::Shake256;
use core::sync::atomic::{compiler_fence, Ordering};
use subtle::{Choice, ConstantTimeEq};

/// Number of challenge bits = number of Lamport positions.
const SECURITY_BITS: usize = 256;
/// Bytes per leaf / hash node.
const LEAF: usize = 32;
const CHALLENGE_BYTES: usize = SECURITY_BITS / 8;

/// Protocol label binding the transcript to this relation.
const PROTO: &[u8] = b"veil7:relation:lamport-hash-preimage:v1";

/// The Lamport public key: `pk[i] = [H(sk[i][0]), H(sk[i][1])]`.
pub struct Statement {
    pub pk: Vec<[[u8; LEAF]; 2]>, // len == SECURITY_BITS
}

/// The 32-byte master secret whose Lamport public key is the statement.
pub struct Witness {
    pub seed: [u8; LEAF],
}

impl Drop for Witness {
    #[inline(never)]
    fn drop(&mut self) {
        zeroize_bytes(&mut self.seed);
    }
}

/// One revealed leaf per position, selected by the challenge bit.
pub struct Proof {
    pub openings: Vec<[u8; LEAF]>, // len == SECURITY_BITS
}

impl Drop for Proof {
    #[inline(never)]
    fn drop(&mut self) {
        for opening in self.openings.iter_mut() {
            zeroize_bytes(opening);
        }
    }
}

/// SHAKE256 → 32 bytes, over a sequence of tagged chunks.
// SIDE-CHANNEL: T-table Keccak. Inputs here include the Lamport secret leaves
// (`sk[i][b] = H(LAMPORT_SECRET ‖ w ‖ i ‖ b)`). On shared-cache hardware an
// attacker can recover the per-leaf secret bytes. See SPEC-HARDENING.md
// §"Cache timing and T-table side channels". Risk class: HIGH (private witness).
fn h32(parts: &[&[u8]]) -> [u8; LEAF] {
    let mut xof = Shake256::default();
    for p in parts {
        xof.update(p);
    }
    let mut out = [0u8; LEAF];
    let mut reader = xof.finalize_xof();
    reader.read(&mut out);
    out
}

/// Derive a single secret leaf `sk[i][b]` from the witness seed.
fn derive_sk(seed: &[u8; LEAF], i: usize, b: u8) -> [u8; LEAF] {
    h32(&[
        domain::LAMPORT_SECRET,
        seed,
        &(i as u16).to_le_bytes(),
        &[b],
    ])
}

/// Public node from a secret leaf: `pk = H(sk)`.
fn pubnode(sk: &[u8; LEAF]) -> [u8; LEAF] {
    h32(&[domain::LAMPORT_PUBNODE, sk])
}

/// Bit `i` (LSB-first within each byte) of the challenge.
#[inline]
fn challenge_bit(c: &[u8; CHALLENGE_BYTES], i: usize) -> u8 {
    (c[i / 8] >> (i % 8)) & 1
}

/// Compact binding commitment over the whole public key, absorbed into the
/// transcript so the challenge depends on every pk byte.
// SIDE-CHANNEL: T-table Keccak. Absorbs only **public** statement bytes (the
// Lamport public key). The T-table access pattern leaks the pk, but pk is
// public by definition. See SPEC-HARDENING.md §"Cache timing and T-table side
// channels". Risk class: LOW (public input).
fn pk_commitment(stmt: &Statement) -> [u8; LEAF] {
    let mut xof = Shake256::default();
    xof.update(domain::LAMPORT_PUBNODE);
    xof.update(&(stmt.pk.len() as u64).to_le_bytes());
    for pair in &stmt.pk {
        xof.update(&pair[0]);
        xof.update(&pair[1]);
    }
    let mut out = [0u8; LEAF];
    let mut reader = xof.finalize_xof();
    reader.read(&mut out);
    out
}

/// The relation marker type.
pub struct HashPreimage;

impl Relation for HashPreimage {
    type Statement = Statement;
    type Witness = Witness;
    type Proof = Proof;

    fn protocol_label() -> &'static [u8] {
        PROTO
    }

    fn statement_from_witness(witness: &Witness) -> Statement {
        let mut pk = Vec::with_capacity(SECURITY_BITS);
        for i in 0..SECURITY_BITS {
            // Derive both leaves transiently, publish their hashes, wipe secrets.
            let mut sk0 = derive_sk(&witness.seed, i, 0);
            let mut sk1 = derive_sk(&witness.seed, i, 1);
            let p0 = pubnode(&sk0);
            let p1 = pubnode(&sk1);
            zeroize_bytes(&mut sk0);
            zeroize_bytes(&mut sk1);
            pk.push([p0, p1]);
        }
        Statement { pk }
    }

    fn bind_statement(stmt: &Statement, t: &mut Transcript) {
        let commit = pk_commitment(stmt);
        t.absorb(b"lamport:pk", &commit);
    }

    fn prove(
        witness: &Witness,
        _entropy: &[u8], // deterministic relation: entropy not required
    ) -> Result<(Statement, Proof), VeilError> {
        let stmt = Self::statement_from_witness(witness);

        let mut t = Transcript::new(PROTO);
        Self::bind_statement(&stmt, &mut t);
        let c: [u8; CHALLENGE_BYTES] = t.challenge_array(b"lamport:challenge");

        // Reveal exactly the challenged leaf at each position.
        let mut openings = Vec::with_capacity(SECURITY_BITS);
        for i in 0..SECURITY_BITS {
            let b = challenge_bit(&c, i);
            openings.push(derive_sk(&witness.seed, i, b));
        }
        Ok((stmt, Proof { openings }))
    }

    fn verify(stmt: &Statement, proof: &Proof) -> Result<Choice, VeilError> {
        // Malformed proof/statement -> reject (no panic, no oracle).
        if stmt.pk.len() != SECURITY_BITS || proof.openings.len() != SECURITY_BITS {
            // Side-channel hardening: a fence around the malformed-input
            // rejection so the early-return Choice is observable across
            // the function boundary (CVE-2026-23519-style fragility in
            // subtle's "best-effort" optimization barrier).
            compiler_fence(Ordering::SeqCst);
            let c = Choice::from(0u8);
            compiler_fence(Ordering::SeqCst);
            return Ok(c);
        }

        let mut t = Transcript::new(PROTO);
        Self::bind_statement(stmt, &mut t);
        let c: [u8; CHALLENGE_BYTES] = t.challenge_array(b"lamport:challenge");

        // Every position must check out; combine in constant time (no early exit).
        //
        // Side-channel hardening: compiler_fence(SeqCst) around the
        // initial Choice::from(1) and the returned `ok` so the
        // accumulator's final state is observable across the function
        // boundary regardless of any future LLVM optimization that
        // might try to fold the loop's AND-accumulator into a branch.
        compiler_fence(Ordering::SeqCst);
        let mut ok = Choice::from(1u8);
        for i in 0..SECURITY_BITS {
            let b = challenge_bit(&c, i) as usize;
            let recomputed = pubnode(&proof.openings[i]);
            ok &= recomputed.ct_eq(&stmt.pk[i][b]);
        }
        compiler_fence(Ordering::SeqCst);
        Ok(ok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn witness(byte: u8) -> Witness {
        Witness { seed: [byte; LEAF] }
    }

    #[test]
    fn honest_proof_verifies() {
        let w = witness(0x11);
        let (stmt, proof) = HashPreimage::prove(&w, &[]).unwrap();
        let ok = HashPreimage::verify(&stmt, &proof).unwrap();
        assert_eq!(ok.unwrap_u8(), 1, "honest prover must verify");
    }

    #[test]
    fn wrong_statement_fails() {
        // Prove with one witness, verify against a different witness's pk.
        let (_, proof) = HashPreimage::prove(&witness(0x11), &[]).unwrap();
        let other = HashPreimage::statement_from_witness(&witness(0x22));
        let ok = HashPreimage::verify(&other, &proof).unwrap();
        assert_eq!(
            ok.unwrap_u8(),
            0,
            "proof must not validate under another pk"
        );
    }

    #[test]
    fn tampered_opening_fails() {
        let w = witness(0x33);
        let (stmt, mut proof) = HashPreimage::prove(&w, &[]).unwrap();
        proof.openings[0][0] ^= 0xFF; // corrupt one revealed leaf
        let ok = HashPreimage::verify(&stmt, &proof).unwrap();
        assert_eq!(ok.unwrap_u8(), 0, "tampered opening must fail");
    }

    #[test]
    fn forged_opening_without_witness_fails() {
        // Attacker knows the public key (statement) but not the witness, and
        // tries to answer with zero leaves. Must fail with overwhelming prob.
        let stmt = HashPreimage::statement_from_witness(&witness(0x44));
        let forged = Proof {
            openings: alloc::vec![[0u8; LEAF]; SECURITY_BITS],
        };
        let ok = HashPreimage::verify(&stmt, &forged).unwrap();
        assert_eq!(ok.unwrap_u8(), 0, "forgery without preimages must fail");
    }

    #[test]
    fn wrong_length_proof_rejected() {
        let stmt = HashPreimage::statement_from_witness(&witness(0x55));
        let short = Proof {
            openings: alloc::vec![[0u8; LEAF]; 10],
        };
        let ok = HashPreimage::verify(&stmt, &short).unwrap();
        assert_eq!(ok.unwrap_u8(), 0, "malformed proof rejected, no panic");
    }

    #[test]
    fn proof_is_deterministic() {
        // Same witness -> same statement & openings (stateless reproducibility).
        let (s1, p1) = HashPreimage::prove(&witness(0x66), &[]).unwrap();
        let (s2, p2) = HashPreimage::prove(&witness(0x66), &[]).unwrap();
        assert_eq!(s1.pk, s2.pk);
        assert_eq!(p1.openings, p2.openings);
    }
}
