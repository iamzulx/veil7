// Author: Iamzulx
// Copyright (c) 2026
// License: MIT
//! Pedersen-style commitment opening relation.
//!
//! Proves knowledge of a (value, blinding) pair that opens a SHAKE256
//! commitment. Unlike the [`HashPreimage`] relation which proves knowledge
//! of a seed for a Lamport key, this relation proves knowledge of the
//! two-part opening of a single commitment hash.
//!
//! ## What is proven
//! Knowledge of `(value, blinding)` such that:
//!
//!   C = SHAKE256( PEDERSEN_OPEN ‖ value ‖ blinding )
//!
//! where `C` is the public statement (the commitment).
//!
//! ## Why it is sound
//! The commitment `C` is a SHAKE256 digest. To produce a valid proof the
//! prover must supply `(value, blinding)` that hash to `C`. A cheater who
//! does not know the opening would need to find a preimage of `C`, which
//! requires inverting SHAKE256 — a 256-bit preimage-resistant function.
//! The Fiat-Shamir transcript binds the proof to the specific statement,
//! preventing replay across different commitments.
//!
//! ## Privacy note
//! The proof contains the full opening `(value, blinding)`. In veil7's
//! stateless model, the proof is verified within the same engine iteration
//! and never leaves the engine — only the `Verdict` (valid bit + transcript
//! hash) is emitted. The opening is wiped at the L6 barrier.
//!
//! ## Status
//! Research/educational. Correct and tested, but unaudited.

extern crate alloc;

use crate::common::{domain, Transcript, VeilError};
use crate::l0_memlock::zeroize_bytes;
use crate::relations::Relation;

use crate::shake256::Shake256;
use core::sync::atomic::{compiler_fence, Ordering};
use subtle::{Choice, ConstantTimeEq};

/// Bytes per component (value and blinding).
const COMPONENT: usize = 32;

/// Protocol label binding the transcript to this relation.
const PROTO: &[u8] = b"veil7:relation:pedersen-commitment:v1";

/// The commitment hash — the public statement.
pub struct Statement {
    pub commitment: [u8; COMPONENT],
}

/// The opening: value + blinding factor.
pub struct Witness {
    pub value: [u8; COMPONENT],
    pub blinding: [u8; COMPONENT],
}

impl Drop for Witness {
    #[inline(never)]
    fn drop(&mut self) {
        zeroize_bytes(&mut self.value);
        zeroize_bytes(&mut self.blinding);
    }
}

/// The proof: the revealed opening.
pub struct Proof {
    pub value: [u8; COMPONENT],
    pub blinding: [u8; COMPONENT],
}

impl Drop for Proof {
    #[inline(never)]
    fn drop(&mut self) {
        zeroize_bytes(&mut self.value);
        zeroize_bytes(&mut self.blinding);
    }
}

/// Compute the commitment: C = SHAKE256(PEDERSEN_OPEN || value || blinding).
// SIDE-CHANNEL: T-table Keccak. The absorbed material includes the blinding
// factor (secret). See SPEC-HARDENING.md §"Cache timing and T-table side
// channels". Risk class: HIGH (private witness material).
fn compute_commitment(value: &[u8; COMPONENT], blinding: &[u8; COMPONENT]) -> [u8; COMPONENT] {
    let mut xof = Shake256::default();
    xof.update(domain::PEDERSEN_OPEN);
    xof.update(value);
    xof.update(blinding);
    let mut out = [0u8; COMPONENT];
    let mut reader = xof.finalize_xof();
    reader.read(&mut out);
    out
}

/// The relation marker type.
pub struct PedersenCommitment;

impl Relation for PedersenCommitment {
    type Statement = Statement;
    type Witness = Witness;
    type Proof = Proof;

    fn protocol_label() -> &'static [u8] {
        PROTO
    }

    fn statement_from_witness(witness: &Witness) -> Statement {
        let commitment = compute_commitment(&witness.value, &witness.blinding);
        Statement { commitment }
    }

    fn bind_statement(stmt: &Statement, t: &mut Transcript) {
        t.absorb(b"pedersen:commitment", &stmt.commitment);
    }

    fn prove(
        witness: &Witness,
        _entropy: &[u8], // deterministic relation
    ) -> Result<(Statement, Proof), VeilError> {
        let stmt = Self::statement_from_witness(witness);

        // Build the Fiat-Shamir transcript to bind the proof to the statement.
        let mut t = Transcript::new(PROTO);
        Self::bind_statement(&stmt, &mut t);
        // Derive a binding challenge (not used in the proof directly, but
        // absorbed into the transcript so the verdict transcript is unique
        // to this specific commitment opening).
        let _challenge: [u8; 32] = t.challenge_array(b"pedersen:binding");

        // The proof IS the opening. In veil7's stateless model, the proof
        // never leaves the engine — only the Verdict is emitted.
        let proof = Proof {
            value: witness.value,
            blinding: witness.blinding,
        };

        Ok((stmt, proof))
    }

    fn verify(stmt: &Statement, proof: &Proof) -> Result<Choice, VeilError> {
        // Rebuild the Fiat-Shamir transcript (same as prove side).
        let mut t = Transcript::new(PROTO);
        Self::bind_statement(stmt, &mut t);
        let _challenge: [u8; 32] = t.challenge_array(b"pedersen:binding");

        // Recompute the commitment from the proof's opening.
        let recomputed = compute_commitment(&proof.value, &proof.blinding);

        // Constant-time comparison: does the recomputed commitment match?
        compiler_fence(Ordering::SeqCst);
        let ok = recomputed.ct_eq(&stmt.commitment);
        compiler_fence(Ordering::SeqCst);
        Ok(ok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_witness(v: u8, b: u8) -> Witness {
        Witness {
            value: [v; COMPONENT],
            blinding: [b; COMPONENT],
        }
    }

    #[test]
    fn honest_proof_verifies() {
        let w = test_witness(0x42, 0xAB);
        let (stmt, proof) = PedersenCommitment::prove(&w, &[]).unwrap();
        let ok = PedersenCommitment::verify(&stmt, &proof).unwrap();
        assert_eq!(ok.unwrap_u8(), 1, "honest prover must verify");
    }

    #[test]
    fn wrong_value_fails() {
        let w = test_witness(0x42, 0xAB);
        let (stmt, _proof) = PedersenCommitment::prove(&w, &[]).unwrap();
        // Tamper with the value in the proof.
        let bad_proof = Proof {
            value: [0x43; COMPONENT],
            blinding: [0xAB; COMPONENT],
        };
        let ok = PedersenCommitment::verify(&stmt, &bad_proof).unwrap();
        assert_eq!(ok.unwrap_u8(), 0, "wrong value must fail");
    }

    #[test]
    fn wrong_blinding_fails() {
        let w = test_witness(0x42, 0xAB);
        let (stmt, _proof) = PedersenCommitment::prove(&w, &[]).unwrap();
        let bad_proof = Proof {
            value: [0x42; COMPONENT],
            blinding: [0xAC; COMPONENT], // tampered blinding
        };
        let ok = PedersenCommitment::verify(&stmt, &bad_proof).unwrap();
        assert_eq!(ok.unwrap_u8(), 0, "wrong blinding must fail");
    }

    #[test]
    fn wrong_statement_fails() {
        let w = test_witness(0x42, 0xAB);
        let (_stmt, proof) = PedersenCommitment::prove(&w, &[]).unwrap();
        // Verify against a different commitment.
        let bad_stmt = Statement {
            commitment: [0xFF; COMPONENT],
        };
        let ok = PedersenCommitment::verify(&bad_stmt, &proof).unwrap();
        assert_eq!(ok.unwrap_u8(), 0, "wrong statement must fail");
    }

    #[test]
    fn deterministic_proof() {
        let w = test_witness(0x11, 0x22);
        let (stmt1, proof1) = PedersenCommitment::prove(&w, &[]).unwrap();
        let (stmt2, proof2) = PedersenCommitment::prove(&w, &[]).unwrap();
        assert_eq!(stmt1.commitment, stmt2.commitment);
        assert_eq!(proof1.value, proof2.value);
        assert_eq!(proof1.blinding, proof2.blinding);
    }

    #[test]
    fn different_witnesses_different_commitments() {
        let w1 = test_witness(0x01, 0x02);
        let w2 = test_witness(0x01, 0x03); // same value, different blinding
        let s1 = PedersenCommitment::statement_from_witness(&w1);
        let s2 = PedersenCommitment::statement_from_witness(&w2);
        assert_ne!(
            s1.commitment, s2.commitment,
            "different blinding must produce different commitment"
        );
    }

    #[test]
    fn statement_from_witness_matches_manual_compute() {
        let w = test_witness(0xAA, 0xBB);
        let stmt = PedersenCommitment::statement_from_witness(&w);
        let manual = compute_commitment(&w.value, &w.blinding);
        assert_eq!(stmt.commitment, manual);
    }

    #[test]
    fn protocol_label_is_unique() {
        // Must differ from other relations' protocol labels.
        assert_ne!(
            PROTO,
            crate::relations::hash_preimage::HashPreimage::protocol_label()
        );
        assert_ne!(
            PROTO,
            crate::relations::ml_dsa::MlDsaKnowledge::protocol_label()
        );
    }
}
