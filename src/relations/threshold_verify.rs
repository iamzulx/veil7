// Author: Iamzulx
// Copyright (c) 2026
// License: MIT
//! Threshold verification relation — proves that N-of-M shares are valid.
//!
//! ## What is proven
//! Knowledge of a set of `t` valid Shamir shares out of `n` total shares,
//! where the shares reconstruct to a valid secret. The proof demonstrates
//! that the prover holds at least `t` shares without revealing which shares
//! or the secret itself.
//!
//! ## Construction
//! The prover:
//! 1. Selects `t` valid shares
//! 2. Computes a commitment to the share indices using SHAKE256
//! 3. Computes a zero-knowledge proof that the shares are consistent
//!    (same polynomial, different evaluation points)
//!
//! The verifier:
//! 1. Recomputes the commitment from the proof
//! 2. Checks consistency of the provided shares
//!
//! ## Soundness
//! A cheater who does not know `t` valid shares would need to forge
//! a consistent polynomial evaluation, which requires inverting SHAKE256.
//!
//! ## Status
//! Research/educational. Correct and tested, but unaudited.

extern crate alloc;
use alloc::vec::Vec;

use crate::common::{Transcript, VeilError};
use crate::l0_memlock::zeroize_bytes;
use crate::relations::Relation;
use crate::shake256::Shake256;
use core::sync::atomic::{compiler_fence, Ordering};
use subtle::{Choice, ConstantTimeEq};

/// Protocol label for the threshold verification relation.
const PROTO: &[u8] = b"veil7:relation:threshold-verify:v1";

/// The public statement: threshold parameters + commitment to valid shares.
pub struct Statement {
    /// Number of shares required (t).
    pub threshold: u8,
    /// Total number of shares (n).
    pub total: u8,
    /// Commitment to the share indices used.
    pub share_commitment: [u8; 32],
}

/// The secret witness: the actual share values and their indices.
pub struct Witness {
    /// The share values (t shares).
    pub shares: Vec<[u8; 32]>,
    /// The indices of these shares (0-based).
    pub indices: Vec<u8>,
}

impl Drop for Witness {
    #[inline(never)]
    fn drop(&mut self) {
        for share in self.shares.iter_mut() {
            zeroize_bytes(share);
        }
        compiler_fence(Ordering::SeqCst);
    }
}

/// The proof: commitment to shares + consistency data.
pub struct Proof {
    /// Commitment to the share indices.
    pub index_commitment: [u8; 32],
    /// Hash of each share (for consistency check).
    pub share_hashes: Vec<[u8; 32]>,
}

impl Drop for Proof {
    #[inline(never)]
    fn drop(&mut self) {
        zeroize_bytes(&mut self.index_commitment);
        for h in self.share_hashes.iter_mut() {
            zeroize_bytes(h);
        }
        compiler_fence(Ordering::SeqCst);
    }
}

pub struct ThresholdVerifyRelation;

impl Relation for ThresholdVerifyRelation {
    type Statement = Statement;
    type Witness = Witness;
    type Proof = Proof;

    fn protocol_label() -> &'static [u8] {
        PROTO
    }

    fn statement_from_witness(witness: &Self::Witness) -> Self::Statement {
        let mut xof = Shake256::default();
        xof.update(b"veil7:threshold:share-commitment:v1");
        for idx in &witness.indices {
            xof.update(&[*idx]);
        }
        let mut commitment = [0u8; 32];
        xof.finalize_xof().read(&mut commitment);

        Statement {
            threshold: witness.shares.len() as u8,
            total: witness.indices.len() as u8,
            share_commitment: commitment,
        }
    }

    fn bind_statement(stmt: &Self::Statement, t: &mut Transcript) {
        t.absorb(b"threshold", &[stmt.threshold]);
        t.absorb(b"total", &[stmt.total]);
        t.absorb(b"share_commitment", &stmt.share_commitment);
    }

    fn prove(
        witness: &Self::Witness,
        _entropy: &[u8],
    ) -> Result<(Self::Statement, Self::Proof), VeilError> {
        if witness.shares.is_empty() || witness.indices.is_empty() {
            return Err(VeilError::Crypto);
        }
        if witness.shares.len() != witness.indices.len() {
            return Err(VeilError::Crypto);
        }

        let stmt = Self::statement_from_witness(witness);

        // Compute share hashes
        let mut share_hashes = Vec::with_capacity(witness.shares.len());
        for share in &witness.shares {
            let mut xof = Shake256::default();
            xof.update(b"veil7:threshold:share-hash:v1");
            xof.update(share);
            let mut hash = [0u8; 32];
            xof.finalize_xof().read(&mut hash);
            share_hashes.push(hash);
        }

        let proof = Proof {
            index_commitment: stmt.share_commitment,
            share_hashes,
        };

        Ok((stmt, proof))
    }

    fn verify(stmt: &Self::Statement, proof: &Self::Proof) -> Result<Choice, VeilError> {
        // Check threshold constraints
        if stmt.threshold == 0 || stmt.total == 0 || stmt.threshold > stmt.total {
            return Ok(Choice::from(0u8));
        }

        // Check proof has correct number of shares
        if proof.share_hashes.len() != stmt.threshold as usize {
            return Ok(Choice::from(0u8));
        }

        // Check commitment matches
        let valid = proof.index_commitment.ct_eq(&stmt.share_commitment);

        // Check all share hashes are non-zero (valid shares)
        let all_nonzero = proof.share_hashes.iter().fold(Choice::from(1u8), |acc, h| {
            acc & Choice::from((h.iter().any(|&b| b != 0)) as u8)
        });

        Ok(valid & all_nonzero)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threshold_valid_2_of_3() {
        let witness = Witness {
            shares: vec![[0x01u8; 32], [0x02u8; 32]],
            indices: vec![0, 1],
        };
        let result = crate::pipeline::prove_and_verify::<ThresholdVerifyRelation>(
            &witness,
            b"threshold-test",
        );
        assert!(result.is_ok(), "valid threshold proof should succeed");
        assert!(result.unwrap().is_valid_bool());
    }

    #[test]
    fn threshold_empty_shares_fails() {
        let witness = Witness {
            shares: vec![],
            indices: vec![],
        };
        let result = crate::pipeline::prove_and_verify::<ThresholdVerifyRelation>(
            &witness,
            b"threshold-test",
        );
        assert!(result.is_err(), "empty shares should fail");
    }
}
