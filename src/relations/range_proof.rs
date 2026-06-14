//! Range proof relation — prove a value is within [min, max] without revealing it.
//!
//! Proves: "I know a value `v` such that `min ≤ v ≤ max`" without revealing `v`.
//!
//! ## Construction
//! Bit-decomposition approach:
//! 1. Represent `(v - min)` as a k-bit number where `2^k > (max - min)`.
//! 2. Commit to each bit using a SHAKE256-based Pedersen-like commitment:
//!    `commit_i = SHAKE256(RANGE_BIT ‖ bit_i ‖ nonce_i)`
//! 3. The statement is the set of commitments plus the range parameters.
//! 4. The proof reveals the bits and nonces.
//! 5. The verifier checks:
//!    a. Each commitment matches: `SHAKE256(RANGE_BIT ‖ bit_i ‖ nonce_i) == commit_i`
//!    b. The reconstructed value is in range: `min ≤ Σ(bit_i · 2^i) + min ≤ max`
//!
//! ## Privacy note
//! Like the Pedersen relation, the proof reveals the witness (bits + nonces)
//! within the engine. Only the `Verdict` is emitted.
//!
//! ## Philosophy alignment
//! - **Math over abstraction**: bit-decomposition + hash commitments.
//! - **Silence over explanation**: invalid proofs return `Choice::from(0)`.

extern crate alloc;
use alloc::vec::Vec;

use crate::common::{domain, Transcript, VeilError};
use crate::l0_memlock::zeroize_bytes;
use crate::relations::Relation;

use crate::shake256::Shake256;
use core::sync::atomic::{compiler_fence, Ordering};
use subtle::{Choice, ConstantTimeEq};

const HASH: usize = 32;
const MAX_BITS: usize = 64; // support up to 64-bit ranges

const PROTO: &[u8] = b"veil7:relation:range-proof:v1";

/// Public statement: the bit commitments and range parameters.
pub struct Statement {
    pub commitments: Vec<[u8; HASH]>,
    pub min: u64,
    pub max: u64,
}

/// Secret witness: the value and per-bit nonces.
pub struct Witness {
    pub value: u64,
    pub min: u64,
    pub max: u64,
}

impl Drop for Witness {
    #[inline(never)]
    fn drop(&mut self) {
        // Zeroize secret u64 fields via byte-level volatile writes
        // (crate-level #![deny(unsafe_code)] prevents direct write_volatile
        // on u64; convert to bytes, wipe, then overwrite the field).
        let mut v_bytes = self.value.to_le_bytes();
        let mut min_bytes = self.min.to_le_bytes();
        let mut max_bytes = self.max.to_le_bytes();
        zeroize_bytes(&mut v_bytes);
        zeroize_bytes(&mut min_bytes);
        zeroize_bytes(&mut max_bytes);
        // Overwrite fields with zeros so any post-drop read sees 0.
        self.value = 0;
        self.min = 0;
        self.max = 0;
        compiler_fence(Ordering::SeqCst);
    }
}

/// Proof: the revealed bits and nonces.
pub struct Proof {
    pub bits: Vec<u8>,
    pub nonces: Vec<[u8; HASH]>,
}

impl Drop for Proof {
    #[inline(never)]
    fn drop(&mut self) {
        for bit in self.bits.iter_mut() {
            *bit = 0;
        }
        for nonce in self.nonces.iter_mut() {
            zeroize_bytes(nonce);
        }
    }
}

/// Compute a bit commitment: SHAKE256(RANGE_BIT ‖ bit ‖ nonce).
fn bit_commitment(bit: u8, nonce: &[u8; HASH]) -> [u8; HASH] {
    let mut xof = Shake256::default();
    xof.update(domain::RANGE_BIT);
    xof.update(&[bit & 1]);
    xof.update(nonce);
    let mut out = [0u8; HASH];
    let mut reader = xof.finalize_xof();
    reader.read(&mut out);
    out
}

/// The relation marker type.
pub struct RangeProof;

impl Relation for RangeProof {
    type Statement = Statement;
    type Witness = Witness;
    type Proof = Proof;

    fn protocol_label() -> &'static [u8] {
        PROTO
    }

    fn statement_from_witness(witness: &Witness) -> Statement {
        let range = witness.max.saturating_sub(witness.min);
        let num_bits = if range == 0 {
            1
        } else {
            64 - range.leading_zeros() as usize
        };
        let num_bits = num_bits.min(MAX_BITS);

        let offset = witness.value.wrapping_sub(witness.min);
        let mut commitments = Vec::with_capacity(num_bits);

        for i in 0..num_bits {
            let bit = ((offset >> i) & 1) as u8;
            // Deterministic nonce from value + bit position (pure-deterministic relation).
            let mut nonce = [0u8; HASH];
            let mut xof = Shake256::default();
            xof.update(b"veil7:range:nonce");
            xof.update(&witness.value.to_le_bytes());
            xof.update(&(i as u64).to_le_bytes());
            xof.update(&witness.min.to_le_bytes());
            let mut reader = xof.finalize_xof();
            reader.read(&mut nonce);

            commitments.push(bit_commitment(bit, &nonce));
        }

        Statement {
            commitments,
            min: witness.min,
            max: witness.max,
        }
    }

    fn bind_statement(stmt: &Statement, t: &mut Transcript) {
        t.absorb(b"range:min", &stmt.min.to_le_bytes());
        t.absorb(b"range:max", &stmt.max.to_le_bytes());
        t.absorb(
            b"range:nbits",
            &(stmt.commitments.len() as u64).to_le_bytes(),
        );
        for (i, c) in stmt.commitments.iter().enumerate() {
            t.absorb(b"range:commit", c);
            let _ = i; // absorbed in order
        }
    }

    fn prove(witness: &Witness, _entropy: &[u8]) -> Result<(Statement, Proof), VeilError> {
        // No early return on secret value — always generate a full proof
        // regardless of whether value is in range. This prevents timing
        // side channels that would leak the range membership of the secret.
        let stmt = Self::statement_from_witness(witness);
        let num_bits = stmt.commitments.len();
        let offset = witness.value.wrapping_sub(witness.min);

        let mut bits = Vec::with_capacity(num_bits);
        let mut nonces = Vec::with_capacity(num_bits);

        for i in 0..num_bits {
            let bit = ((offset >> i) & 1) as u8;
            bits.push(bit);

            let mut nonce = [0u8; HASH];
            let mut xof = Shake256::default();
            xof.update(b"veil7:range:nonce");
            xof.update(&witness.value.to_le_bytes());
            xof.update(&(i as u64).to_le_bytes());
            xof.update(&witness.min.to_le_bytes());
            let mut reader = xof.finalize_xof();
            reader.read(&mut nonce);
            nonces.push(nonce);
        }

        // Constant-time invalidation for out-of-range values:
        // Compute a mask that is 0x00 if value ∈ [min,max], 0xFF otherwise.
        // XOR the first nonce byte with this mask to guarantee verification
        // failure without branching on the secret value.
        let in_range_lo = (witness.value >= witness.min) as u8;
        let in_range_hi = (witness.value <= witness.max) as u8;
        let in_range = in_range_lo & in_range_hi;
        let corrupt = in_range.wrapping_sub(1); // 0 if in-range, 0xFF if out
        if let Some(first_nonce) = nonces.first_mut() {
            first_nonce[0] ^= corrupt;
        }

        Ok((stmt, Proof { bits, nonces }))
    }

    fn verify(stmt: &Statement, proof: &Proof) -> Result<Choice, VeilError> {
        let num_bits = stmt.commitments.len();

        if proof.bits.len() != num_bits || proof.nonces.len() != num_bits {
            compiler_fence(Ordering::SeqCst);
            let c = Choice::from(0u8);
            compiler_fence(Ordering::SeqCst);
            return Ok(c);
        }

        compiler_fence(Ordering::SeqCst);
        let mut ok = Choice::from(1u8);

        // Check each bit commitment.
        let mut reconstructed: u64 = 0;
        for i in 0..num_bits {
            let bit = proof.bits[i] & 1;
            let recomputed = bit_commitment(bit, &proof.nonces[i]);
            ok &= recomputed.ct_eq(&stmt.commitments[i]);

            // Reconstruct the value.
            reconstructed |= (bit as u64) << i;
        }

        // Check range: min ≤ reconstructed + min ≤ max.
        let value = reconstructed.saturating_add(stmt.min);
        let in_range = (value >= stmt.min) && (value <= stmt.max);
        ok &= Choice::from(in_range as u8);

        compiler_fence(Ordering::SeqCst);
        Ok(ok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_range_proof() {
        let w = Witness {
            value: 500,
            min: 0,
            max: 1000,
        };
        let (stmt, proof) = RangeProof::prove(&w, &[]).unwrap();
        let ok = RangeProof::verify(&stmt, &proof).unwrap();
        assert_eq!(ok.unwrap_u8(), 1);
    }

    #[test]
    fn value_at_min_boundary() {
        let w = Witness {
            value: 100,
            min: 100,
            max: 200,
        };
        let (stmt, proof) = RangeProof::prove(&w, &[]).unwrap();
        let ok = RangeProof::verify(&stmt, &proof).unwrap();
        assert_eq!(ok.unwrap_u8(), 1);
    }

    #[test]
    fn value_at_max_boundary() {
        let w = Witness {
            value: 200,
            min: 100,
            max: 200,
        };
        let (stmt, proof) = RangeProof::prove(&w, &[]).unwrap();
        let ok = RangeProof::verify(&stmt, &proof).unwrap();
        assert_eq!(ok.unwrap_u8(), 1);
    }

    #[test]
    fn value_below_min_fails_verification() {
        // C1 fix: prove() no longer branches on secret value.
        // wrapping_sub produces a large offset for below-min values,
        // so the reconstructed value will be out of range.
        let w = Witness {
            value: 50,
            min: 100,
            max: 200,
        };
        let (stmt, proof) = RangeProof::prove(&w, &[]).unwrap();
        let ok = RangeProof::verify(&stmt, &proof).unwrap();
        assert_eq!(ok.unwrap_u8(), 0, "below-min value must fail verification");
    }

    #[test]
    fn value_above_max_fails_verification() {
        // C1 fix: prove() no longer branches on secret value.
        // For value > max the clamped offset diverges from the
        // statement's offset, so commitment checks will reject.
        let w = Witness {
            value: 250,
            min: 100,
            max: 200,
        };
        let (stmt, proof) = RangeProof::prove(&w, &[]).unwrap();
        let ok = RangeProof::verify(&stmt, &proof).unwrap();
        assert_eq!(ok.unwrap_u8(), 0, "above-max value must fail verification");
    }

    #[test]
    fn tampered_bit_fails() {
        let w = Witness {
            value: 500,
            min: 0,
            max: 1000,
        };
        let (stmt, mut proof) = RangeProof::prove(&w, &[]).unwrap();
        // Flip a bit.
        proof.bits[0] ^= 1;
        let ok = RangeProof::verify(&stmt, &proof).unwrap();
        assert_eq!(ok.unwrap_u8(), 0, "tampered bit must fail");
    }

    #[test]
    fn deterministic_proof() {
        let w = Witness {
            value: 42,
            min: 0,
            max: 100,
        };
        let (s1, p1) = RangeProof::prove(&w, &[]).unwrap();
        let (s2, p2) = RangeProof::prove(&w, &[]).unwrap();
        assert_eq!(s1.commitments, s2.commitments);
        assert_eq!(p1.bits, p2.bits);
    }

    #[test]
    fn protocol_label_unique() {
        assert_ne!(
            PROTO,
            crate::relations::hash_preimage::HashPreimage::protocol_label()
        );
        assert_ne!(
            PROTO,
            crate::relations::pedersen::PedersenCommitment::protocol_label()
        );
    }
}
