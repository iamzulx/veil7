//! Merkle inclusion relation — proof of set membership against a public root.
//!
//! Proves: "the value at position `index` is a member of the set whose Merkle
//! root is `root`." This is the canonical hash-based authentication structure
//! underpinning XMSS, SPHINCS+, and transparency logs. Adding it shows the
//! engine's universality reaching a *third* shape of statement — set membership
//! — distinct from preimage-knowledge ([`super::hash_preimage`]) and
//! signing-key-knowledge ([`super::ml_dsa`]).
//!
//! ## Construction
//!   leaf_hash(d)      = H( MERKLE_LEAF ‖ d )            (distinct domain tag)
//!   node_hash(l, r)   = H( MERKLE_NODE ‖ l ‖ r )        (distinct domain tag)
//!
//! Using different tags for leaves and internal nodes is the standard defense
//! against the second-preimage attack where an internal node is reinterpreted as
//! a leaf. Odd levels promote the lone trailing node unchanged to the next level
//! (no self-duplication, avoiding the CVE-2012-2459 class of ambiguity); the
//! prover and verifier apply the identical promotion rule so they always agree.
//!
//! ## Honesty / scope
//! This is an INCLUSION proof, not zero-knowledge: the authentication path and
//! the leaf are revealed. It proves membership, it does not hide the member.
//! Soundness rests on collision resistance of SHAKE256 (+ ROM for the transcript
//! binding), so it is plausibly post-quantum. Research/educational, unaudited.
extern crate alloc;
use alloc::vec::Vec;

use crate::common::{domain, Transcript, VeilError};
use crate::relations::Relation;

use crate::shake256::Shake256;
use core::sync::atomic::{compiler_fence, Ordering};
use subtle::{Choice, ConstantTimeEq};

const HASH: usize = 32;

/// Public statement: the Merkle root plus the leaf hash being proven present.
pub struct Statement {
    pub root: [u8; HASH],
    pub leaf: [u8; HASH],
}

/// Witness: the full ordered leaf set and the index claimed to be a member.
pub struct Witness {
    pub leaves: Vec<Vec<u8>>,
    pub index: usize,
}

impl Drop for Witness {
    #[inline(never)]
    fn drop(&mut self) {
        for leaf in self.leaves.iter_mut() {
            crate::l0_memlock::zeroize_bytes(leaf);
        }
    }
}

/// Proof: the authentication path (sibling hashes bottom-up) plus the public
/// position parameters needed to replay the level-reduction unambiguously.
pub struct Proof {
    pub siblings: Vec<[u8; HASH]>,
    pub index: usize,
    pub leaf_count: usize,
}

impl Drop for Proof {
    #[inline(never)]
    fn drop(&mut self) {
        for sib in self.siblings.iter_mut() {
            crate::l0_memlock::zeroize_bytes(sib);
        }
    }
}

fn h32(parts: &[&[u8]]) -> [u8; HASH] {
    // SIDE-CHANNEL: T-table Keccak. Absorbs only public Merkle node bytes.
    // See SPEC-HARDENING.md §"Cache timing and T-table side channels".
    // Risk class: LOW (public tree).
    let mut xof = Shake256::default();
    for p in parts {
        xof.update(p);
    }
    let mut out = [0u8; HASH];
    let mut reader = xof.finalize_xof();
    let _ = reader.read(&mut out);
    out
}

#[inline]
fn leaf_hash(data: &[u8]) -> [u8; HASH] {
    h32(&[domain::MERKLE_LEAF, data])
}

#[inline]
fn node_hash(left: &[u8; HASH], right: &[u8; HASH]) -> [u8; HASH] {
    h32(&[domain::MERKLE_NODE, left, right])
}

/// Hash all leaves into the base level. Empty input yields an empty level.
fn base_level(leaves: &[Vec<u8>]) -> Vec<[u8; HASH]> {
    leaves.iter().map(|d| leaf_hash(d)).collect()
}

/// Compute the root and the authentication path for `index` from a base level.
/// Promotion rule: a lone trailing node at an odd level carries up unchanged.
fn root_and_path(mut level: Vec<[u8; HASH]>, mut idx: usize) -> ([u8; HASH], Vec<[u8; HASH]>) {
    let mut path = Vec::new();
    while level.len() > 1 {
        let n = level.len();

        // Record the sibling for the current index at this level (if any).
        if idx == n - 1 && n % 2 == 1 {
            // promoted node: no sibling recorded
        } else if idx.is_multiple_of(2) {
            path.push(level[idx + 1]);
        } else {
            path.push(level[idx - 1]);
        }

        // Build the next level.
        let mut next = Vec::with_capacity(n.div_ceil(2));
        let mut i = 0;
        while i < n {
            if i + 1 < n {
                next.push(node_hash(&level[i], &level[i + 1]));
            } else {
                next.push(level[i]); // promote
            }
            i += 2;
        }
        idx /= 2;
        level = next;
    }
    let root = if level.is_empty() {
        [0u8; HASH]
    } else {
        level[0]
    };
    (root, path)
}

/// The relation marker type.
pub struct MerkleInclusion;

impl Relation for MerkleInclusion {
    type Statement = Statement;
    type Witness = Witness;
    type Proof = Proof;

    fn protocol_label() -> &'static [u8] {
        b"veil7:relation:merkle-inclusion:v1"
    }

    fn statement_from_witness(witness: &Witness) -> Statement {
        let base = base_level(&witness.leaves);
        if base.is_empty() || witness.index >= base.len() {
            return Statement {
                root: [0u8; HASH],
                leaf: [0u8; HASH],
            };
        }
        let leaf = base[witness.index];
        let (root, _) = root_and_path(base, witness.index);
        Statement { root, leaf }
    }

    fn bind_statement(stmt: &Statement, t: &mut Transcript) {
        t.absorb(b"merkle:root", &stmt.root);
        t.absorb(b"merkle:leaf", &stmt.leaf);
    }

    fn prove(witness: &Witness, _entropy: &[u8]) -> Result<(Statement, Proof), VeilError> {
        let base = base_level(&witness.leaves);
        if base.is_empty() || witness.index >= base.len() {
            return Err(VeilError::Crypto);
        }
        let leaf = base[witness.index];
        let leaf_count = base.len();
        let (root, siblings) = root_and_path(base, witness.index);
        Ok((
            Statement { root, leaf },
            Proof {
                siblings,
                index: witness.index,
                leaf_count,
            },
        ))
    }

    fn verify(stmt: &Statement, proof: &Proof) -> Result<Choice, VeilError> {
        if proof.leaf_count == 0 || proof.index >= proof.leaf_count {
            // Side-channel hardening: a fence around the malformed-input
            // rejection (CVE-2026-23519-style fragility).
            compiler_fence(Ordering::SeqCst);
            let c = Choice::from(0u8);
            compiler_fence(Ordering::SeqCst);
            return Ok(c);
        }

        // Replay the level reduction starting from the public leaf hash.
        // Side-channel hardening: compiler_fence(SeqCst) around the
        // accumulator and the final `ok & hash.ct_eq(...)` so the
        // final state is observable across the function boundary.
        compiler_fence(Ordering::SeqCst);
        let mut hash = stmt.leaf;
        let mut idx = proof.index;
        let mut n = proof.leaf_count;
        let mut used = 0usize;
        let mut ok = Choice::from(1u8);

        while n > 1 {
            if idx == n - 1 && n % 2 == 1 {
                // promoted node: hash carries up unchanged, no sibling consumed
            } else {
                match proof.siblings.get(used) {
                    Some(sib) => {
                        used += 1;
                        hash = if idx.is_multiple_of(2) {
                            node_hash(&hash, sib)
                        } else {
                            node_hash(sib, &hash)
                        };
                    }
                    None => {
                        ok = Choice::from(0u8); // path too short -> malformed
                        break;
                    }
                }
            }
            idx /= 2;
            n = n.div_ceil(2);
        }

        // Reject leftover siblings (path too long) and check the root, ct.
        if used != proof.siblings.len() {
            ok = Choice::from(0u8);
        }
        let result = ok & hash.ct_eq(&stmt.root);
        compiler_fence(Ordering::SeqCst);
        Ok(result)
    }
}

/// Pure-math Merkle root of a leaf slice. Empty input is rejected
/// (there is no tree to compute a root for).
///
/// No PQ, no entropy, no ephemeral identity — anyone with the same
/// leaves and the documented framing reproduces the same root. This is
/// the prover side of the Merkle inclusion relation, exposed as a
/// standalone helper so callers (e.g. `interface::attest_file_streaming`)
/// can compute a tree root without going through the full relation
/// pipeline.
pub fn merkle_root(leaves: &[&[u8]]) -> Result<[u8; 32], VeilError> {
    if leaves.is_empty() {
        return Err(VeilError::Crypto);
    }
    let base: Vec<[u8; HASH]> = leaves.iter().map(|d| leaf_hash(d)).collect();
    let (root, _path) = root_and_path(base, 0);
    Ok(root)
}

/// Pure-math Merkle inclusion-path verification. Returns `Choice::from(1)`
/// if `leaf` authenticates against `root` at position `index` under the
/// sibling path, `Choice::from(0)` otherwise.
///
/// This is the verifier side of the Merkle inclusion relation, exposed
/// standalone so auditors can check certificate-transparency / log
/// inclusion proofs without the engine, without keys, without side
/// effects. Same `Choice` contract as [`crate::chain::chain_verify`].
pub fn merkle_verify_path(
    leaf: &[u8; HASH],
    root: &[u8; HASH],
    index: usize,
    siblings: &[[u8; HASH]],
    leaf_count: usize,
) -> Choice {
    if leaf_count == 0 || index >= leaf_count {
        return Choice::from(0u8);
    }
    let mut hash = *leaf;
    let mut idx = index;
    let mut n = leaf_count;
    let mut used = 0usize;
    let mut ok = Choice::from(1u8);
    while n > 1 {
        if idx == n - 1 && n % 2 == 1 {
            // promoted node: hash carries up unchanged
        } else {
            match siblings.get(used) {
                Some(sib) => {
                    used += 1;
                    hash = if idx.is_multiple_of(2) {
                        node_hash(&hash, sib)
                    } else {
                        node_hash(sib, &hash)
                    };
                }
                None => {
                    ok = Choice::from(0u8);
                    break;
                }
            }
        }
        idx /= 2;
        n = n.div_ceil(2);
    }
    if used != siblings.len() {
        ok = Choice::from(0u8);
    }
    ok & hash.ct_eq(root)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<Vec<u8>> {
        (0..n).map(|i| alloc::vec![i as u8; 8]).collect()
    }

    #[test]
    fn honest_inclusion_verifies_all_indices_power_of_two() {
        let ls = leaves(8);
        for idx in 0..8 {
            let w = Witness {
                leaves: ls.clone(),
                index: idx,
            };
            let (stmt, proof) = MerkleInclusion::prove(&w, &[]).unwrap();
            let ok = MerkleInclusion::verify(&stmt, &proof).unwrap();
            assert_eq!(ok.unwrap_u8(), 1, "index {idx} must verify");
        }
    }

    #[test]
    fn honest_inclusion_verifies_odd_tree() {
        // 5 leaves exercises the promotion path at multiple levels.
        let ls = leaves(5);
        for idx in 0..5 {
            let w = Witness {
                leaves: ls.clone(),
                index: idx,
            };
            let (stmt, proof) = MerkleInclusion::prove(&w, &[]).unwrap();
            let ok = MerkleInclusion::verify(&stmt, &proof).unwrap();
            assert_eq!(ok.unwrap_u8(), 1, "odd-tree index {idx} must verify");
        }
    }

    #[test]
    fn single_leaf_tree() {
        let w = Witness {
            leaves: leaves(1),
            index: 0,
        };
        let (stmt, proof) = MerkleInclusion::prove(&w, &[]).unwrap();
        assert_eq!(stmt.root, stmt.leaf, "single leaf: root == leaf");
        assert_eq!(
            MerkleInclusion::verify(&stmt, &proof).unwrap().unwrap_u8(),
            1
        );
    }

    #[test]
    fn tampered_root_fails() {
        let w = Witness {
            leaves: leaves(8),
            index: 3,
        };
        let (mut stmt, proof) = MerkleInclusion::prove(&w, &[]).unwrap();
        stmt.root[0] ^= 0xFF;
        assert_eq!(
            MerkleInclusion::verify(&stmt, &proof).unwrap().unwrap_u8(),
            0
        );
    }

    #[test]
    fn tampered_sibling_fails() {
        let w = Witness {
            leaves: leaves(8),
            index: 3,
        };
        let (stmt, mut proof) = MerkleInclusion::prove(&w, &[]).unwrap();
        proof.siblings[0][0] ^= 0xFF;
        assert_eq!(
            MerkleInclusion::verify(&stmt, &proof).unwrap().unwrap_u8(),
            0
        );
    }

    #[test]
    fn wrong_index_fails() {
        // A path for index 3 should not validate when claimed at index 4.
        let w = Witness {
            leaves: leaves(8),
            index: 3,
        };
        let (stmt, mut proof) = MerkleInclusion::prove(&w, &[]).unwrap();
        proof.index = 4;
        assert_eq!(
            MerkleInclusion::verify(&stmt, &proof).unwrap().unwrap_u8(),
            0
        );
    }

    #[test]
    fn out_of_range_rejected() {
        let w = Witness {
            leaves: leaves(4),
            index: 9,
        };
        assert!(MerkleInclusion::prove(&w, &[]).is_err());
    }

    #[test]
    fn path_length_mismatch_fails() {
        let w = Witness {
            leaves: leaves(8),
            index: 0,
        };
        let (stmt, mut proof) = MerkleInclusion::prove(&w, &[]).unwrap();
        proof.siblings.push([0u8; HASH]); // too long
        assert_eq!(
            MerkleInclusion::verify(&stmt, &proof).unwrap().unwrap_u8(),
            0
        );
    }

    // ── merkle_root / merkle_verify_path (pure-math helpers) ────────────────
    // The standalone helpers must agree with the relation's prover and
    // verifier. This is the contract that lets the streaming file attest
    // build a root and the audit side verify a path without going through
    // the full relation pipeline.

    #[test]
    fn merkle_root_helper_matches_relation_statement() {
        let ls: Vec<Vec<u8>> = (0..8u8).map(|i| alloc::vec![i; 4]).collect();
        let leaf_refs: Vec<&[u8]> = ls.iter().map(|l| l.as_slice()).collect();
        let helper_root = super::merkle_root(&leaf_refs).expect("non-empty");
        let w = Witness {
            leaves: ls.clone(),
            index: 0,
        };
        let (stmt, _proof) = MerkleInclusion::prove(&w, &[]).unwrap();
        assert_eq!(
            helper_root, stmt.root,
            "merkle_root helper must equal relation's statement.root"
        );
    }

    #[test]
    fn merkle_verify_path_helper_matches_relation_verifier() {
        let ls: Vec<Vec<u8>> = (0..16u8).map(|i| alloc::vec![i; 4]).collect();
        for idx in 0..16 {
            let w = Witness {
                leaves: ls.clone(),
                index: idx,
            };
            let (stmt, proof) = MerkleInclusion::prove(&w, &[]).unwrap();
            let ok = super::merkle_verify_path(
                &stmt.leaf,
                &stmt.root,
                proof.index,
                &proof.siblings,
                proof.leaf_count,
            );
            assert_eq!(ok.unwrap_u8(), 1, "index {idx} must verify");
        }
    }

    #[test]
    fn merkle_verify_path_rejects_tampered_sibling() {
        let ls: Vec<Vec<u8>> = (0..4u8).map(|i| alloc::vec![i; 4]).collect();
        let w = Witness {
            leaves: ls,
            index: 0,
        };
        let (stmt, mut proof) = MerkleInclusion::prove(&w, &[]).unwrap();
        proof.siblings[0][0] ^= 0xFF;
        let ok = super::merkle_verify_path(
            &stmt.leaf,
            &stmt.root,
            proof.index,
            &proof.siblings,
            proof.leaf_count,
        );
        assert_eq!(ok.unwrap_u8(), 0, "tampered sibling must fail");
    }

    #[test]
    fn merkle_root_rejects_empty() {
        let empty: &[&[u8]] = &[];
        assert!(matches!(super::merkle_root(empty), Err(VeilError::Crypto)));
    }
}
