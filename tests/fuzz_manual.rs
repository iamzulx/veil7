//! Manual fuzzing — deterministic random-input stress test without cargo-fuzz.
//!
//! Uses the OS CSPRNG to randomize inputs each run, but the test itself is
//! deterministic: it always starts with honest witnesses and always checks
//! the same invariants. Randomness only comes from input generation.
#![cfg(feature = "std")]

use veil7::l1_entropy::Seed;
use veil7::relations::{
    hash_preimage::{HashPreimage, Witness as HashWitness},
    merkle::{MerkleInclusion, Witness as MerkleWitness},
    ml_dsa::{MlDsaKnowledge, Witness as MlDsaWitness},
};
use veil7::{
    prove_and_verify, verify_once, verify_once_with_oram, verify_once_with_seed,
    verify_once_with_vm, Claim,
};

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).expect("entropy");
    buf
}

fn random_vec(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    getrandom::getrandom(&mut buf).expect("entropy");
    buf
}

#[test]
fn fuzz_verify_once_never_panics() {
    for i in 0..32usize {
        let payload = random_vec(16 + (i % 48));
        let claim = Claim::new(&payload);
        let _ = verify_once(&claim); // Result<_,_> is fine; panic is not.
    }
}

#[test]
fn fuzz_verify_once_with_oram_never_panics() {
    for i in 0..8usize {
        let payload = random_vec(16 + (i % 48));
        let claim = Claim::new(&payload);
        let _ = verify_once_with_oram(&claim);
    }
}

#[test]
fn fuzz_verify_once_with_vm_never_panics() {
    for i in 0..8usize {
        let payload = random_vec(16 + (i % 48));
        let claim = Claim::new(&payload);
        let _ = verify_once_with_vm(&claim);
    }
}

#[test]
fn fuzz_hash_preimage_honest_always_valid() {
    for _ in 0..16 {
        let w = HashWitness {
            seed: random_bytes::<32>(),
        };
        let verdict = prove_and_verify::<HashPreimage>(&w, b"fuzz").expect("no panic");
        assert!(
            verdict.is_valid_bool(),
            "honest hash-preimage witness must always verify"
        );
    }
}

#[test]
fn fuzz_merkle_honest_always_valid() {
    for leaf_count in [1usize, 2, 3, 5, 7, 8, 9, 15, 16] {
        let leaves: Vec<Vec<u8>> = (0..leaf_count).map(|i| vec![i as u8; 8]).collect();
        for idx in 0..leaf_count {
            let w = MerkleWitness {
                leaves: leaves.clone(),
                index: idx,
            };
            let verdict = prove_and_verify::<MerkleInclusion>(&w, b"fuzz").expect("no panic");
            assert!(
                verdict.is_valid_bool(),
                "honest merkle inclusion must verify (leaves={leaf_count}, idx={idx})"
            );
        }
    }
}

#[test]
fn fuzz_ml_dsa_honest_always_valid() {
    for _ in 0..8 {
        let w = MlDsaWitness {
            seed: random_bytes::<32>(),
        };
        let verdict = prove_and_verify::<MlDsaKnowledge>(&w, b"fuzz").expect("no panic");
        assert!(
            verdict.is_valid_bool(),
            "honest ML-DSA witness must always verify"
        );
    }
}

#[test]
fn fuzz_seed_based_never_panics() {
    for _ in 0..16 {
        let seed = Seed::from_bytes(&random_bytes::<64>());
        let payload = random_vec(32);
        let claim = Claim::new(&payload);
        let _ = verify_once_with_seed::<
            veil7::l4_prove::MlDsaProver,
            veil7::l5_verify::MlDsaVerifier,
        >(seed, &claim);
    }
}

// ── New module fuzz tests ──────────────────────────────────────────────────

#[test]
fn fuzz_blind_attest_never_panics() {
    for i in 0..16usize {
        let payload = random_vec(16 + (i % 48));
        let _ = veil7::blind::blind_attest(&payload);
    }
}

#[test]
fn fuzz_commit_reveal_never_panics() {
    for _ in 0..16 {
        let payload = random_vec(32);
        let result = veil7::commit_reveal::commit_phase(&payload);
        if let Ok((token, nonce)) = result {
            let _ = veil7::commit_reveal::reveal_phase(&token, &nonce, &payload);
        }
    }
}

#[test]
fn fuzz_threshold_never_panics() {
    for _ in 0..4 {
        let payload = random_vec(16);
        let claim = Claim::new(&payload);
        let _ = veil7::threshold::threshold_verify(&claim, 2, 3);
    }
}

#[test]
fn fuzz_shamir_split_reconstruct_never_panics() {
    for _ in 0..8 {
        let secret = random_bytes::<64>();
        if let Some(shares) = veil7::shamir::split(&secret, 3, 2) {
            let subset = [
                veil7::shamir::Share {
                    index: shares[0].index,
                    data: shares[0].data,
                },
                veil7::shamir::Share {
                    index: shares[1].index,
                    data: shares[1].data,
                },
            ];
            let _ = veil7::shamir::reconstruct(&subset);
        }
    }
}

#[test]
fn fuzz_hybrid_attest_never_panics() {
    for _ in 0..4 {
        let payload = random_vec(32);
        let claim = Claim::new(&payload);
        let _ = veil7::hybrid::hybrid_attest(&claim);
    }
}

#[test]
fn fuzz_ct_shake256_never_panics() {
    for i in 0..32usize {
        let data = random_vec(1 + (i % 128));
        let mut out = [0u8; 32];
        veil7::keccak_ct::ct_shake256(&data, &mut out);
    }
}

#[test]
fn fuzz_range_proof_honest_always_valid() {
    for i in 0..8usize {
        let min: u64 = (i as u64 * 123) % 1000;
        let range: u64 = 1 + ((i as u64 * 457) % 1000);
        let max = min + range;
        let value = min + ((i as u64 * 31) % range);
        let w = veil7::relations::range_proof::Witness { value, min, max };
        let v = veil7::prove_and_verify::<veil7::relations::range_proof::RangeProof>(&w, b"fuzz")
            .expect("no panic");
        assert!(v.is_valid_bool(), "honest range proof must verify");
    }
}
