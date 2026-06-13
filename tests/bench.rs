//! Lightweight benchmark — no external crate, just `std::time::Instant`.
#![cfg(feature = "std")]

use std::time::Instant;
use veil7::relations::{
    hash_preimage::{HashPreimage, Witness as HashWitness},
    merkle::{MerkleInclusion, Witness as MerkleWitness},
};
use veil7::{prove_and_verify, verify_once, verify_once_with_oram, verify_once_with_vm, Claim};

const ITERATIONS: usize = 8;

fn bench(name: &str, f: impl Fn()) {
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        f();
    }
    let elapsed = start.elapsed();
    let avg = elapsed / ITERATIONS as u32;
    println!("bench {:30} total={:>12?} avg={:>12?}", name, elapsed, avg);
}

#[test]
fn bench_verify_once() {
    bench("verify_once", || {
        let claim = Claim::new(b"benchmark claim");
        let _ = verify_once(&claim).unwrap();
    });
}

#[test]
fn bench_prove_and_verify_hash_preimage() {
    let w = HashWitness { seed: [0xABu8; 32] };
    bench("prove_and_verify_hash", || {
        let _ = prove_and_verify::<HashPreimage>(&w, b"bench").unwrap();
    });
}

#[test]
fn bench_prove_and_verify_merkle() {
    let leaves: Vec<Vec<u8>> = (0..8).map(|i| vec![i as u8; 8]).collect();
    let w = MerkleWitness {
        leaves: leaves.clone(),
        index: 3,
    };
    bench("prove_and_verify_merkle", || {
        let _ = prove_and_verify::<MerkleInclusion>(&w, b"bench").unwrap();
    });
}

#[test]
fn bench_verify_once_with_oram() {
    bench("verify_once_with_oram", || {
        let claim = Claim::new(b"oram benchmark");
        let _ = verify_once_with_oram(&claim).unwrap();
    });
}

#[test]
fn bench_verify_once_with_vm() {
    bench("verify_once_with_vm", || {
        let claim = Claim::new(b"vm benchmark");
        let _ = verify_once_with_vm(&claim).unwrap();
    });
}

#[test]
fn bench_threshold_3_of_5() {
    bench("threshold_3_of_5", || {
        let claim = Claim::new(b"threshold bench");
        let _ = veil7::threshold::threshold_verify(&claim, 3, 5).unwrap();
    });
}

#[test]
fn bench_blind_attest() {
    bench("blind_attest", || {
        let _ = veil7::blind::blind_attest(b"blind benchmark").unwrap();
    });
}

#[test]
fn bench_hybrid_attest() {
    bench("hybrid_attest", || {
        let claim = Claim::new(b"hybrid benchmark");
        let _ = veil7::hybrid::hybrid_attest(&claim).unwrap();
    });
}

#[test]
fn bench_prove_and_verify_pedersen() {
    let w = veil7::relations::pedersen::Witness {
        value: [0xAA; 32],
        blinding: [0xBB; 32],
    };
    bench("prove_and_verify_pedersen", || {
        let _ = prove_and_verify::<veil7::relations::pedersen::PedersenCommitment>(&w, b"bench")
            .unwrap();
    });
}

#[test]
fn bench_prove_and_verify_range_proof() {
    let w = veil7::relations::range_proof::Witness {
        value: 500,
        min: 0,
        max: 1000,
    };
    bench("prove_and_verify_range", || {
        let _ =
            prove_and_verify::<veil7::relations::range_proof::RangeProof>(&w, b"bench").unwrap();
    });
}
