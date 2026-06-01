//! veil7 demo binary.
//!
//! Demonstrates the engine in two modes, and prints only traceless verdicts:
//!
//!   1. Legacy ML-DSA pipeline      — `verify_once(claim)`
//!   2. Universal relation pipeline — `prove_and_verify::<R>(witness)` for two
//!      completely different relations (pure-hash Lamport, and ML-DSA), routed
//!      through the SAME generic entry point. That shared path is the whole
//!      point: swap the relation, the verification machinery is unchanged.
//!
//! The engine library writes nothing anywhere; all output here is from main().

use veil7::l1_entropy::harvest;
use veil7::pipeline::prove_and_verify;
use veil7::relations::{
    hash_preimage::HashPreimage, merkle::MerkleInclusion, ml_dsa::MlDsaKnowledge,
};
use veil7::{verify_once, Claim};

fn main() {
    // Probe whether seed memory-locking is active on this host.
    if let Ok(seed) = harvest(b"probe") {
        println!("seed_mlock={}", seed.is_locked() as u8);
    }

    println!("\n[1] legacy ML-DSA pipeline  (verify_once)");
    for c in [
        b"attestation: device booted in verified state".as_slice(),
        b"attestation: payload hash matches manifest".as_slice(),
    ] {
        match verify_once(&Claim::new(c)) {
            Ok(v) => println!(
                "    valid={} transcript={}",
                v.is_valid_bool() as u8,
                hex(v.transcript())
            ),
            Err(_) => println!("    valid=0 transcript=-"),
        }
    }

    println!("\n[2] universal relation pipeline  (prove_and_verify::<R>)");

    // Relation A: pure-hash Lamport proof of knowledge.
    {
        use veil7::relations::hash_preimage::Witness;
        let w = Witness { seed: [0x42u8; 32] };
        match prove_and_verify::<HashPreimage>(&w, b"demo") {
            Ok(v) => println!(
                "    hash_preimage  valid={} transcript={}",
                v.is_valid_bool() as u8,
                hex(v.transcript())
            ),
            Err(_) => println!("    hash_preimage  valid=0 transcript=-"),
        }
    }

    // Relation B: ML-DSA-65 knowledge — different cryptography, same entry point.
    {
        use veil7::relations::ml_dsa::Witness;
        let w = Witness { seed: [0x42u8; 32] };
        match prove_and_verify::<MlDsaKnowledge>(&w, b"demo") {
            Ok(v) => println!(
                "    ml_dsa         valid={} transcript={}",
                v.is_valid_bool() as u8,
                hex(v.transcript())
            ),
            Err(_) => println!("    ml_dsa         valid=0 transcript=-"),
        }
    }

    // Relation C: Merkle set membership — a third statement shape, same entry.
    {
        use veil7::relations::merkle::Witness;
        let leaves: Vec<Vec<u8>> = (0..8u8).map(|i| vec![i; 8]).collect();
        let w = Witness { leaves, index: 5 };
        match prove_and_verify::<MerkleInclusion>(&w, b"demo") {
            Ok(v) => println!(
                "    merkle         valid={} transcript={}",
                v.is_valid_bool() as u8,
                hex(v.transcript())
            ),
            Err(_) => println!("    merkle         valid=0 transcript=-"),
        }
    }

    println!("\n(note: three different cryptographic families — hash preimage,");
    println!(" lattice signature, set membership — through ONE generic entry.)");
}

fn hex(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for &byte in b.iter() {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}
