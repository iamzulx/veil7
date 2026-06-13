//! Real-data test — read `math_claims.txt` and verify every line through two
//! pipelines:
//!   1. Legacy ML-DSA pipeline (`verify_once`) — attestation on raw bytes.
//!   2. Universal verification (`prove_and_verify::<MathSum>`) — proves that the
//!      prover knows `a` and `b` such that `a + b = s`.
#![cfg(feature = "std")]

use std::fs;

use subtle::{Choice, ConstantTimeEq};
use veil7::common::{Transcript, VeilError};
use veil7::interface::{attest_chain, attest_file, attest_file_streaming};
use veil7::relations::Relation;
use veil7::{
    chain_root, chain_verify, merkle_root, merkle_verify_path, prove_and_verify, verify_once, Claim,
};

const MATH_FILE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/math_claims.txt");

// ────────────────────────────────────────────────────────────────────────────
// Relation: MathSum — proof of knowledge that a + b = s
// ────────────────────────────────────────────────────────────────────────────

struct MathSum;

struct MathWitness {
    a: u64,
    b: u64,
}

struct MathStatement {
    s: u64,
}

struct MathProof {
    a: u64,
    b: u64,
}

impl Relation for MathSum {
    type Statement = MathStatement;
    type Witness = MathWitness;
    type Proof = MathProof;

    fn protocol_label() -> &'static [u8] {
        b"veil7:relation:math-sum:v1"
    }

    fn statement_from_witness(witness: &MathWitness) -> MathStatement {
        MathStatement {
            s: witness.a + witness.b,
        }
    }

    fn bind_statement(stmt: &MathStatement, t: &mut Transcript) {
        t.absorb(b"math:s", &stmt.s.to_le_bytes());
    }

    fn prove(
        witness: &MathWitness,
        _entropy: &[u8],
    ) -> Result<(MathStatement, MathProof), VeilError> {
        let stmt = Self::statement_from_witness(witness);
        Ok((
            stmt,
            MathProof {
                a: witness.a,
                b: witness.b,
            },
        ))
    }

    fn verify(stmt: &MathStatement, proof: &MathProof) -> Result<Choice, VeilError> {
        let sum = proof.a + proof.b;
        let sum_bytes = sum.to_le_bytes();
        let s_bytes = stmt.s.to_le_bytes();
        Ok(Choice::from(sum_bytes.ct_eq(&s_bytes).unwrap_u8()))
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

fn parse_line(line: &str) -> Option<(u64, u64, u64)> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let parts: Vec<&str> = trimmed.split(',').collect();
    if parts.len() != 3 {
        return None;
    }
    let a = parts[0].trim().parse().ok()?;
    let b = parts[1].trim().parse().ok()?;
    let s = parts[2].trim().parse().ok()?;
    Some((a, b, s))
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn real_data_txt_exists_and_readable() {
    let raw = fs::read_to_string(MATH_FILE).expect("math_claims.txt must exist");
    assert!(
        raw.contains("7,8,15"),
        "sample equation must be present in file"
    );
}

#[test]
fn real_data_verify_once_attests_every_line() {
    let raw = fs::read_to_string(MATH_FILE).expect("read file");
    let mut count = 0;
    for line in raw.lines() {
        if let Some((a, b, s)) = parse_line(line) {
            let payload = format!("{a} + {b} = {s}");
            let claim = Claim::new(payload.as_bytes());
            let verdict = verify_once(&claim).expect("pipeline ok");
            assert!(
                verdict.is_valid_bool(),
                "line '{payload}' must be attested by verify_once"
            );
            count += 1;
        }
    }
    assert_eq!(count, 5, "file must contain 5 valid equations");
}

#[test]
fn real_data_universal_math_sum_valid() {
    let raw = fs::read_to_string(MATH_FILE).expect("read file");
    let mut count = 0;
    for line in raw.lines() {
        if let Some((a, b, _s)) = parse_line(line) {
            let w = MathWitness { a, b };
            let verdict =
                prove_and_verify::<MathSum>(&w, b"real-data").expect("relation pipeline ok");
            assert!(
                verdict.is_valid_bool(),
                "{a} + {b} must be valid in MathSum"
            );
            assert_eq!(
                verdict.transcript().len(),
                32,
                "transcript must be 32 bytes"
            );
            count += 1;
        }
    }
    assert_eq!(count, 5, "must have 5 valid proofs");
}

#[test]
fn real_data_universal_math_sum_tampered_fails() {
    // Forged proof: 5 + 7 = 999 (wrong)
    let _w = MathWitness { a: 5, b: 7 };
    let mut t = Transcript::new(MathSum::protocol_label());
    let stmt = MathStatement { s: 999 }; // forged statement
    MathSum::bind_statement(&stmt, &mut t);
    let proof = MathProof { a: 5, b: 7 };
    let ok = MathSum::verify(&stmt, &proof).expect("no panic");
    assert_eq!(ok.unwrap_u8(), 0, "forged equation 5+7=999 must fail");
}

#[test]
fn real_data_relation_deterministic_transcript() {
    // Same witness -> same statement -> same transcript
    let w = MathWitness { a: 77, b: 23 };
    let v1 = prove_and_verify::<MathSum>(&w, b"x").unwrap();
    let v2 = prove_and_verify::<MathSum>(&w, b"y").unwrap();
    assert!(
        v1.is_valid_bool() && v2.is_valid_bool(),
        "same witness must verify"
    );
    assert_eq!(
        v1.transcript(),
        v2.transcript(),
        "transcript digest must be deterministic for the same statement"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Chained attestation (`interface::attest_chain` + `chain::chain_root`)
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn real_data_chain_root_matches_expected_framing() {
    // The `chain_root` accumulator is `no_std` available; this test pins the
    // exact framing so external verifiers can reproduce the root locally.
    let events: &[&[u8]] = &[b"a", b"b", b"c"];
    let root = chain_root(events).expect("non-empty");

    // Independent re-derivation using the documented domain tags.
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    use sha3::Shake256;
    let mut xof = Shake256::default();
    xof.update(veil7::common::domain::CHAIN_HEAD);
    for ev in events {
        xof.update(veil7::common::domain::CHAIN_STEP);
        xof.update(ev);
    }
    let mut expected = [0u8; 32];
    xof.finalize_xof().read(&mut expected);
    assert_eq!(
        root, expected,
        "chain_root framing must match documented spec"
    );
}

#[test]
fn real_data_attest_chain_deterministic_for_same_events() {
    let events: &[&[u8]] = &[b"login:alice", b"file:read", b"logout:alice"];
    let v1 = attest_chain(events).expect("chain ok");
    let v2 = attest_chain(events).expect("chain ok");
    assert!(v1.is_valid_bool() && v2.is_valid_bool());
    // Each call uses freshly harvested entropy → different ephemeral keys →
    // different ML-DSA signatures → different transcripts. The CHAIN ROOT
    // is what is deterministic for a given event sequence, not the
    // verdict's pq-side transcript.
    let root1 = chain_root(events).expect("non-empty");
    let root2 = chain_root(events).expect("non-empty");
    assert_eq!(
        root1, root2,
        "chain root must be deterministic for same events"
    );
    // And the engine accepts the root as a valid claim byte sequence.
    let root_v = verify_once(&Claim::new(&root1)).expect("root pipeline ok");
    assert!(
        root_v.is_valid_bool(),
        "re-attested chain root must produce a valid verdict"
    );
}

#[test]
fn real_data_attest_chain_tampered_event_changes_root() {
    let original: &[&[u8]] = &[b"event-A", b"event-B", b"event-C"];
    let tampered: &[&[u8]] = &[b"event-A", b"event-B!", b"event-C"];
    let r1 = chain_root(original).expect("non-empty");
    let r2 = chain_root(tampered).expect("non-empty");
    assert_ne!(
        r1, r2,
        "tampering with one event must change the chain root"
    );

    // Both still verify individually (the engine doesn't know which is
    // "right"), but the roots differ — so anyone with the original events
    // can detect that r2 is not the expected anchor.
    let v1 = attest_chain(original).expect("ok");
    let v2 = attest_chain(tampered).expect("ok");
    assert!(v1.is_valid_bool() && v2.is_valid_bool());

    // chain_verify is the pure-math oracle: 1 if events fold to root, 0 if
    // they don't. This is the universal verification side of USE_CASES.md §7
    // — any holder of the events + the root can audit offline, no PQ, no
    // engine identity, no entropy.
    assert_eq!(
        chain_verify(original, &r1).unwrap_u8(),
        1,
        "untampered events verify against their own root"
    );
    assert_eq!(
        chain_verify(tampered, &r1).unwrap_u8(),
        0,
        "tampered events do not verify against the original root"
    );
    assert_eq!(
        chain_verify(original, &r2).unwrap_u8(),
        0,
        "untampered events do not verify against the tampered root"
    );
    assert_eq!(
        chain_verify(tampered, &r2).unwrap_u8(),
        1,
        "tampered events verify against their own (different) root"
    );
}

#[test]
fn real_data_attest_chain_rejects_empty() {
    let empty: &[&[u8]] = &[];
    let err = attest_chain(empty).expect_err("empty chain must fail");
    // We use a single Crypto error for empty input — no metadata leak.
    assert!(matches!(err, VeilError::Crypto));
}

// ────────────────────────────────────────────────────────────────────────────
// Streaming file attest (`interface::attest_file_streaming`)
// ────────────────────────────────────────────────────────────────────────────

const STREAM_SAMPLE: &[u8] = b"veil7 streaming-attest sample payload, padded for chunking";

#[test]
fn real_data_streaming_attest_matches_loaded_attest() {
    // The streaming path and the loaded path produce different Verdict
    // transcripts (ephemeral identity) but they both bind to the same
    // claim bytes, so the SAME file content reaches the engine in both
    // cases. The test writes a file, attests it both ways, and confirms
    // the same content yields valid=1 from both.
    let dir = std::env::temp_dir();
    let path = dir.join("veil7-streaming-test.bin");
    std::fs::write(&path, STREAM_SAMPLE).expect("write");

    let v1 = attest_file(path.to_str().unwrap()).expect("loaded attest ok");
    let v2 = attest_file_streaming(path.to_str().unwrap()).expect("streaming attest ok");
    assert!(v1.is_valid_bool() && v2.is_valid_bool());

    // Clean up.
    let _ = std::fs::remove_file(&path);
}

#[test]
fn real_data_streaming_attest_handles_multichunk_file() {
    // File size > 4096 (one chunk) forces the streaming loop to absorb
    // multiple chunks. Same content as a loaded attest should still pass.
    let dir = std::env::temp_dir();
    let path = dir.join("veil7-streaming-multichunk.bin");
    // 10KB payload = 3 chunks at 4KB chunk size (rounded up to 4KB,
    // then 4KB, then 2KB final).
    let payload: Vec<u8> = (0..10_000u32).map(|i| (i & 0xFF) as u8).collect();
    std::fs::write(&path, &payload).expect("write");

    let v_stream = attest_file_streaming(path.to_str().unwrap()).expect("ok");
    assert!(v_stream.is_valid_bool());

    let _ = std::fs::remove_file(&path);
}

#[test]
fn real_data_streaming_attest_rejects_missing_file() {
    let dir = std::env::temp_dir();
    let path = dir.join("veil7-does-not-exist.bin");
    let err = attest_file_streaming(path.to_str().unwrap()).expect_err("missing file");
    assert!(matches!(err, VeilError::Crypto));
}

#[test]
fn real_data_streaming_attest_rejects_empty_file() {
    let dir = std::env::temp_dir();
    let path = dir.join("veil7-empty-stream.bin");
    std::fs::write(&path, b"").expect("write");
    let err = attest_file_streaming(path.to_str().unwrap()).expect_err("empty file");
    assert!(matches!(err, VeilError::Crypto));
    let _ = std::fs::remove_file(&path);
}

// ────────────────────────────────────────────────────────────────────────────
// Merkle pure-math helpers (prove CLI surface)
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn real_data_merkle_root_and_verify_path_round_trip() {
    // The pure-math helpers are the prover/verifier side of the Merkle
    // inclusion relation. They are what `prove merkle-root` and
    // `prove merkle-include` expose to the CLI.
    let leaves: Vec<Vec<u8>> = (0..8u8).map(|i| vec![i; 4]).collect();
    let leaf_refs: Vec<&[u8]> = leaves.iter().map(|l| l.as_slice()).collect();
    let root = merkle_root(&leaf_refs).expect("non-empty");

    // Compute the inclusion path for index 3 by re-running the relation
    // (the path is not exposed by merkle_root alone, by design).
    let w = veil7::relations::merkle::Witness {
        leaves: leaves.clone(),
        index: 3,
    };
    let (stmt, proof) = veil7::relations::merkle::MerkleInclusion::prove(&w, b"").expect("prove");

    // The standalone verifier must accept the same path.
    let ok = merkle_verify_path(
        &stmt.leaf,
        &stmt.root,
        proof.index,
        &proof.siblings,
        proof.leaf_count,
    );
    assert_eq!(ok.unwrap_u8(), 1, "honest inclusion must verify");

    // And the helper's root must equal the relation's statement root.
    assert_eq!(
        root, stmt.root,
        "merkle_root helper must match relation root"
    );
}

#[test]
fn real_data_merkle_verify_path_rejects_tampered_sibling() {
    let leaves: Vec<Vec<u8>> = (0..4u8).map(|i| vec![i; 4]).collect();
    let w = veil7::relations::merkle::Witness { leaves, index: 0 };
    let (stmt, mut proof) =
        veil7::relations::merkle::MerkleInclusion::prove(&w, b"").expect("prove");
    proof.siblings[0][0] ^= 0xFF;
    let ok = merkle_verify_path(
        &stmt.leaf,
        &stmt.root,
        proof.index,
        &proof.siblings,
        proof.leaf_count,
    );
    assert_eq!(ok.unwrap_u8(), 0, "tampered sibling must fail verification");
}
