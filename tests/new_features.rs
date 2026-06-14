//! Integration tests for new v0.3.0 features.
//!
//! Covers: threshold verification, commit-reveal protocol, blind attestation,
//! Shamir secret sharing, range proof relation, hybrid attestation, and
//! constant-time Keccak wrapper.
#![cfg(feature = "std")]

use veil7::Claim;

// ═══════════════════════════════════════════════════════════════════════════
// Threshold Verification
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn threshold_2_of_3_all_valid() {
    let claim = Claim::new(b"threshold-integration");
    let v = veil7::threshold::threshold_verify(&claim, 2, 3).unwrap();
    assert!(v.is_valid_bool(), "all 3 valid, threshold 2 → pass");
}

#[test]
fn threshold_1_of_1() {
    let claim = Claim::new(b"threshold-1-of-1");
    let v = veil7::threshold::threshold_verify(&claim, 1, 1).unwrap();
    assert!(v.is_valid_bool());
}

#[test]
fn threshold_large_m() {
    let claim = Claim::new(b"threshold-large");
    // 5 of 10 iterations — all should be valid.
    let v = veil7::threshold::threshold_verify(&claim, 5, 10).unwrap();
    assert!(v.is_valid_bool());
}

#[test]
fn threshold_invalid_params() {
    let claim = Claim::new(b"x");
    assert!(veil7::threshold::threshold_verify(&claim, 0, 5).is_err());
    assert!(veil7::threshold::threshold_verify(&claim, 1, 0).is_err());
    assert!(veil7::threshold::threshold_verify(&claim, 6, 5).is_err());
}

// ═══════════════════════════════════════════════════════════════════════════
// Commit-Reveal Protocol
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn commit_reveal_honest_roundtrip() {
    let claim = b"sealed-bid:5000";
    let (token, nonce) = veil7::commit_reveal::commit_phase(claim).unwrap();
    let v = veil7::commit_reveal::reveal_phase(&token, &nonce, claim).unwrap();
    assert!(v.is_valid_bool());
}

#[test]
fn commit_reveal_different_claims_different_tokens() {
    let (t1, _) = veil7::commit_reveal::commit_phase(b"bid-A").unwrap();
    let (t2, _) = veil7::commit_reveal::commit_phase(b"bid-B").unwrap();
    // Different claims + different nonces → different tokens.
    assert_ne!(t1.as_bytes(), t2.as_bytes());
}

#[test]
fn commit_reveal_tampered_claim_rejected() {
    let claim = b"honest-bid";
    let (token, nonce) = veil7::commit_reveal::commit_phase(claim).unwrap();
    let result = veil7::commit_reveal::reveal_phase(&token, &nonce, b"tampered-bid");
    assert!(result.is_err(), "tampered claim must fail commitment check");
}

#[test]
fn commit_reveal_wrong_nonce_rejected() {
    let claim = b"honest-bid";
    let (token, _) = veil7::commit_reveal::commit_phase(claim).unwrap();
    let bad_nonce = [0xFF; 32];
    let result = veil7::commit_reveal::reveal_phase(&token, &bad_nonce, claim);
    assert!(result.is_err(), "wrong nonce must fail");
}

#[test]
fn commit_reveal_token_serialization() {
    let claim = b"serialize-test";
    let (token, nonce) = veil7::commit_reveal::commit_phase(claim).unwrap();
    // Serialize and reconstruct.
    let bytes = *token.as_bytes();
    let reconstructed = veil7::commit_reveal::CommitmentToken::from_bytes(&bytes);
    let v = veil7::commit_reveal::reveal_phase(&reconstructed, &nonce, claim).unwrap();
    assert!(v.is_valid_bool());
}

// ═══════════════════════════════════════════════════════════════════════════
// Blind Attestation
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn blind_attest_produces_valid_verdict() {
    let claim = b"secret-auction-bid";
    let (v, unblinded) = veil7::blind::blind_attest(claim).unwrap();
    assert!(v.is_valid_bool());
    assert_ne!(unblinded, [0u8; 32]);
}

#[test]
fn blind_claim_is_uniformly_random_looking() {
    let claim = b"plaintext-data-that-should-be-hidden";
    let factor = veil7::blind::BlindFactor::fresh().unwrap();
    let blinded = veil7::blind::blind_claim(claim, &factor);
    // Blinded data should differ from original.
    assert_ne!(&blinded[..], &claim[..]);
    // And have the same length.
    assert_eq!(blinded.len(), claim.len());
}

#[test]
fn blind_double_xor_recovers_original() {
    let claim = b"round-trip-blind";
    let factor = veil7::blind::BlindFactor::fresh().unwrap();
    let blinded = veil7::blind::blind_claim(claim, &factor);
    let recovered = veil7::blind::blind_claim(&blinded, &factor);
    assert_eq!(
        &recovered[..],
        &claim[..],
        "XOR twice with same mask = identity"
    );
}

#[test]
fn blind_different_factors_different_blinds() {
    let claim = b"same-claim";
    let f1 = veil7::blind::BlindFactor::from_nonce([0x01; 32]);
    let f2 = veil7::blind::BlindFactor::from_nonce([0x02; 32]);
    let b1 = veil7::blind::blind_claim(claim, &f1);
    let b2 = veil7::blind::blind_claim(claim, &f2);
    assert_ne!(b1, b2);
}

#[test]
fn blind_unblinded_transcript_differs_from_engine_transcript() {
    let claim = b"test-data";
    let factor = veil7::blind::BlindFactor::fresh().unwrap();
    let blinded = veil7::blind::blind_claim(claim, &factor);
    let v = veil7::verify_once(&Claim::new(&blinded)).unwrap();
    let unblinded = veil7::blind::unblind_transcript(v.transcript(), &factor);
    assert_ne!(&unblinded[..], &v.transcript()[..]);
}

// ═══════════════════════════════════════════════════════════════════════════
// Shamir Secret Sharing
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn shamir_2_of_3_roundtrip() {
    let secret = [0xAB; 64];
    let shares = veil7::shamir::split(&secret, 3, 2).unwrap();
    assert_eq!(shares.len(), 3);

    // Reconstruct from shares 0 and 2.
    let subset = [
        veil7::shamir::Share {
            index: shares[0].index,
            data: shares[0].data,
        },
        veil7::shamir::Share {
            index: shares[2].index,
            data: shares[2].data,
        },
    ];
    let recovered = veil7::shamir::reconstruct(&subset).unwrap();
    assert_eq!(recovered, secret);
}

#[test]
fn shamir_3_of_5_roundtrip() {
    let secret = [0x42; 64];
    let shares = veil7::shamir::split(&secret, 5, 3).unwrap();

    let subset: Vec<veil7::shamir::Share> = [0, 1, 4]
        .iter()
        .map(|&i| veil7::shamir::Share {
            index: shares[i].index,
            data: shares[i].data,
        })
        .collect();
    let recovered = veil7::shamir::reconstruct(&subset).unwrap();
    assert_eq!(recovered, secret);
}

#[test]
fn shamir_insufficient_shares_wrong_result() {
    let secret = [0xFF; 64];
    let shares = veil7::shamir::split(&secret, 5, 3).unwrap();

    // Only 2 shares (need 3).
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
    let recovered = veil7::shamir::reconstruct(&subset).unwrap();
    assert_ne!(recovered, secret, "2 of 3 threshold must not reconstruct");
}

#[test]
fn shamir_all_shares_reconstruct() {
    let secret = [0x77; 64];
    let shares = veil7::shamir::split(&secret, 4, 2).unwrap();

    let all: Vec<veil7::shamir::Share> = shares
        .iter()
        .map(|s| veil7::shamir::Share {
            index: s.index,
            data: s.data,
        })
        .collect();
    let recovered = veil7::shamir::reconstruct(&all).unwrap();
    assert_eq!(recovered, secret);
}

#[test]
fn shamir_shares_differ_from_secret() {
    let secret = [0xCD; 64];
    let shares = veil7::shamir::split(&secret, 3, 2).unwrap();
    for share in &shares {
        assert_ne!(share.data, secret);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Range Proof Relation
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn range_proof_valid_in_range() {
    use veil7::relations::range_proof::{RangeProof, Witness};
    use veil7::relations::Relation;

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
fn range_proof_at_boundaries() {
    use veil7::relations::range_proof::{RangeProof, Witness};
    use veil7::relations::Relation;

    // At min.
    let w = Witness {
        value: 100,
        min: 100,
        max: 200,
    };
    let (s, p) = RangeProof::prove(&w, &[]).unwrap();
    assert_eq!(RangeProof::verify(&s, &p).unwrap().unwrap_u8(), 1);

    // At max.
    let w = Witness {
        value: 200,
        min: 100,
        max: 200,
    };
    let (s, p) = RangeProof::prove(&w, &[]).unwrap();
    assert_eq!(RangeProof::verify(&s, &p).unwrap().unwrap_u8(), 1);
}

#[test]
fn range_proof_out_of_range_rejected() {
    use veil7::relations::range_proof::{RangeProof, Witness};
    use veil7::relations::Relation;

    // prove() no longer returns Err (constant-time: no early return on secret).
    // Out-of-range proofs are generated but fail verification.
    let w_below = Witness {
        value: 50,
        min: 100,
        max: 200,
    };
    let (s, p) = RangeProof::prove(&w_below, &[]).unwrap();
    assert_eq!(
        RangeProof::verify(&s, &p).unwrap().unwrap_u8(),
        0,
        "below-min proof must fail verification"
    );

    let w_above = Witness {
        value: 250,
        min: 100,
        max: 200,
    };
    let (s2, p2) = RangeProof::prove(&w_above, &[]).unwrap();
    assert_eq!(
        RangeProof::verify(&s2, &p2).unwrap().unwrap_u8(),
        0,
        "above-max proof must fail verification"
    );
}

#[test]
fn range_proof_tampered_bit_rejected() {
    use veil7::relations::range_proof::{RangeProof, Witness};
    use veil7::relations::Relation;

    let w = Witness {
        value: 500,
        min: 0,
        max: 1000,
    };
    let (stmt, mut proof) = RangeProof::prove(&w, &[]).unwrap();
    proof.bits[0] ^= 1;
    let ok = RangeProof::verify(&stmt, &proof).unwrap();
    assert_eq!(ok.unwrap_u8(), 0, "tampered bit must fail");
}

#[test]
fn range_proof_via_prove_and_verify() {
    use veil7::prove_and_verify;
    use veil7::relations::range_proof::{RangeProof, Witness};

    let w = Witness {
        value: 42,
        min: 0,
        max: 100,
    };
    let v = prove_and_verify::<RangeProof>(&w, b"").unwrap();
    assert!(v.is_valid_bool());
}

// ═══════════════════════════════════════════════════════════════════════════
// Hybrid PQ+Classical Attestation
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn hybrid_attest_valid() {
    let claim = Claim::new(b"hybrid-integration-test");
    let v = veil7::hybrid::hybrid_attest(&claim).unwrap();
    assert!(v.is_valid_bool());
}

#[test]
fn hybrid_differs_from_plain_attest() {
    let claim = Claim::new(b"same-data");
    let v_plain = veil7::verify_once(&claim).unwrap();
    let v_hybrid = veil7::hybrid::hybrid_attest(&claim).unwrap();
    assert!(v_plain.is_valid_bool() && v_hybrid.is_valid_bool());
    assert_ne!(v_plain.transcript(), v_hybrid.transcript());
}

// ═══════════════════════════════════════════════════════════════════════════
// Constant-Time Keccak Wrapper
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn ct_shake256_produces_output() {
    let mut out = [0u8; 32];
    veil7::keccak_ct::ct_shake256(b"test-data", &mut out).unwrap();
    assert_ne!(out, [0u8; 32]);
}

#[test]
fn ct_shake256_deterministic_with_fixed_mask() {
    let mask = [0x42; 32];
    let mut h1 = veil7::keccak_ct::CtShake256::with_mask(mask);
    let mut h2 = veil7::keccak_ct::CtShake256::with_mask(mask);

    h1.ct_update(b"hello");
    h2.ct_update(b"hello");

    let out1: [u8; 32] = h1.ct_finalize_array();
    let out2: [u8; 32] = h2.ct_finalize_array();
    assert_eq!(out1, out2);
}

#[test]
fn ct_shake256_public_update_matches_standard() {
    use veil7::shake256::Shake256;

    // Standard SHAKE256.
    let mut std = Shake256::default();
    std.update(b"public-data");
    let mut std_out = [0u8; 32];
    std.finalize_xof().read(&mut std_out);

    // CT with public update.
    let mut ct = veil7::keccak_ct::CtShake256::with_mask([0xFF; 32]);
    ct.update_public(b"public-data");
    let ct_out: [u8; 32] = ct.ct_finalize_array();

    assert_eq!(std_out, ct_out);
}
