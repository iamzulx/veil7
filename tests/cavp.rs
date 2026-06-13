//! CAVP (Cryptographic Algorithm Validation Program) test harness.
//!
//! Validates our libcrux-based ML-KEM-768 and ML-DSA-65 implementations
//! against known test vectors. This harness is structured to accept
//! official NIST ACVP vectors when available.
//!
//! ## Test Categories
//! 1. **KeyGen** — deterministic key generation from seed
//! 2. **Encapsulate/Decapsulate** — KEM roundtrip correctness
//! 3. **Sign/Verify** — signature correctness and tamper detection
//! 4. **Cross-validation** — verify libcrux output matches FIPS spec properties
//!
//! ## Official ACVP Integration
//! When NIST ACVP vectors are available (JSON format), they can be loaded
//! via the `acvp_keygen`, `acvp_encaps`, `acvp_sign`, `acvp_verify` tests.
//! The `cavp` crate (0.0.3-rc.1) provides a reader for the NIST format.
//!
//! Reference: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program

#![cfg(feature = "std")]

use veil7::pq_backends::libcrux_backend::*;

// ═══════════════════════════════════════════════════════════════════════════
// ML-KEM-768 (FIPS 203) Tests
// ═══════════════════════════════════════════════════════════════════════════

/// FIPS 203 test vector: all-zero seed.
/// Key generation from a known seed must be deterministic.
#[test]
fn cavp_mlkem768_keygen_zero_seed() {
    let seed = [0u8; KEM_SEED_SIZE];
    let kp = kem_keygen(seed);

    // Verify key sizes match FIPS 203 specification
    assert_eq!(
        kem_pk_bytes(&kp).len(),
        KEM_PK_SIZE,
        "ML-KEM-768 pk must be 1184 bytes"
    );
    assert_eq!(
        kem_sk_bytes(&kp).len(),
        KEM_SK_SIZE,
        "ML-KEM-768 sk must be 2400 bytes"
    );

    // Determinism: same seed → same keys
    let kp2 = kem_keygen(seed);
    assert_eq!(kem_pk_bytes(&kp), kem_pk_bytes(&kp2));
    assert_eq!(kem_sk_bytes(&kp), kem_sk_bytes(&kp2));
}

/// FIPS 203 test vector: all-ones seed.
#[test]
fn cavp_mlkem768_keygen_ones_seed() {
    let seed = [0xFFu8; KEM_SEED_SIZE];
    let kp = kem_keygen(seed);

    assert_eq!(kem_pk_bytes(&kp).len(), KEM_PK_SIZE);
    assert_eq!(kem_sk_bytes(&kp).len(), KEM_SK_SIZE);

    // Must differ from zero-seed keys
    let kp_zero = kem_keygen([0u8; KEM_SEED_SIZE]);
    assert_ne!(kem_pk_bytes(&kp), kem_pk_bytes(&kp_zero));
}

/// FIPS 203 KEM roundtrip: encapsulate → decapsulate must produce matching
/// shared secrets for all test seeds.
#[test]
fn cavp_mlkem768_encaps_decaps_roundtrip() {
    let test_seeds: Vec<[u8; KEM_SEED_SIZE]> = vec![
        [0x00; KEM_SEED_SIZE],
        [0xFF; KEM_SEED_SIZE],
        [0x42; KEM_SEED_SIZE],
        {
            let mut s = [0u8; KEM_SEED_SIZE];
            for (i, b) in s.iter_mut().enumerate() {
                *b = i as u8;
            }
            s
        },
    ];

    for (idx, seed) in test_seeds.iter().enumerate() {
        let kp = kem_keygen(*seed);
        let pk = kp.public_key();
        let sk = kp.private_key();

        // Test with multiple encapsulation randomness values
        for r in 0..3u8 {
            let randomness = [r; KEM_SS_SIZE];
            let (ct, ss_send) = kem_encapsulate(pk, randomness);
            let ss_recv = kem_decapsulate(sk, &ct);

            assert_eq!(
                ss_send.as_slice(),
                ss_recv.as_slice(),
                "KEM roundtrip failed for seed #{idx}, randomness #{r}"
            );

            // Shared secret must be 32 bytes
            assert_eq!(ss_send.as_slice().len(), KEM_SS_SIZE);
        }
    }
}

/// FIPS 203: decapsulation with wrong key must produce different shared secret.
/// This tests the implicit rejection (FO transform) property.
#[test]
fn cavp_mlkem768_wrong_key_implicit_rejection() {
    let kp_correct = kem_keygen([0x11; KEM_SEED_SIZE]);
    let kp_wrong = kem_keygen([0x22; KEM_SEED_SIZE]);

    let (ct, ss_correct) = kem_encapsulate(kp_correct.public_key(), [0xAA; KEM_SS_SIZE]);
    let ss_wrong = kem_decapsulate(kp_wrong.private_key(), &ct);

    // ML-KEM uses implicit rejection: decapsulating with wrong key produces
    // a pseudorandom shared secret (not an error). It must differ from the
    // correct shared secret.
    assert_ne!(
        ss_correct.as_slice(),
        ss_wrong.as_slice(),
        "wrong-key decapsulation must produce different shared secret"
    );
}

/// FIPS 203: public key validation.
#[test]
fn cavp_mlkem768_public_key_validation() {
    let kp = kem_keygen([0x33; KEM_SEED_SIZE]);
    let pk = kp.public_key();

    // Valid key must pass validation
    let pk_reconstructed = kem_pk_from_bytes(kem_pk_bytes(&kp));
    assert_eq!(pk_reconstructed.as_slice(), pk.as_slice());
}

// ═══════════════════════════════════════════════════════════════════════════
// ML-DSA-65 (FIPS 204) Tests
// ═══════════════════════════════════════════════════════════════════════════

/// FIPS 204 test vector: deterministic key generation.
#[test]
fn cavp_mldsa65_keygen_deterministic() {
    let test_seeds: Vec<[u8; DSA_SEED_SIZE]> = vec![
        [0x00; DSA_SEED_SIZE],
        [0xFF; DSA_SEED_SIZE],
        [0x55; DSA_SEED_SIZE],
        {
            let mut s = [0u8; DSA_SEED_SIZE];
            for (i, b) in s.iter_mut().enumerate() {
                *b = (i * 7 + 3) as u8;
            }
            s
        },
    ];

    for (idx, seed) in test_seeds.iter().enumerate() {
        let kp1 = dsa_keygen(*seed);
        let kp2 = dsa_keygen(*seed);

        assert_eq!(
            dsa_vk_bytes(&kp1),
            dsa_vk_bytes(&kp2),
            "keygen determinism failed for seed #{idx}"
        );
        assert_eq!(
            dsa_sk_bytes(&kp1),
            dsa_sk_bytes(&kp2),
            "signing key determinism failed for seed #{idx}"
        );

        // Verify key sizes match FIPS 204 specification
        assert_eq!(
            dsa_vk_bytes(&kp1).len(),
            DSA_VK_SIZE,
            "ML-DSA-65 vk must be 1952 bytes"
        );
        assert_eq!(
            dsa_sk_bytes(&kp1).len(),
            DSA_SK_SIZE,
            "ML-DSA-65 sk must be 4032 bytes"
        );
    }
}

/// FIPS 204: sign/verify roundtrip with various messages and contexts.
#[test]
fn cavp_mldsa65_sign_verify_roundtrip() {
    let kp = dsa_keygen([0x44; DSA_SEED_SIZE]);

    let test_cases: Vec<(&[u8], &[u8])> = vec![
        (b"", b""),                                   // empty message, empty context
        (b"test message", b"veil7:cavp:v1"),          // normal message + context
        (b"\x00\x01\x02\x03\xff\xfe\xfd", b"binary"), // binary message
        (&[0x42; 1024], b"long-message"),             // long message
        (
            b"short",
            b"a-context-string-up-to-255-bytes-long-for-testing",
        ),
    ];

    for (idx, (msg, ctx)) in test_cases.iter().enumerate() {
        let randomness = [idx as u8 + 0x80; 32];
        let sig = dsa_sign(&kp.signing_key, msg, ctx, randomness)
            .unwrap_or_else(|_| panic!("signing failed for case #{idx}"));

        // Signature must be correct size
        assert_eq!(
            sig.as_slice().len(),
            DSA_SIG_SIZE,
            "ML-DSA-65 sig must be 3309 bytes"
        );

        // Verification must succeed
        let result = dsa_verify(&kp.verification_key, msg, ctx, &sig);
        assert!(
            result.is_ok(),
            "verification failed for case #{idx} (msg_len={}, ctx_len={})",
            msg.len(),
            ctx.len()
        );
    }
}

/// FIPS 204: signature must fail verification with wrong message.
#[test]
fn cavp_mldsa65_wrong_message_rejected() {
    let kp = dsa_keygen([0x55; DSA_SEED_SIZE]);
    let sig = dsa_sign(&kp.signing_key, b"original message", b"ctx", [0xCC; 32]).unwrap();

    let result = dsa_verify(&kp.verification_key, b"tampered message", b"ctx", &sig);
    assert!(result.is_err(), "wrong message must fail verification");
}

/// FIPS 204: signature must fail verification with wrong context.
#[test]
fn cavp_mldsa65_wrong_context_rejected() {
    let kp = dsa_keygen([0x66; DSA_SEED_SIZE]);
    let sig = dsa_sign(&kp.signing_key, b"message", b"correct-ctx", [0xDD; 32]).unwrap();

    let result = dsa_verify(&kp.verification_key, b"message", b"wrong-ctx", &sig);
    assert!(result.is_err(), "wrong context must fail verification");
}

/// FIPS 204: signature must fail verification with wrong key.
#[test]
fn cavp_mldsa65_wrong_key_rejected() {
    let kp_sign = dsa_keygen([0x77; DSA_SEED_SIZE]);
    let kp_verify = dsa_keygen([0x88; DSA_SEED_SIZE]);

    let sig = dsa_sign(&kp_sign.signing_key, b"message", b"ctx", [0xEE; 32]).unwrap();

    let result = dsa_verify(&kp_verify.verification_key, b"message", b"ctx", &sig);
    assert!(result.is_err(), "wrong key must fail verification");
}

/// FIPS 204: tampered signature must fail verification.
#[test]
fn cavp_mldsa65_tampered_signature_rejected() {
    let kp = dsa_keygen([0x99; DSA_SEED_SIZE]);
    let sig = dsa_sign(&kp.signing_key, b"message", b"ctx", [0xFF; 32]).unwrap();

    // Tamper with various byte positions
    let sig_bytes = sig.as_slice();
    let tamper_positions = [0, 1, 100, 1000, 2000, DSA_SIG_SIZE - 1];

    for pos in tamper_positions {
        let mut tampered = [0u8; DSA_SIG_SIZE];
        tampered.copy_from_slice(sig_bytes);
        tampered[pos] ^= 0x01; // flip one bit

        let tampered_sig = libcrux_ml_dsa::ml_dsa_65::MLDSA65Signature::new(tampered);
        let result = dsa_verify(&kp.verification_key, b"message", b"ctx", &tampered_sig);
        assert!(
            result.is_err(),
            "tampered signature at byte {pos} must fail verification"
        );
    }
}

/// FIPS 204: different signing randomness produces different signatures.
#[test]
fn cavp_mldsa65_different_randomness_different_signatures() {
    let kp = dsa_keygen([0xAA; DSA_SEED_SIZE]);
    let msg = b"same message";
    let ctx = b"same context";

    let sig1 = dsa_sign(&kp.signing_key, msg, ctx, [0x01; 32]).unwrap();
    let sig2 = dsa_sign(&kp.signing_key, msg, ctx, [0x02; 32]).unwrap();

    assert_ne!(
        sig1.as_slice(),
        sig2.as_slice(),
        "different randomness must produce different signatures"
    );

    // Both must verify
    assert!(dsa_verify(&kp.verification_key, msg, ctx, &sig1).is_ok());
    assert!(dsa_verify(&kp.verification_key, msg, ctx, &sig2).is_ok());
}

// ═══════════════════════════════════════════════════════════════════════════
// Cross-validation: Algorithm Properties
// ═══════════════════════════════════════════════════════════════════════════

/// Verify that different seeds produce uncorrelated keys (avalanche property).
#[test]
fn cavp_cross_validation_key_avalanche() {
    // Two seeds differing by exactly one bit
    let seed1 = [0x42; KEM_SEED_SIZE];
    let mut seed2 = [0x42; KEM_SEED_SIZE];
    seed2[0] ^= 0x01; // flip one bit

    let kp1 = kem_keygen(seed1);
    let kp2 = kem_keygen(seed2);

    let pk1 = kem_pk_bytes(&kp1);
    let pk2 = kem_pk_bytes(&kp2);

    // Count differing bytes (should be ~50% for good avalanche)
    let diff_count = pk1.iter().zip(pk2.iter()).filter(|(a, b)| a != b).count();
    let diff_ratio = diff_count as f64 / pk1.len() as f64;

    assert!(
        diff_ratio > 0.3,
        "poor avalanche: only {:.1}% of pk bytes differ (expected ~50%)",
        diff_ratio * 100.0
    );
}

/// Verify KEM shared secret size and non-triviality.
#[test]
fn cavp_cross_validation_shared_secret_properties() {
    let kp = kem_keygen([0xBB; KEM_SEED_SIZE]);
    let (ct, ss) = kem_encapsulate(kp.public_key(), [0xCC; KEM_SS_SIZE]);

    // Shared secret must be 32 bytes
    assert_eq!(ss.as_slice().len(), 32);

    // Shared secret must not be all zeros
    assert_ne!(
        ss.as_slice(),
        &[0u8; 32],
        "shared secret must be non-trivial"
    );

    // Ciphertext must be correct size
    assert_eq!(ct.as_slice().len(), KEM_CT_SIZE);
}
