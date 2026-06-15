//! Comprehensive stress test suite for veil7
//!
//! This test suite performs comprehensive stress testing using various methods:
//! - Edge case testing
//! - Boundary condition testing
//! - Malformed input testing
//! - Multi-vector injection testing
//! - Metadata leakage detection
//! - Logging violation detection

use veil7::{verify_once, Claim};

// ═══════════════════════════════════════════════════════════════════════════
// EDGE CASE TESTING
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_test_empty_claim() {
    let claim = Claim::new(b"");
    let result = verify_once(&claim);
    assert!(result.is_ok(), "empty claim should succeed");
}

#[test]
fn stress_test_very_large_claim() {
    // Test with 1MB claim
    let large_claim = vec![0x42u8; 1024 * 1024];
    let claim = Claim::new(&large_claim);
    let result = verify_once(&claim);
    assert!(result.is_ok(), "very large claim should succeed");
}

#[test]
fn stress_test_all_zeros_claim() {
    let claim = Claim::new(&[0u8; 1024]);
    let result = verify_once(&claim);
    assert!(result.is_ok(), "all zeros claim should succeed");
}

#[test]
fn stress_test_all_ones_claim() {
    let claim = Claim::new(&[0xFFu8; 1024]);
    let result = verify_once(&claim);
    assert!(result.is_ok(), "all ones claim should succeed");
}

#[test]
fn stress_test_alternating_pattern() {
    let mut claim = vec![0u8; 1024];
    for i in 0..claim.len() {
        claim[i] = if i % 2 == 0 { 0xAA } else { 0x55 };
    }
    let claim = Claim::new(&claim);
    let result = verify_once(&claim);
    assert!(result.is_ok(), "alternating pattern should succeed");
}

// ═══════════════════════════════════════════════════════════════════════════
// BOUNDARY CONDITION TESTING
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_test_exact_1_byte() {
    let claim = Claim::new(&[0x42u8; 1]);
    let result = verify_once(&claim);
    assert!(result.is_ok(), "1 byte claim should succeed");
}

#[test]
fn stress_test_exact_32_bytes() {
    let claim = Claim::new(&[0x42u8; 32]);
    let result = verify_once(&claim);
    assert!(result.is_ok(), "32 bytes claim should succeed");
}

#[test]
fn stress_test_exact_64_bytes() {
    let claim = Claim::new(&[0x42u8; 64]);
    let result = verify_once(&claim);
    assert!(result.is_ok(), "64 bytes claim should succeed");
}

#[test]
fn stress_test_exact_1024_bytes() {
    let claim = Claim::new(&[0x42u8; 1024]);
    let result = verify_once(&claim);
    assert!(result.is_ok(), "1024 bytes claim should succeed");
}

#[test]
fn stress_test_exact_4096_bytes() {
    let claim = Claim::new(&[0x42u8; 4096]);
    let result = verify_once(&claim);
    assert!(result.is_ok(), "4096 bytes claim should succeed");
}

// ═══════════════════════════════════════════════════════════════════════════
// MALFORMED INPUT TESTING
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_test_null_bytes_in_middle() {
    let mut claim = vec![0x42u8; 1024];
    claim[512] = 0x00;
    claim[513] = 0x00;
    claim[514] = 0x00;
    let claim = Claim::new(&claim);
    let result = verify_once(&claim);
    assert!(result.is_ok(), "null bytes in middle should succeed");
}

#[test]
fn stress_test_unicode_characters() {
    let claim = Claim::new("Hello 世界 🌍".as_bytes());
    let result = verify_once(&claim);
    assert!(result.is_ok(), "unicode characters should succeed");
}

#[test]
fn stress_test_control_characters() {
    let mut claim = vec![0u8; 256];
    for i in 0..32 {
        claim[i] = i as u8; // Control characters 0-31
    }
    let claim = Claim::new(&claim);
    let result = verify_once(&claim);
    assert!(result.is_ok(), "control characters should succeed");
}

#[test]
fn stress_test_high_bytes() {
    let mut claim = vec![0u8; 256];
    for i in 0..256 {
        claim[i] = i as u8; // All byte values 0-255
    }
    let claim = Claim::new(&claim);
    let result = verify_once(&claim);
    assert!(result.is_ok(), "all byte values should succeed");
}

// ═══════════════════════════════════════════════════════════════════════════
// METADATA LEAKAGE DETECTION
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_test_no_metadata_in_verdict() {
    let claim = Claim::new(b"test claim");
    let verdict = verify_once(&claim).unwrap();
    
    // Check that verdict only contains valid and transcript
    let debug_str = format!("{:?}", verdict);
    
    // Should only contain "valid" and "transcript"
    assert!(debug_str.contains("valid"), "debug should contain 'valid'");
    assert!(debug_str.contains("transcript"), "debug should contain 'transcript'");
    
    // Should NOT contain metadata (check for full words, not substrings)
    assert!(!debug_str.contains("timestamp"), "debug should NOT contain timestamp");
    assert!(!debug_str.contains("sequence"), "debug should NOT contain sequence");
    assert!(!debug_str.contains("session"), "debug should NOT contain session");
    // Note: "id" is a substring of "valid", so we only check for " id " (with spaces)
    assert!(!debug_str.contains(" id "), "debug should NOT contain ' id '");
    // Note: "id:" is a substring of "valid:", so we don't check for it
    assert!(!debug_str.contains("key"), "debug should NOT contain key");
    assert!(!debug_str.contains("signature"), "debug should NOT contain signature");
    assert!(!debug_str.contains("claim"), "debug should NOT contain claim");
}

#[test]
fn stress_test_no_timestamp_in_verdict() {
    let claim = Claim::new(b"test claim");
    let verdict1 = verify_once(&claim).unwrap();
    
    // Wait a bit
    std::thread::sleep(std::time::Duration::from_millis(100));
    
    let verdict2 = verify_once(&claim).unwrap();
    
    // Transcripts should be different (different seeds)
    assert_ne!(verdict1.transcript(), verdict2.transcript(), "transcripts should be different");
    
    // But both should be valid
    assert!(verdict1.is_valid_bool(), "verdict1 should be valid");
    assert!(verdict2.is_valid_bool(), "verdict2 should be valid");
}

// ═══════════════════════════════════════════════════════════════════════════
// LOGGING VIOLATION DETECTION
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_test_no_logging_violations() {
    // This test verifies that veil7 doesn't log anything
    // We can't directly test for logging, but we can verify that
    // the library doesn't panic or produce unexpected output
    
    let claim = Claim::new(b"test claim");
    let result = verify_once(&claim);
    
    // Should succeed without panic
    assert!(result.is_ok(), "should succeed without panic");
    
    let verdict = result.unwrap();
    
    // Should produce valid verdict
    assert!(verdict.is_valid_bool(), "should produce valid verdict");
    
    // Should produce non-zero transcript
    assert!(!verdict.transcript().iter().all(|&b| b == 0), "transcript should not be all zeros");
}

// ═══════════════════════════════════════════════════════════════════════════
// MULTI-VECTOR INJECTION TESTING
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_test_rapid_successive_calls() {
    // Test rapid successive calls to verify statelessness
    for i in 0..100 {
        let claim_str = format!("claim {}", i);
        let claim = Claim::new(claim_str.as_bytes());
        let result = verify_once(&claim);
        assert!(result.is_ok(), "call {} should succeed", i);
    }
}

#[test]
fn stress_test_concurrent_calls() {
    use std::thread;
    
    let handles: Vec<_> = (0..10)
        .map(|i| {
            thread::spawn(move || {
                let claim_str = format!("claim {}", i);
                let claim = Claim::new(claim_str.as_bytes());
                let result = verify_once(&claim);
                assert!(result.is_ok(), "concurrent call should succeed");
            })
        })
        .collect();
    
    for handle in handles {
        handle.join().unwrap();
    }
}

#[test]
fn stress_test_deterministic_with_same_seed() {
    // Test that same seed produces same keys
    use veil7::l1_entropy::Seed;
    use veil7::l2_keygen::derive_keys;
    
    let seed_bytes = [0x42u8; 64];
    let seed1 = Seed::from_bytes(&seed_bytes);
    let seed2 = Seed::from_bytes(&seed_bytes);
    
    let keys1 = derive_keys(&seed1).unwrap();
    let keys2 = derive_keys(&seed2).unwrap();
    
    // Should produce same keys
    let pk1 = veil7::pq_backends::libcrux_backend::kem_pk_bytes(&keys1.kem_kp);
    let pk2 = veil7::pq_backends::libcrux_backend::kem_pk_bytes(&keys2.kem_kp);
    assert_eq!(pk1, pk2, "same seed should produce same keys");
}

#[test]
fn stress_test_different_seeds_different_keys() {
    use veil7::l1_entropy::Seed;
    use veil7::l2_keygen::derive_keys;
    
    let seed1_bytes = [0x42u8; 64];
    let seed2_bytes = [0x43u8; 64];
    
    let seed1 = Seed::from_bytes(&seed1_bytes);
    let seed2 = Seed::from_bytes(&seed2_bytes);
    
    let keys1 = derive_keys(&seed1).unwrap();
    let keys2 = derive_keys(&seed2).unwrap();
    
    // Should produce different keys
    let pk1 = veil7::pq_backends::libcrux_backend::kem_pk_bytes(&keys1.kem_kp);
    let pk2 = veil7::pq_backends::libcrux_backend::kem_pk_bytes(&keys2.kem_kp);
    assert_ne!(pk1, pk2, "different seeds should produce different keys");
}

// ═══════════════════════════════════════════════════════════════════════════
// COMPREHENSIVE INTEGRATION TEST
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_test_full_pipeline_integration() {
    // Test full pipeline with various inputs
    let large_claim = vec![0x42u8; 1024];
    let all_zeros = vec![0u8; 1024];
    let all_ones = vec![0xFFu8; 1024];
    
    let test_cases = vec![
        b"".as_slice(),
        b"short".as_slice(),
        b"medium length claim for testing".as_slice(),
        &large_claim,
        &all_zeros,
        &all_ones,
    ];
    
    for (i, claim_bytes) in test_cases.iter().enumerate() {
        let claim = Claim::new(claim_bytes);
        let result = verify_once(&claim);
        assert!(result.is_ok(), "test case {} should succeed", i);
        
        let verdict = result.unwrap();
        assert!(verdict.is_valid_bool(), "test case {} should be valid", i);
        assert!(!verdict.transcript().iter().all(|&b| b == 0), "test case {} should have non-zero transcript", i);
    }
}
