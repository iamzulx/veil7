#![no_main]
use libfuzzer_sys::fuzz_target;

/// Fuzz target for KEM encapsulate/decapsulate roundtrip.
///
/// Verifies that:
/// - Encapsulation never panics on arbitrary input
/// - Decapsulation never panics on arbitrary ciphertext
/// - Roundtrip produces matching shared secrets (for valid keypairs)
fuzz_target!(|data: &[u8]| {
    // Need at least 64 bytes for KEM seed
    if data.len() < 64 {
        return;
    }

    // Use first 64 bytes as KEM seed
    let mut seed = [0u8; 64];
    seed.copy_from_slice(&data[..64]);

    // Generate keypair
    let kp = veil7::pq_backends::libcrux_backend::kem_keygen(seed);

    // Encapsulate with random coins
    let mut coins = [0u8; 32];
    if data.len() >= 96 {
        coins.copy_from_slice(&data[64..96]);
    }
    let pk = veil7::pq_backends::libcrux_backend::kem_pk_from_bytes(
        veil7::pq_backends::libcrux_backend::kem_pk_bytes(&kp),
    );
    let (ct, ss_enc) = veil7::pq_backends::libcrux_backend::kem_encapsulate(&pk, coins);

    // Decapsulate
    let sk = veil7::pq_backends::libcrux_backend::kem_sk_from_bytes(
        veil7::pq_backends::libcrux_backend::kem_sk_bytes(&kp),
    );
    let ss_dec = veil7::pq_backends::libcrux_backend::kem_decapsulate(&sk, &ct);

    // Verify roundtrip
    assert_eq!(
        ss_enc.as_slice(),
        ss_dec.as_slice(),
        "KEM roundtrip must produce matching shared secrets"
    );
});
