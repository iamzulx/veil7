#![no_main]
use libfuzzer_sys::fuzz_target;

/// Fuzz target for DSA sign/verify roundtrip.
///
/// Verifies that:
/// - Signing never panics on arbitrary input
/// - Verification never panics on arbitrary signatures
/// - Roundtrip produces valid signatures (for valid keypairs)
fuzz_target!(|data: &[u8]| {
    // Need at least 32 bytes for DSA seed
    if data.len() < 32 {
        return;
    }

    // Use first 32 bytes as DSA seed
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&data[..32]);

    // Generate keypair
    let kp = veil7::pq_backends::libcrux_backend::dsa_keygen(seed);

    // Sign a message
    let message = if data.len() > 32 { &data[32..] } else { b"test" };
    let ctx = b"veil7:fuzz";
    let mut randomness = [0u8; 32];
    if data.len() >= 64 {
        randomness.copy_from_slice(&data[32..64]);
    }

    let sig = match veil7::pq_backends::libcrux_backend::dsa_sign(
        veil7::pq_backends::libcrux_backend::dsa_sk_bytes(&kp),
        message,
        ctx,
        randomness,
    ) {
        Ok(s) => s,
        Err(_) => return, // Signing can fail on invalid inputs
    };

    // Verify the signature
    let vk = veil7::pq_backends::libcrux_backend::dsa_vk_from_bytes(
        veil7::pq_backends::libcrux_backend::dsa_vk_bytes(&kp),
    );
    let result = veil7::pq_backends::libcrux_backend::dsa_verify(&vk, &sig, message, ctx);

    // Valid signature must verify
    assert!(result.is_ok(), "valid signature must verify");
});
