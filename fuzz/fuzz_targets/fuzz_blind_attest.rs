#![no_main]
use libfuzzer_sys::fuzz_target;
use veil7::blind::{blind_attest, blind_claim, BlindFactor};

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 || data.len() > 4096 {
        return;
    }
    // Use first 32 bytes as nonce for BlindFactor
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&data[..32]);
    let factor = BlindFactor::from_nonce(nonce);
    let claim = &data[32..];

    let blinded = blind_claim(claim, &factor);
    assert_eq!(blinded.len(), claim.len());
    assert_ne!(&blinded[..], claim, "blinded must differ from original");

    // Double-blind recovers original
    let recovered = blind_claim(&blinded, &factor);
    assert_eq!(&recovered[..], claim);

    // Full blind attestation
    let _ = blind_attest(data);
});
