#![no_main]
use libfuzzer_sys::fuzz_target;
use veil7::keccak_ct::{CtShake256, ct_shake256};

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }

    // One-shot ct_shake256
    let out_len = ((data[0] as usize) % 64) + 1;
    let mut out = vec![0u8; out_len];
    let _ = ct_shake256(&data[1..], &mut out);

    // Incremental CtShake256 API
    if let Ok(mut hasher) = CtShake256::new() {
        let num_chunks = (data[1] as usize % 8) + 1;
        for chunk in data[2..].chunks((data.len() / num_chunks).max(1)) {
            hasher.ct_update(chunk);
        }
        let mut result = [0u8; 32];
        hasher.ct_finalize(&mut result);
    }

    // with_mask variant
    if data.len() >= 35 {
        let mut mask = [0u8; 32];
        mask.copy_from_slice(&data[1..33]);
        let mut hasher = CtShake256::with_mask(mask);
        hasher.ct_update(&data[33..]);
        let mut result = [0u8; 64];
        hasher.ct_finalize(&mut result);
    }

    // update_public path
    if let Ok(mut hasher) = CtShake256::new() {
        hasher.update_public(data);
        let mut result = [0u8; 32];
        hasher.ct_finalize(&mut result);
    }
});
