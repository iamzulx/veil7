#![no_main]
use libfuzzer_sys::fuzz_target;
use veil7::shake256::{Shake256, shake256};

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    // Split: first byte = number of chunks, rest = data
    let num_chunks = (data[0] as usize % 8) + 1;
    let payload = &data[1..];

    // Incremental API
    let mut xof = Shake256::new();
    for chunk in payload.chunks((payload.len() / num_chunks).max(1)) {
        xof.update(chunk);
    }
    let mut reader1 = xof.finalize_xof();
    let mut out1 = [0u8; 32];
    reader1.read(&mut out1);

    // One-shot API
    let out2: [u8; 32] = shake256(payload);

    // Both must produce same result
    assert_eq!(out1, out2, "incremental must match one-shot");

    // Variable length using Shake256Reader
    let mut out3 = [0u8; 64];
    let mut xof2 = Shake256::new();
    xof2.update(payload);
    let mut reader2 = xof2.finalize_xof();
    reader2.read(&mut out3);
    assert_ne!(out3, [0u8; 64]);
});
