#![no_main]
use libfuzzer_sys::fuzz_target;
use veil7::shamir::{split, reconstruct, Share};

fuzz_target!(|data: &[u8]| {
    if data.len() < 66 {
        return; // need 64 bytes secret + n + t
    }
    let mut secret = [0u8; 64];
    secret.copy_from_slice(&data[..64]);
    let n = (data[64] % 10) + 2; // 2..11
    let t = (data[65] % n) + 1;  // 1..n (but t >= 2 for split)
    let t = t.max(2);

    if let Some(shares) = split(&secret, n, t) {
        // Reconstruct from first t shares
        let subset: Vec<Share> = shares.iter().take(t as usize).map(|s| {
            Share { index: s.index, data: s.data }
        }).collect();

        if let Some(recovered) = reconstruct(&subset) {
            assert_eq!(recovered, secret, "reconstruction must match original");
        }
    }
});
