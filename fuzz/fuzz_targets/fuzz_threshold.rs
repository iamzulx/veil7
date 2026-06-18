#![no_main]
use libfuzzer_sys::fuzz_target;
use veil7::threshold::threshold_verify;
use veil7::Claim;

fuzz_target!(|data: &[u8]| {
    if data.len() < 17 {
        return;
    }
    let claim = Claim::new(data);
    let n = (data[0] as usize % 8) + 2;  // 2..9
    let m = ((data[1] as usize) % n) + 1; // 1..n
    let _ = threshold_verify(&claim, n, m);
});
