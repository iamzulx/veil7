#![no_main]
use libfuzzer_sys::fuzz_target;
use veil7::{verify_once, Claim};

fuzz_target!(|data: &[u8]| {
    if data.len() < 1 || data.len() > 4096 {
        return;
    }
    let claim = Claim::new(data);
    let _ = verify_once(&claim);
    // Goal: no panic, no crash, no memory safety issue
});
