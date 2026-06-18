#![no_main]
use libfuzzer_sys::fuzz_target;
use veil7::{verify_once_with_vm, Claim};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > 4096 {
        return;
    }
    let claim = Claim::new(data);
    let _ = verify_once_with_vm(&claim);
});
