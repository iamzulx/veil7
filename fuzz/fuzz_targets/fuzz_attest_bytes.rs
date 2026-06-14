#![no_main]
use libfuzzer_sys::fuzz_target;
use veil7::interface::attest_bytes;

fuzz_target!(|data: &[u8]| {
    if data.len() < 1 || data.len() > 4096 {
        return;
    }
    let _ = attest_bytes(data);
});
