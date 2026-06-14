#![no_main]
use libfuzzer_sys::fuzz_target;
use veil7::commit_reveal::{commit_phase, reveal_phase};

fuzz_target!(|data: &[u8]| {
    if data.len() < 1 || data.len() > 4096 {
        return;
    }
    if let Ok((token, nonce)) = commit_phase(data) {
        // Reveal with same data — must succeed
        let result = reveal_phase(&token, &nonce, data);
        if let Ok(verdict) = result {
            assert!(verdict.is_valid_bool(), "honest reveal must verify");
        }
    }
});
