#![no_main]
use libfuzzer_sys::fuzz_target;
use veil7::chain_root;

fuzz_target!(|data: &[u8]| {
    // Split input into multiple events
    if data.len() < 4 {
        return;
    }
    let chunk_size = (data.len() / 4).max(1);
    let events: Vec<&[u8]> = data.chunks(chunk_size).collect();
    if events.is_empty() {
        return;
    }
    let _ = chain_root(&events);
});
