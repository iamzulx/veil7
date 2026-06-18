#![no_main]
use libfuzzer_sys::fuzz_target;
use veil7::chain::ChainState;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > 8192 {
        return;
    }
    let mut builder = ChainState::new();
    let num_chunks = (data[0] as usize % 8) + 1;
    for chunk in data[1..].chunks((data.len() / num_chunks).max(1)) {
        builder.absorb(chunk);
    }
    let _ = builder.finalize();
});
