#![no_main]
use libfuzzer_sys::fuzz_target;
use veil7::{chain_root, chain_verify};

fuzz_target!(|data: &[u8]| {
    if data.len() < 36 {
        return; // need at least 32 bytes for root + 1 event
    }
    let (root_bytes, event_data) = data.split_at(32);
    let mut root = [0u8; 32];
    root.copy_from_slice(root_bytes);

    let events: Vec<&[u8]> = event_data.chunks(16).collect();
    if events.is_empty() {
        return;
    }

    // Compute actual root and verify against it (should always pass)
    if let Ok(actual_root) = chain_root(&events) {
        let result = chain_verify(&events, &actual_root);
        assert_eq!(result.unwrap_u8(), 1, "chain_verify must pass for correct root");
    }

    // Verify against fuzz root (should almost certainly fail)
    let _ = chain_verify(&events, &root);
});
