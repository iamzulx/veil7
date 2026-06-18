#![no_main]
use libfuzzer_sys::fuzz_target;
use veil7::merkle_verify_path;

fuzz_target!(|data: &[u8]| {
    if data.len() < 96 {
        return;
    }
    let mut leaf = [0u8; 32];
    let mut root = [0u8; 32];
    leaf.copy_from_slice(&data[0..32]);
    root.copy_from_slice(&data[32..64]);
    let index = usize::from_le_bytes(data[64..72].try_into().unwrap()) % 256;
    let leaf_count = ((data[72] as usize) % 32) + 1;
    let index = index % leaf_count;

    let siblings: Vec<[u8; 32]> = data[73..].chunks(32)
        .filter(|c| c.len() == 32)
        .map(|c| {
            let mut s = [0u8; 32];
            s.copy_from_slice(c);
            s
        })
        .collect();

    let _ = merkle_verify_path(&leaf, &root, index, &siblings, leaf_count);
});
