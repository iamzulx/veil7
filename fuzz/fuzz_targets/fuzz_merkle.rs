#![no_main]
use libfuzzer_sys::fuzz_target;
use veil7::merkle_root;

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 {
        return;
    }
    // Split into leaves (8 bytes each)
    let leaves: Vec<&[u8]> = data.chunks(8).collect();
    if leaves.len() < 2 {
        return;
    }

    // Compute Merkle root — must not panic regardless of input
    let _ = merkle_root(&leaves);

    // Determinism: same input must produce same root
    let root1 = merkle_root(&leaves);
    let root2 = merkle_root(&leaves);
    if let (Ok(r1), Ok(r2)) = (root1, root2) {
        assert_eq!(r1, r2, "Merkle root must be deterministic");
    }

    // Tamper detection: changing any leaf must change the root
    if leaves.len() >= 2 {
        let mut tampered_leaves: Vec<&[u8]> = leaves.to_vec();
        let alt = [0xFFu8; 8];
        tampered_leaves[0] = &alt;
        if let (Ok(r1), Ok(r2)) = (merkle_root(&leaves), merkle_root(&tampered_leaves)) {
            assert_ne!(r1, r2, "tampered leaf must change root");
        }
    }
});
