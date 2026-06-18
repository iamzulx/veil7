#![no_main]
use libfuzzer_sys::fuzz_target;
use veil7::interface;
use veil7::Claim;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    match data[0] % 9 {
        0 => { let _ = interface::attest_bytes(data); }
        1 => {
            if data.len() >= 32 {
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&data[..32]);
                let _ = interface::prove_hash_preimage(seed);
            }
        }
        2 => {
            if data.len() >= 64 {
                let mut value = [0u8; 32];
                let mut blinding = [0u8; 32];
                value.copy_from_slice(&data[..32]);
                blinding.copy_from_slice(&data[32..64]);
                let _ = interface::prove_pedersen(value, blinding);
            }
        }
        3 => {
            if data.len() > 8 {
                let leaves: Vec<&[u8]> = data[1..8].chunks(1).collect();
                if !leaves.is_empty() {
                    let index = (data[0] as usize) % leaves.len();
                    let _ = interface::prove_merkle(&leaves, index);
                }
            }
        }
        4 => {
            if data.len() >= 24 {
                let value = u64::from_le_bytes(data[0..8].try_into().unwrap());
                let min = u64::from_le_bytes(data[8..16].try_into().unwrap());
                let max = u64::from_le_bytes(data[16..24].try_into().unwrap());
                let (lo, hi) = if min <= max { (min, max) } else { (max, min) };
                let _ = interface::prove_range(value, lo, hi);
            }
        }
        5 => { let _ = interface::check_chain(&[data], &[0u8; 32]); }
        6 => {
            if data.len() >= 96 {
                let mut leaf = [0u8; 32];
                let mut root = [0u8; 32];
                leaf.copy_from_slice(&data[..32]);
                root.copy_from_slice(&data[32..64]);
                let index = usize::from_le_bytes(data[64..72].try_into().unwrap()) % 8;
                let leaf_count = ((data[72] as usize) % 4) + 1;
                let index = index % leaf_count;
                let siblings: Vec<[u8; 32]> = data[73..].chunks(32)
                    .filter(|c| c.len() == 32)
                    .map(|c| {
                        let mut s = [0u8; 32];
                        s.copy_from_slice(c);
                        s
                    })
                    .collect();
                let _ = interface::check_merkle(&leaf, &root, index, &siblings, leaf_count);
            }
        }
        7 => { let _ = interface::blind_claim(data); }
        8 => {
            if !data.is_empty() {
                let claim = Claim::new(data);
                let _ = veil7::verify_once(&claim);
            }
        }
        _ => {}
    }
});
