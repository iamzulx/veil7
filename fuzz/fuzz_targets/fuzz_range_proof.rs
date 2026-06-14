#![no_main]
use libfuzzer_sys::fuzz_target;
use veil7::relations::range_proof::{RangeProof, Witness};
use veil7::relations::Relation;

fuzz_target!(|data: &[u8]| {
    if data.len() < 24 {
        return;
    }
    let value = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let min = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let max = u64::from_le_bytes(data[16..24].try_into().unwrap());

    // Ensure min <= max
    let (min, max) = if min <= max { (min, max) } else { (max, min) };
    if min == max { return; }

    let witness = Witness { value, min, max };
    let _ = RangeProof::prove(&witness, &[]);
    // May fail if value is out of range — that's expected
});
