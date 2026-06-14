#![no_main]
use libfuzzer_sys::fuzz_target;
use veil7::relations::hash_preimage::{HashPreimage, Witness};
use veil7::relations::Relation;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&data[..32]);
    let witness = Witness { seed };

    if let Ok((stmt, proof)) = HashPreimage::prove(&witness, &[]) {
        let result = HashPreimage::verify(&stmt, &proof);
        if let Ok(ok) = result {
            assert_eq!(ok.unwrap_u8(), 1, "honest proof must verify");
        }
    }
});
