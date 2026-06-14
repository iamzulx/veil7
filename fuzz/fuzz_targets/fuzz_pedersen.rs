#![no_main]
use libfuzzer_sys::fuzz_target;
use veil7::relations::pedersen::{PedersenCommitment, Witness};
use veil7::relations::Relation;

fuzz_target!(|data: &[u8]| {
    if data.len() < 64 {
        return;
    }
    let mut value = [0u8; 32];
    let mut blinding = [0u8; 32];
    value.copy_from_slice(&data[..32]);
    blinding.copy_from_slice(&data[32..64]);
    let witness = Witness { value, blinding };

    if let Ok((stmt, proof)) = PedersenCommitment::prove(&witness, &[]) {
        let result = PedersenCommitment::verify(&stmt, &proof);
        if let Ok(ok) = result {
            assert_eq!(ok.unwrap_u8(), 1, "honest proof must verify");
        }
    }
});
