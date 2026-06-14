#![no_main]
use libfuzzer_sys::fuzz_target;
use veil7::{verify_batch, Claim};

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let num_claims = (data[0] as usize % 5) + 1;
    let payload = &data[1..];
    let chunk_size = (payload.len() / num_claims).max(1);
    let claims: Vec<Claim> = payload.chunks(chunk_size)
        .take(num_claims)
        .map(|c| Claim::new(c))
        .collect();
    if claims.is_empty() {
        return;
    }
    let _ = verify_batch(&claims);
});
