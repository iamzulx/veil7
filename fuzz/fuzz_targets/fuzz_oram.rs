#![no_main]
use libfuzzer_sys::fuzz_target;
use veil7::storage::ObliviousRAM;

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }
    let mut oram = ObliviousRAM::new();
    let mut pos = 0;

    while pos + 65 < data.len() {
        let op = data[pos];
        let addr = data[pos + 1] as usize;
        pos += 2;

        match op % 5 {
            0 => { let _ = oram.read(addr); }
            1 => {
                let mut val = [0u8; 64];
                let end = (pos + 64).min(data.len());
                let len = end - pos;
                val[..len].copy_from_slice(&data[pos..end]);
                oram.write(addr, val);
                pos += 64;
            }
            2 => {
                oram.read_modify_write(addr, |old| {
                    let mut new = old;
                    for b in new.iter_mut() { *b ^= 0xFF; }
                    new
                });
            }
            3 => {
                let addr2 = if pos < data.len() { data[pos] as usize } else { 0 };
                pos += 1;
                let _ = oram.swap(addr, addr2);
            }
            _ => { let _ = oram.read(addr); }
        }
    }
    // ORAM drops and zeroizes all slots
});