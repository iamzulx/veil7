#![no_main]
use libfuzzer_sys::fuzz_target;
use veil7::execution::MicroVM;

fuzz_target!(|data: &[u8]| {
    if data.len() < 1 || data.len() > 4096 {
        return;
    }
    let mut vm = MicroVM::new();
    let _root = vm.execute(data);
    // Goal: no panic, no crash regardless of bytecode
});
