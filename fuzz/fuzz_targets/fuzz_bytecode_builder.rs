#![no_main]
use libfuzzer_sys::fuzz_target;
use veil7::execution::{BytecodeBuilder, MicroVM};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > 4096 {
        return;
    }
    match data[0] % 3 {
        0 => {
            let code: Vec<u8> = data[1..].iter().map(|b| b % 20).collect();
            let mut vm = MicroVM::new();
            let _ = vm.execute(&code);
        }
        1 => {
            let mut builder = BytecodeBuilder::new();
            for &byte in data.iter().skip(1) {
                builder = builder.op(byte);
            }
            let code = builder.build();
            let mut vm = MicroVM::new();
            let _ = vm.execute(&code);
        }
        2 => {
            let mut builder = BytecodeBuilder::new();
            for &byte in data.iter().skip(1) {
                match byte % 19 {
                    0 => builder = builder.nop(),
                    1 => {
                        let mut val_bytes = [0u8; 8];
                        for (i, &b) in data.iter().skip(2).take(8).enumerate() {
                            val_bytes[i] = b;
                        }
                        builder = builder.push(u64::from_le_bytes(val_bytes));
                    }
                    2 => builder = builder.add(),
                    3 => builder = builder.xor(),
                    4 => builder = builder.mul(),
                    5 => builder = builder.pop(),
                    6 => builder = builder.dup(),
                    7 => builder = builder.swap(),
                    8 => builder = builder.and(),
                    9 => builder = builder.or(),
                    10 => builder = builder.not(),
                    11 => builder = builder.shl(),
                    12 => builder = builder.shr(),
                    13 => builder = builder.rot(),
                    14 => builder = builder.eq(),
                    15 => builder = builder.lt(),
                    _ => builder = builder.nop(),
                }
            }
            let code = builder.build();
            let mut vm = MicroVM::new();
            let _ = vm.execute(&code);
        }
        _ => {}
    }
});
