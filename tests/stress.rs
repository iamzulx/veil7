//! Multi-method stress tests — pushing veil7 to its limits.
//!
//! Tests extreme conditions: high concurrency, large inputs, repeated
//! iterations, edge cases, and cross-module stress scenarios.

#![cfg(feature = "std")]

use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Instant;
use veil7::{verify_once, Claim};

// ═══════════════════════════════════════════════════════════════════════════
// 1. Extreme Concurrency (32 threads × 10 iterations each)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_extreme_concurrency_32_threads() {
    let n_threads = 32;
    let n_iters = 10;
    let barrier = Arc::new(Barrier::new(n_threads));

    let handles: Vec<_> = (0..n_threads)
        .map(|tid| {
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                let mut results = Vec::new();
                for i in 0..n_iters {
                    let data = format!("thread-{}-iter-{}", tid, i);
                    let claim = Claim::new(data.as_bytes());
                    let result = verify_once(&claim);
                    results.push(result.is_ok());
                }
                results
            })
        })
        .collect();

    let mut total = 0;
    let mut passed = 0;
    for h in handles {
        let results = h.join().unwrap();
        for r in &results {
            total += 1;
            if *r {
                passed += 1;
            }
        }
    }
    assert_eq!(total, n_threads * n_iters, "all iterations must complete");
    assert_eq!(passed, total, "all iterations must pass");
    println!(
        "  stress_extreme_concurrency: {} threads × {} iters = {} total, all passed",
        n_threads, n_iters, total
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. Repeated Iteration Stress (500 sequential iterations)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_repeated_iterations_500() {
    let n = 500;
    let mut passed = 0;
    for i in 0..n {
        let data = format!("iteration-{}", i);
        let claim = Claim::new(data.as_bytes());
        if verify_once(&claim).is_ok() {
            passed += 1;
        }
    }
    assert_eq!(passed, n, "all {} iterations must pass", n);
    println!("  stress_repeated_iterations: {} iterations, all passed", n);
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. Large Input Stress (varying sizes from 1 byte to 64KB)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_large_inputs() {
    let sizes: Vec<usize> = vec![1, 16, 64, 256, 1024, 4096, 16384, 65536];
    for size in &sizes {
        let data = vec![0x42u8; *size];
        let claim = Claim::new(&data);
        let result = verify_once(&claim);
        assert!(
            result.is_ok(),
            "verify_once must succeed for input size {}",
            size
        );
    }
    println!("  stress_large_inputs: sizes {:?} all passed", sizes);
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. Edge Case Stress
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_edge_cases() {
    // Empty input
    let claim = Claim::new(b"");
    assert!(verify_once(&claim).is_ok(), "empty input must succeed");

    // Single byte
    let claim = Claim::new(&[0xFF]);
    assert!(verify_once(&claim).is_ok(), "single byte must succeed");

    // All zeros
    let data = vec![0u8; 1024];
    let claim = Claim::new(&data);
    assert!(verify_once(&claim).is_ok(), "all zeros must succeed");

    // All ones
    let data = vec![0xFFu8; 1024];
    let claim = Claim::new(&data);
    assert!(verify_once(&claim).is_ok(), "all ones must succeed");

    // Alternating pattern
    let data: Vec<u8> = (0..1024)
        .map(|i| if i % 2 == 0 { 0xAA } else { 0x55 })
        .collect();
    let claim = Claim::new(&data);
    assert!(
        verify_once(&claim).is_ok(),
        "alternating pattern must succeed"
    );

    println!("  stress_edge_cases: all edge cases passed");
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. Chain Stress (long chains)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_chain_long() {
    let n_events = 1000;
    let events: Vec<&[u8]> = (0..n_events)
        .map(|i| {
            // Use static-ish slices by formatting into a leaked string
            Box::leak(format!("event-{}", i).into_boxed_str()) as &str
        })
        .map(|s| s.as_bytes())
        .collect();

    let result = veil7::chain_root(&events);
    assert!(
        result.is_ok(),
        "chain_root must succeed for {} events",
        n_events
    );

    let root = result.unwrap();
    assert!(veil7::chain_verify(&events, &root).unwrap_u8() == 1);
    println!("  stress_chain_long: {} events, verified", n_events);
}

// ═══════════════════════════════════════════════════════════════════════════
// 6. Batch Verification Stress
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_batch_large() {
    let n = 50;
    let claims: Vec<Claim> = (0..n)
        .map(|i| {
            let data = Box::leak(format!("batch-{}", i).into_boxed_str());
            Claim::new(data.as_bytes())
        })
        .collect();

    let result = veil7::verify_batch(&claims);
    assert!(result.is_ok(), "batch of {} must succeed", n);
    assert!(result.unwrap().is_valid_bool());
    println!("  stress_batch_large: {} claims, all valid", n);
}

// ═══════════════════════════════════════════════════════════════════════════
// 7. MicroVM Stress (complex programs)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_microvm_complex_programs() {
    use veil7::execution::vm::{BytecodeBuilder, MicroVM};

    // Program 1: Fibonacci-like computation
    let mut builder = BytecodeBuilder::new();
    builder = builder.push(1).push(1);
    for _ in 0..20 {
        builder = builder.dup().add();
    }
    let code1 = builder.build();
    let mut vm = MicroVM::new();
    let root = vm.execute(&code1);
    assert_ne!(
        root, [0u8; 64],
        "Fibonacci program must produce non-zero root"
    );

    // Program 2: Bitwise operations chain
    let code2 = BytecodeBuilder::new()
        .push(0xDEADBEEF)
        .push(0xCAFEBABE)
        .xor()
        .dup()
        .push(0xFF)
        .and()
        .not()
        .build();
    let mut vm2 = MicroVM::new();
    let root2 = vm2.execute(&code2);
    assert_ne!(root2, [0u8; 64]);

    // Program 3: Shift operations
    let code3 = BytecodeBuilder::new()
        .push(1)
        .push(32)
        .shl() // 1 << 32
        .push(16)
        .shr() // >> 16
        .build();
    let mut vm3 = MicroVM::new();
    let root3 = vm3.execute(&code3);
    assert_ne!(root3, [0u8; 64]);

    println!("  stress_microvm_complex: 3 complex programs, all non-zero roots");
}

// ═══════════════════════════════════════════════════════════════════════════
// 8. Shamir Stress (various threshold configurations)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_shamir_various_thresholds() {
    use veil7::shamir::{reconstruct, split, Share};

    let configs: Vec<(u8, u8)> = vec![(2, 2), (3, 2), (5, 3), (10, 5), (10, 10)];

    for (n, t) in &configs {
        let secret = [0x42u8; 64];
        let shares = split(&secret, *n, *t).unwrap();
        assert_eq!(shares.len(), *n as usize);

        // Reconstruct from first t shares
        let subset: Vec<Share> = shares
            .iter()
            .take(*t as usize)
            .map(|s| Share {
                index: s.index,
                data: s.data,
            })
            .collect();
        let recovered = reconstruct(&subset).unwrap();
        assert_eq!(recovered, secret, "reconstruct({}, {}) must match", n, t);
    }
    println!("  stress_shamir_various: configs {:?} all passed", configs);
}

// ═══════════════════════════════════════════════════════════════════════════
// 9. ORAM Stress (many operations)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_oram_many_operations() {
    use veil7::storage::ObliviousRAM;

    let mut oram = ObliviousRAM::new();

    // Write to all 256 slots
    for i in 0..256 {
        let mut val = [0u8; 64];
        val[0] = i as u8;
        oram.write(i, val);
    }

    // Read back and verify
    for i in 0..256 {
        let val = oram.read(i);
        // Note: ORAM hashes values, so we compare against hash
        assert_ne!(val, [0u8; 64], "slot {} must be non-zero", i);
    }

    // Swap some slots
    oram.swap(0, 255);
    oram.swap(1, 254);

    // Read-modify-write
    let result = oram.read_modify_write(128, |old| {
        let mut new = old;
        for b in new.iter_mut() {
            *b = b.wrapping_add(1);
        }
        new
    });
    assert_ne!(result, [0u8; 64]);

    println!("  stress_oram_many: 256 writes + reads + swaps + RMW, all passed");
}

// ═══════════════════════════════════════════════════════════════════════════
// 10. Cross-Module Stress (all modules in sequence)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_cross_module_all() {
    use veil7::execution::vm::{BytecodeBuilder, MicroVM};
    use veil7::keccak_ct;
    use veil7::shamir::{reconstruct, split, Share};
    use veil7::storage::ObliviousRAM;

    // 1. Pipeline attestation
    let claim = Claim::new(b"cross-module-stress");
    let v = verify_once(&claim).unwrap();
    assert!(v.is_valid_bool());

    // 2. Chain attestation
    let events: &[&[u8]] = &[b"a", b"b", b"c", b"d", b"e"];
    let root = veil7::chain_root(events).unwrap();
    assert!(veil7::chain_verify(events, &root).unwrap_u8() == 1);

    // 3. MicroVM execution
    let code = BytecodeBuilder::new()
        .push(100)
        .push(200)
        .add()
        .push(3)
        .mul()
        .build();
    let mut vm = MicroVM::new();
    let vm_root = vm.execute(&code);
    assert_ne!(vm_root, [0u8; 64]);

    // 4. ORAM operations
    let mut oram = ObliviousRAM::new();
    oram.write(0, [0xAA; 64]);
    let val = oram.read(0);
    assert_ne!(val, [0u8; 64]);

    // 5. Shamir split/reconstruct
    let secret = [0x42u8; 64];
    let shares = split(&secret, 5, 3).unwrap();
    let subset: Vec<Share> = shares
        .iter()
        .take(3)
        .map(|s| Share {
            index: s.index,
            data: s.data,
        })
        .collect();
    let recovered = reconstruct(&subset).unwrap();
    assert_eq!(recovered, secret);

    // 6. CT SHAKE256
    let mut out = [0u8; 32];
    let _ = ct_shake256(b"cross-module-ct", &mut out);
    assert_ne!(out, [0u8; 32]);

    // 7. Relation proofs
    let witness = veil7::relations::hash_preimage::Witness { seed: [0xAB; 32] };
    let v2 =
        veil7::prove_and_verify::<veil7::relations::hash_preimage::HashPreimage>(&witness, b"")
            .unwrap();
    assert!(v2.is_valid_bool());

    // 8. Pedersen
    let pw = veil7::relations::pedersen::Witness {
        value: [0x11; 32],
        blinding: [0x22; 32],
    };
    let v3 = veil7::prove_and_verify::<veil7::relations::pedersen::PedersenCommitment>(&pw, b"")
        .unwrap();
    assert!(v3.is_valid_bool());

    println!("  stress_cross_module: 8 modules tested in sequence, all passed");
}

// Helper: use the ct_shake256 function
fn ct_shake256(data: &[u8], out: &mut [u8]) -> Result<(), veil7::VeilError> {
    veil7::keccak_ct::ct_shake256(data, out)
}

// ═══════════════════════════════════════════════════════════════════════════
// 11. Timing Consistency (verify no timing anomalies)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn stress_timing_consistency() {
    let n = 100;
    let mut times = Vec::new();

    for i in 0..n {
        let data = format!("timing-test-{}", i);
        let claim = Claim::new(data.as_bytes());
        let start = Instant::now();
        let _ = verify_once(&claim);
        times.push(start.elapsed());
    }

    // Calculate stats
    let avg: u128 = times.iter().map(|d| d.as_micros()).sum::<u128>() / n as u128;
    let min = times.iter().map(|d| d.as_micros()).min().unwrap();
    let max = times.iter().map(|d| d.as_micros()).max().unwrap();
    let spread = max - min;

    // Timing should be reasonably consistent (spread < 10x average)
    assert!(
        spread < avg * 10,
        "timing spread {}µs is too large (avg {}µs)",
        spread,
        avg
    );

    println!(
        "  stress_timing: {} iters, avg={}µs min={}µs max={}µs spread={}µs",
        n, avg, min, max, spread
    );
}
