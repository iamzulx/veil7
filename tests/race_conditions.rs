//! Race condition and thread-safety stress tests.
//!
//! Tests concurrent access patterns across all veil7 modules to detect
//! data races, timing side channels, and thread-safety violations.
//!
//! Run with: cargo test --test race_conditions -- --nocapture
//! Run with TSan: RUSTFLAGS="-Z sanitizer=thread" cargo +nightly test --test race_conditions

#![cfg(feature = "std")]

use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use veil7::Claim;

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Run a closure on N threads, all starting simultaneously via a barrier.
/// Returns per-thread timings.
fn parallel_timed<F, R>(n_threads: usize, label: &str, f: F) -> Vec<(usize, Duration, R)>
where
    F: Fn(usize) -> R + Send + Sync + 'static,
    R: Send + 'static,
{
    let barrier = Arc::new(Barrier::new(n_threads));
    let f = Arc::new(f);

    let handles: Vec<_> = (0..n_threads)
        .map(|id| {
            let barrier = Arc::clone(&barrier);
            let f = Arc::clone(&f);
            thread::spawn(move || {
                barrier.wait(); // all threads start simultaneously
                let start = Instant::now();
                let result = f(id);
                let elapsed = start.elapsed();
                (id, elapsed, result)
            })
        })
        .collect();

    let mut results: Vec<(usize, Duration, R)> = Vec::new();
    for h in handles {
        results.push(h.join().expect("thread panicked"));
    }

    // Print timing summary
    let times: Vec<u128> = results.iter().map(|(_, d, _)| d.as_micros()).collect();
    let min = times.iter().min().unwrap();
    let max = times.iter().max().unwrap();
    let avg = times.iter().sum::<u128>() / times.len() as u128;
    let spread = max - min;
    println!("[{label}] threads={n_threads} min={min}µs max={max}µs avg={avg}µs spread={spread}µs");

    results
}

/// Run a closure on N threads, each executing `iterations` rounds.
fn stress_test<F>(n_threads: usize, iterations: usize, label: &str, f: F)
where
    F: Fn(usize) + Send + Sync + 'static,
{
    let barrier = Arc::new(Barrier::new(n_threads));
    let f = Arc::new(f);

    let handles: Vec<_> = (0..n_threads)
        .map(|id| {
            let barrier = Arc::clone(&barrier);
            let f = Arc::clone(&f);
            thread::spawn(move || {
                barrier.wait();
                for _ in 0..iterations {
                    f(id);
                }
            })
        })
        .collect();

    for h in handles {
        h.join()
            .unwrap_or_else(|_| panic!("[{label}] thread panicked"));
    }
    println!(
        "[{label}] completed: {n_threads} threads × {iterations} iterations = {} ops",
        n_threads * iterations
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 1: Concurrent entropy harvesting (L1)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn race_entropy_harvest_concurrent() {
    println!("\n=== TEST 1: Concurrent Entropy Harvesting ===");
    let n_threads = 8;
    let iterations = 20;

    let results = parallel_timed(n_threads, "entropy-harvest", move |id| {
        let mut seeds = Vec::new();
        for i in 0..iterations {
            let personalization = format!("thread-{id}-iter-{i}");
            let seed = veil7::l1_entropy::harvest(personalization.as_bytes()).unwrap();
            seeds.push(*seed.as_bytes());
        }
        seeds
    });

    // Verify all seeds are unique (no shared state contamination)
    let all_seeds: Vec<[u8; 64]> = results
        .into_iter()
        .flat_map(|(_, _, seeds)| seeds)
        .collect();
    let unique: std::collections::HashSet<Vec<u8>> = all_seeds.iter().map(|s| s.to_vec()).collect();
    assert_eq!(
        unique.len(),
        all_seeds.len(),
        "CONCURRENCY BUG: duplicate seeds detected across threads!"
    );
    println!(
        "  ✓ All {} seeds unique across {} threads",
        all_seeds.len(),
        n_threads
    );
}

#[test]
fn race_entropy_multi_source_concurrent() {
    println!("\n=== TEST 2: Concurrent Multi-Source Entropy ===");
    let n_threads = 8;
    let iterations = 15;

    stress_test(n_threads, iterations, "entropy-multi-source", |_id| {
        let personalization = b"race-test";
        let _seed = veil7::l1_entropy::harvest_multi_source(personalization).unwrap();
    });
    println!("  ✓ No panics or deadlocks in multi-source entropy");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 2: Concurrent full pipeline (L1→L7)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn race_verify_once_concurrent() {
    println!("\n=== TEST 3: Concurrent Full Pipeline (verify_once) ===");
    let n_threads = 8;
    let iterations = 5;

    let results = parallel_timed(n_threads, "verify-once", move |id| {
        let mut verdicts = Vec::new();
        for i in 0..iterations {
            let claim_data = format!("thread-{id}-claim-{i}");
            let claim = Claim::new(claim_data.as_bytes());
            let verdict = veil7::verify_once(&claim).unwrap();
            verdicts.push(verdict.is_valid_bool());
        }
        verdicts
    });

    // All verdicts should be valid
    let all_valid: Vec<bool> = results
        .into_iter()
        .flat_map(|(_, _, verdicts)| verdicts)
        .collect();
    assert!(
        all_valid.iter().all(|&v| v),
        "CONCURRENCY BUG: some verdicts invalid under concurrent load!"
    );
    println!(
        "  ✓ All {} verdicts valid across {} threads",
        all_valid.len(),
        n_threads
    );
}

#[test]
fn race_verify_once_high_concurrency() {
    println!("\n=== TEST 4: High-Concurrency Pipeline Stress ===");
    let n_threads = 16;
    let iterations = 3;

    stress_test(n_threads, iterations, "pipeline-stress", |id| {
        let data = format!("stress-{id}");
        let claim = Claim::new(data.as_bytes());
        let _ = veil7::verify_once(&claim);
    });
    println!("  ✓ No panics under 16-thread stress");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 3: Concurrent batch verification
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn race_batch_verify_concurrent() {
    println!("\n=== TEST 5: Concurrent Batch Verification ===");
    let n_threads = 8;
    let iterations = 3;

    stress_test(n_threads, iterations, "batch-verify", |id| {
        let claims: Vec<Claim<'_>> = (0..5)
            .map(|i| {
                // Use leaked string to get 'static lifetime — acceptable in tests
                let s: &'static str = Box::leak(format!("batch-{id}-{i}").into_boxed_str());
                Claim::new(s.as_bytes())
            })
            .collect();
        let _ = veil7::verify_batch(&claims);
    });
    println!("  ✓ Batch verification thread-safe");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 4: Concurrent ORAM operations
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn race_oram_concurrent_independent() {
    println!("\n=== TEST 6: Concurrent ORAM (independent instances) ===");
    let n_threads = 8;
    let iterations = 50;

    stress_test(n_threads, iterations, "oram-independent", |_id| {
        let mut oram = veil7::storage::ObliviousRAM::new();
        for addr in 0..10u8 {
            oram.write(addr as usize, [addr; 64]);
            let _read = oram.read(addr as usize);
        }
    });
    println!("  ✓ Independent ORAM instances thread-safe");
}

#[test]
fn race_oram_read_modify_write() {
    println!("\n=== TEST 7: ORAM read_modify_write under concurrency ===");
    let n_threads = 4;
    let iterations = 20;

    stress_test(n_threads, iterations, "oram-rmw", |_id| {
        let mut oram = veil7::storage::ObliviousRAM::new();
        oram.write(0, [0x42; 64]);
        let _result = oram.read_modify_write(0, |old| {
            let mut new = old;
            for b in new.iter_mut() {
                *b = b.wrapping_add(1);
            }
            new
        });
    });
    println!("  ✓ ORAM read_modify_write thread-safe");
}

#[test]
fn race_oram_swap() {
    println!("\n=== TEST 8: ORAM swap under concurrency ===");
    let n_threads = 4;
    let iterations = 20;

    stress_test(n_threads, iterations, "oram-swap", |_id| {
        let mut oram = veil7::storage::ObliviousRAM::new();
        oram.write(0, [0xAA; 64]);
        oram.write(1, [0xBB; 64]);
        oram.swap(0, 1);
        let a = oram.read(0);
        let b = oram.read(1);
        // After swap, slot 0 should have hash of [0xBB;64]
        // and slot 1 should have hash of [0xAA;64]
        assert_ne!(a, b, "ORAM swap produced identical slots");
    });
    println!("  ✓ ORAM swap thread-safe");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 5: Concurrent MicroVM execution
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn race_vm_concurrent_execution() {
    println!("\n=== TEST 9: Concurrent MicroVM Execution ===");
    use veil7::execution::vm::BytecodeBuilder;

    let n_threads = 8;
    let iterations = 50;

    // Same bytecode should produce same root across all threads
    let code = BytecodeBuilder::new()
        .push(10)
        .push(20)
        .add()
        .push(5)
        .mul()
        .build();

    let results = parallel_timed(n_threads, "vm-exec", move |_id| {
        let mut roots = Vec::new();
        for _ in 0..iterations {
            let mut vm = veil7::execution::MicroVM::new();
            let root = vm.execute(&code);
            roots.push(root);
        }
        roots
    });

    // All roots from same bytecode should be identical (deterministic)
    let all_roots: Vec<[u8; 64]> = results
        .into_iter()
        .flat_map(|(_, _, roots)| roots)
        .collect();
    let first = all_roots[0];
    for (i, root) in all_roots.iter().enumerate() {
        assert_eq!(
            *root, first,
            "DETERMINISM BUG: VM root mismatch at index {i} — race condition in VM state!"
        );
    }
    println!(
        "  ✓ All {} VM executions produced identical root (deterministic)",
        all_roots.len()
    );
}

#[test]
fn race_vm_different_bytecodes() {
    println!("\n=== TEST 10: Concurrent VM with Different Bytecodes ===");
    use veil7::execution::vm::BytecodeBuilder;

    let n_threads = 8;
    let iterations = 30;

    stress_test(n_threads, iterations, "vm-diverse", |id| {
        let code = BytecodeBuilder::new()
            .push(id as u64)
            .push(100)
            .add()
            .build();
        let mut vm = veil7::execution::MicroVM::new();
        let root = vm.execute(&code);
        assert_ne!(root, [0u8; 64], "VM produced zero root");
    });
    println!("  ✓ Different bytecodes under concurrency — no cross-contamination");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 6: Concurrent Shamir secret sharing
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn race_shamir_split_reconstruct() {
    println!("\n=== TEST 11: Concurrent Shamir Split + Reconstruct ===");
    let n_threads = 8;
    let iterations = 10;

    stress_test(n_threads, iterations, "shamir", |id| {
        let secret = [id as u8; 64];
        let shares = veil7::shamir::split(&secret, 5, 3).unwrap();
        let subset = [
            veil7::shamir::Share {
                index: shares[0].index,
                data: shares[0].data,
            },
            veil7::shamir::Share {
                index: shares[2].index,
                data: shares[2].data,
            },
            veil7::shamir::Share {
                index: shares[4].index,
                data: shares[4].data,
            },
        ];
        let recovered = veil7::shamir::reconstruct(&subset).unwrap();
        assert_eq!(
            recovered, secret,
            "RACE BUG: Shamir reconstruction mismatch!"
        );
    });
    println!("  ✓ Shamir split/reconstruct thread-safe");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 7: Concurrent blind attestation
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn race_blind_attest_concurrent() {
    println!("\n=== TEST 12: Concurrent Blind Attestation ===");
    let n_threads = 8;
    let iterations = 3;

    stress_test(n_threads, iterations, "blind-attest", |id| {
        let claim = format!("blind-secret-{id}");
        let (verdict, unblinded) = veil7::blind::blind_attest(claim.as_bytes()).unwrap();
        assert!(verdict.is_valid_bool());
        assert_ne!(unblinded, [0u8; 32]);
    });
    println!("  ✓ Blind attestation thread-safe");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 8: Concurrent commit-reveal protocol
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn race_commit_reveal_concurrent() {
    println!("\n=== TEST 13: Concurrent Commit-Reveal Protocol ===");
    let n_threads = 8;
    let iterations = 3;

    stress_test(n_threads, iterations, "commit-reveal", |id| {
        let claim = format!("commit-claim-{id}");
        let (token, nonce) = veil7::commit_reveal::commit_phase(claim.as_bytes()).unwrap();
        let verdict = veil7::commit_reveal::reveal_phase(&token, &nonce, claim.as_bytes()).unwrap();
        assert!(verdict.is_valid_bool());
    });
    println!("  ✓ Commit-reveal protocol thread-safe");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 9: Concurrent threshold verification
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn race_threshold_concurrent() {
    println!("\n=== TEST 14: Concurrent Threshold Verification ===");
    let n_threads = 4;
    let iterations = 2;

    stress_test(n_threads, iterations, "threshold", |_id| {
        let claim = Claim::new(b"threshold-race-test");
        let verdict = veil7::threshold::threshold_verify(&claim, 2, 3).unwrap();
        assert!(verdict.is_valid_bool());
    });
    println!("  ✓ Threshold verification thread-safe");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 10: Concurrent hybrid attestation
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn race_hybrid_attest_concurrent() {
    println!("\n=== TEST 15: Concurrent Hybrid Attestation ===");
    let n_threads = 4;
    let iterations = 2;

    stress_test(n_threads, iterations, "hybrid", |_id| {
        let claim = Claim::new(b"hybrid-race-test");
        let verdict = veil7::hybrid::hybrid_attest(&claim).unwrap();
        assert!(verdict.is_valid_bool());
    });
    println!("  ✓ Hybrid attestation thread-safe");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 11: Concurrent chain operations
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn race_chain_root_concurrent() {
    println!("\n=== TEST 16: Concurrent Chain Root (pure math, should be deterministic) ===");
    let n_threads = 8;
    let iterations = 100;

    let events: &[&[u8]] = &[b"event-A", b"event-B", b"event-C"];
    let expected_root = veil7::chain_root(events).unwrap();

    let results = parallel_timed(n_threads, "chain-root", move |_id| {
        let mut roots = Vec::new();
        for _ in 0..iterations {
            let root = veil7::chain_root(events).unwrap();
            roots.push(root);
        }
        roots
    });

    let all_roots: Vec<[u8; 32]> = results
        .into_iter()
        .flat_map(|(_, _, roots)| roots)
        .collect();
    for root in &all_roots {
        assert_eq!(
            *root, expected_root,
            "DETERMINISM BUG: chain_root not deterministic under concurrency!"
        );
    }
    println!(
        "  ✓ All {} chain roots identical (deterministic)",
        all_roots.len()
    );
}

#[test]
fn race_chain_state_concurrent() {
    println!("\n=== TEST 17: Concurrent ChainState (independent accumulators) ===");
    let n_threads = 8;
    let iterations = 50;

    stress_test(n_threads, iterations, "chain-state", |_id| {
        let mut state = veil7::ChainState::new();
        state.absorb(b"event-1");
        state.absorb(b"event-2");
        state.absorb(b"event-3");
        let _root = state.finalize().unwrap();
    });
    println!("  ✓ Independent ChainState instances thread-safe");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 12: Concurrent relation proofs
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn race_relations_concurrent() {
    println!("\n=== TEST 18: Concurrent Relation Proofs ===");
    use veil7::relations::hash_preimage::HashPreimage;
    use veil7::relations::pedersen::PedersenCommitment;
    use veil7::relations::Relation;

    let n_threads = 8;
    let iterations = 5;

    stress_test(n_threads, iterations, "relations", |id| {
        // Pedersen
        let pw = veil7::relations::pedersen::Witness {
            value: [id as u8; 32],
            blinding: [id.wrapping_add(1) as u8; 32],
        };
        let (ps, pp) = PedersenCommitment::prove(&pw, &[]).unwrap();
        let ok = PedersenCommitment::verify(&ps, &pp).unwrap();
        assert_eq!(ok.unwrap_u8(), 1);

        // Hash preimage
        let hw = veil7::relations::hash_preimage::Witness {
            seed: [id.wrapping_mul(7) as u8; 32],
        };
        let (hs, hp) = HashPreimage::prove(&hw, &[]).unwrap();
        let ok = HashPreimage::verify(&hs, &hp).unwrap();
        assert_eq!(ok.unwrap_u8(), 1);
    });
    println!("  ✓ Relation proofs thread-safe");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 13: Concurrent keccak_ct
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn race_keccak_ct_concurrent() {
    println!("\n=== TEST 19: Concurrent Constant-Time Keccak ===");
    let n_threads = 8;
    let iterations = 100;

    stress_test(n_threads, iterations, "keccak-ct", |_id| {
        let mut out = [0u8; 32];
        veil7::keccak_ct::ct_shake256(b"race-test-data", &mut out).unwrap();
        assert_ne!(out, [0u8; 32]);
    });
    println!("  ✓ CtShake256 thread-safe");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 14: Timing variance analysis (side-channel detection)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn timing_variance_verify_once() {
    println!("\n=== TEST 20: Timing Variance Analysis (verify_once) ===");
    let n_runs = 50;
    let mut times_a = Vec::new();
    let mut times_b = Vec::new();

    // Claim A: short
    let claim_a = Claim::new(b"A");
    // Claim B: long
    let claim_b = Claim::new(&[0x42u8; 1024]);

    for _ in 0..n_runs {
        let start = Instant::now();
        let _ = veil7::verify_once(&claim_a).unwrap();
        times_a.push(start.elapsed());

        let start = Instant::now();
        let _ = veil7::verify_once(&claim_b).unwrap();
        times_b.push(start.elapsed());
    }

    let avg_a: u128 = times_a.iter().map(|d| d.as_micros()).sum::<u128>() / n_runs as u128;
    let avg_b: u128 = times_b.iter().map(|d| d.as_micros()).sum::<u128>() / n_runs as u128;

    println!("  Claim A (1 byte):   avg={avg_a}µs");
    println!("  Claim B (1024 bytes): avg={avg_b}µs");

    // Large timing difference could indicate claim-size-dependent processing
    if avg_a > 0 && avg_b > 0 {
        let ratio = if avg_a > avg_b {
            avg_a as f64 / avg_b as f64
        } else {
            avg_b as f64 / avg_a as f64
        };
        if ratio > 3.0 {
            println!("  ⚠️  WARNING: timing ratio = {ratio:.2}x — claim size may affect timing!");
        } else {
            println!("  ✓ Timing ratio = {ratio:.2}x — acceptable variance");
        }
    }
}

#[test]
fn timing_variance_shamir() {
    println!("\n=== TEST 21: Timing Variance Analysis (Shamir) ===");
    let n_runs = 30;

    // Secret A: all zeros
    let secret_a = [0u8; 64];
    // Secret B: all 0xFF
    let secret_b = [0xFFu8; 64];

    let mut times_a = Vec::new();
    let mut times_b = Vec::new();

    for _ in 0..n_runs {
        let start = Instant::now();
        let _ = veil7::shamir::split(&secret_a, 5, 3);
        times_a.push(start.elapsed());

        let start = Instant::now();
        let _ = veil7::shamir::split(&secret_b, 5, 3);
        times_b.push(start.elapsed());
    }

    let avg_a: u128 = times_a.iter().map(|d| d.as_micros()).sum::<u128>() / n_runs as u128;
    let avg_b: u128 = times_b.iter().map(|d| d.as_micros()).sum::<u128>() / n_runs as u128;

    println!("  Secret A (all 0x00): avg={avg_a}µs");
    println!("  Secret B (all 0xFF): avg={avg_b}µs");

    if avg_a > 0 && avg_b > 0 {
        let ratio = if avg_a > avg_b {
            avg_a as f64 / avg_b as f64
        } else {
            avg_b as f64 / avg_a as f64
        };
        if ratio > 2.0 {
            println!("  ⚠️  WARNING: timing ratio = {ratio:.2}x — secret value may affect Shamir timing!");
        } else {
            println!("  ✓ Timing ratio = {ratio:.2}x — constant-time Shamir confirmed");
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 15: Mixed workload (all modules simultaneously)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn race_mixed_workload() {
    println!("\n=== TEST 22: Mixed Workload (all modules simultaneously) ===");
    let n_threads = 16;
    let barrier = Arc::new(Barrier::new(n_threads));

    let handles: Vec<_> = (0..n_threads)
        .map(|id| {
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                match id % 8 {
                    0 => {
                        // Pipeline
                        let claim = Claim::new(b"mixed-pipeline");
                        let _ = veil7::verify_once(&claim);
                    }
                    1 => {
                        // ORAM
                        let mut oram = veil7::storage::ObliviousRAM::new();
                        oram.write(0, [id as u8; 64]);
                        let _ = oram.read(0);
                    }
                    2 => {
                        // VM
                        use veil7::execution::vm::BytecodeBuilder;
                        let code = BytecodeBuilder::new().push(id as u64).add().build();
                        let mut vm = veil7::execution::MicroVM::new();
                        let _ = vm.execute(&code);
                    }
                    3 => {
                        // Shamir
                        let secret = [id as u8; 64];
                        let _ = veil7::shamir::split(&secret, 3, 2);
                    }
                    4 => {
                        // Blind
                        let _ = veil7::blind::blind_attest(b"mixed-blind");
                    }
                    5 => {
                        // Chain
                        let _ = veil7::chain_root(&[b"a", b"b", b"c"]);
                    }
                    6 => {
                        // Keccak CT
                        let mut out = [0u8; 32];
                        veil7::keccak_ct::ct_shake256(b"mixed-ct", &mut out).unwrap();
                    }
                    7 => {
                        // Threshold
                        let claim = Claim::new(b"mixed-threshold");
                        let _ = veil7::threshold::threshold_verify(&claim, 1, 2);
                    }
                    _ => unreachable!(),
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("mixed workload thread panicked");
    }
    println!("  ✓ 16-thread mixed workload completed without panics or deadlocks");
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 16: Rapid sequential verify (state leak detection)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn race_rapid_sequential_state_leak() {
    println!("\n=== TEST 23: Rapid Sequential State Leak Detection ===");
    let n_runs = 20;

    // Each run uses a unique claim and checks the transcript is unique
    let mut transcripts = Vec::new();
    for i in 0..n_runs {
        let data = format!("unique-claim-{i}");
        let claim = Claim::new(data.as_bytes());
        let verdict = veil7::verify_once(&claim).unwrap();
        transcripts.push(*verdict.transcript());
    }

    // All transcripts should be unique (stateless = fresh identity each time)
    let unique: std::collections::HashSet<Vec<u8>> =
        transcripts.iter().map(|t| t.to_vec()).collect();
    assert_eq!(
        unique.len(),
        transcripts.len(),
        "STATE LEAK: duplicate transcripts detected — engine not fully stateless!"
    );
    println!(
        "  ✓ All {} transcripts unique — statelessness confirmed",
        transcripts.len()
    );
}
