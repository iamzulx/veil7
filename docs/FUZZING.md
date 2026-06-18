# Fuzzing Infrastructure

## Overview

veil7 includes comprehensive fuzz testing coverage for all public APIs using
**cargo-fuzz** (libFuzzer) and a 72-hour automated runner. The goal is to find
panics, memory safety issues, and unexpected behavior from malformed inputs.

## Quick Start

```bash
# Run single target (requires nightly)
cargo install cargo-fuzz && cargo fuzz run fuzz_verify_once -- -max_total_time=300

# Run all targets for 72 hours
./fuzz/fuzz_run_72h.sh

# Manual mode for Termux (stable Rust)
./fuzz/fuzz_run_72h.sh --manual
```

## Architecture

```
fuzz/
  Cargo.toml              # 25 fuzz targets, libfuzzer-sys dependency
  fuzz_run_72h.sh         # Automated 72-hour runner (cargo-fuzz or manual mode)
  fuzz_targets/           # Individual fuzz target harnesses (25 files)
  corpus/                 # Seed corpus (86 files across 25 targets)
```

## Targets (25)

### Core Pipeline
| Target | Module | Coverage |
|--------|--------|----------|
| fuzz_verify_once | pipeline | Full L1→L7 verify_once path |
| fuzz_attest_bytes | interface | attest_bytes public API |
| fuzz_interface_facade | interface | All 18 interface functions (dispatch) |

### Layer-Specific
| Target | Module | Coverage |
|--------|--------|----------|
| fuzz_shake256 | shake256 | SHAKE256 XOF wrapper |
| fuzz_oram | storage/oram | ORAM read/write/swap |
| fuzz_verify_once_oram | pipeline | ORAM-backed verification path |
| fuzz_verify_once_vm | pipeline | MicroVM-backed verification path |

### Relations (Generic Fiat-Shamir)
| Target | Module | Coverage |
|--------|--------|----------|
| fuzz_hash_preimage | relations | Lamport-style proof of knowledge |
| fuzz_pedersen | relations | SHAKE256 commitment opening |
| fuzz_range_proof | relations | Value range proof [min, max] |
| fuzz_merkle | relations | Merkle tree set membership |
| fuzz_merkle_verify | relations | Merkle path verification |

### Cryptographic Protocols
| Target | Module | Coverage |
|--------|--------|----------|
| fuzz_kem_roundtrip | pq_backends | ML-KEM-768 keypair → encaps → decaps |
| fuzz_dsa_sign_verify | pq_backends | ML-DSA-65 keypair → sign → verify |
| fuzz_shamir | shamir | Secret sharing (split/combine) |
| fuzz_blind_attest | blind | Blind attestation protocol |
| fuzz_commit_reveal | commit_reveal | Two-phase commit-reveal |
| fuzz_threshold | threshold | N-of-M threshold verification |
| fuzz_keccak_ct | keccak_ct | Masked SHAKE256 defense-in-depth |

### Chains and Batching
| Target | Module | Coverage |
|--------|--------|----------|
| fuzz_chain_root | chain | Tamper-evident chain root |
| fuzz_chain_verify | chain | Chain verification |
| fuzz_chain_builder | chain | ChainBuilder sequence operations |
| fuzz_batch_verify | pipeline | Batch verification path |

### Execution
| Target | Module | Coverage |
|--------|--------|----------|
| fuzz_microvm | execution/vm | MicroVM 17-opcode stack machine |
| fuzz_bytecode_builder | execution/vm | BytecodeBuilder opcode sequences |

## Seed Corpus

Each target has a `corpus/<target_name>/` directory with domain-specific seed
inputs (86 total across 25 targets). Seeds exercise:
- Byte boundaries (1, 32, 64, 128, 4096 bytes)
- Special values (all-zeros, all-0xFF, alternating)
- Domain-specific shapes (bytecode sequences, key-sized buffers, event chains)
- Edge cases (empty payloads, maximum-length inputs)

## Running Fuzz Targets

### Prerequisites

```bash
rustup default nightly    # Required for cargo-fuzz
cargo install cargo-fuzz
```

### Single Target

```bash
cargo fuzz run fuzz_verify_once -- -max_total_time=300 -max_len=4096
```

### All Targets (72-hour run)

```bash
bash fuzz_run_72h.sh --timeout-per-target 10800   # 3h per target
bash fuzz_run_72h.sh --manual                      # Termux / stable Rust
```

## CI Integration

GitHub Actions (`.github/workflows/rust.yml`) runs all 25 fuzz targets for
300 seconds each on every push/PR. Fuzz artifacts (crash inputs) are uploaded
for 30-day retention.

## Crash Handling

1. Crash input saved in `fuzz/artifacts/<target_name>/`
2. Reproduce: `cargo fuzz run <target> <crash_file>`
3. Minimize: `cargo fuzz tmin <target> <crash_file>`
4. Check for: panics, OOM, stack overflow, memory safety violations

## Key Principles

- **No panics in library code**: Fuzz targets catch panics as findings
- **Arbitrary byte input**: Each target accepts `&[u8]`, validates internally
- **Max input size**: 4096 bytes (configurable via `-max_len`)
- **Timeout**: 30 seconds per iteration (prevents infinite loops)

## Philosophy Compliance

- **NO logging**: Fuzz targets don't add logging, just exercise code paths
- **NO metadata**: No counters or telemetry in fuzz harnesses
- **Stateless**: Fuzz inputs are ephemeral, no persistent state
- **Wipe > leak**: Crashes reported without leaking internal state
- **Smaller surface**: No extra deps beyond libfuzzer-sys + veil7

## References

- [cargo-fuzz](https://rust-fuzz.github.io/book/)
- [libFuzzer](https://llvm.org/docs/LibFuzzer.html)
- [AFL++](https://aflplus.plus/) (alternative fuzzer, not currently integrated)
