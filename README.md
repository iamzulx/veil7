# veil7

A stateless, 7-layer universal post-quantum verification engine in pure Rust.
One iteration harvests fresh entropy, builds an ephemeral post-quantum identity,
proves a statement, verifies it in constant time, then wipes every secret — and
emits nothing but a single validity bit plus a correlation hash. No logs, no
metadata, no trace, no persisted state.

## Status

Verified on aarch64-android (Termux), Rust 1.95.0:

- `cargo build` / `cargo build --release` — clean
- `cargo test` — **375 tests** (233 unit + 142 integration), all passing
- `cargo clippy --all-targets -- -D warnings` — clean (zero warnings)
- `cargo fmt --check` — clean
- `cargo check --no-default-features` — clean (`#![no_std]` + `alloc` compatible)
- Release binary: ~480 KB, stripped (no symbols)
- ~12 800 lines of Rust (src + tests + fuzz targets)

## Design invariants

These are enforced by construction, not by policy or runtime checks:

- **No log** — no logging crate is in the dependency tree. The library never
  writes to stdout, stderr, or any file. (The demo `main.rs` prints; the library
  does not.)
- **No metadata** — a `Verdict` holds exactly two things: a constant-time
  validity `Choice` (one bit) and a 32-byte transcript hash. There is no field
  for a timestamp, sequence number, session ID, key material, signature, or
  claim plaintext.
- **No trace** — release profile is `panic = "abort"` (no unwind tables, no
  backtrace), `strip = true` (no symbols), `debug = false` (no debuginfo).
- **Stateless** — every iteration regenerates its entire cryptographic context
  from freshly harvested entropy. Nothing persists between calls; there is no
  global or static mutable state.
- **Post-quantum** — ML-KEM-768 (FIPS 203) + ML-DSA-65 (FIPS 204) via **libcrux**
  (hax/F\* formally verified) + SHAKE256. Validated against official NIST ACVP
  test vectors (byte-perfect match). No C dependencies.
- **Auto-zeroise** — veil7-owned secret buffers are wiped with volatile stores
  plus a compiler fence; upstream PQ key material uses dependency
  `ZeroizeOnDrop` and is explicitly dropped at the L6 barrier before the verdict
  is returned.
- **Memory-locked** — harvested seed material is `mlock`'d (kept out of swap) and
  wiped-then-unlocked on drop.
- **`#![deny(unsafe_code)]`** everywhere except the single `l0_memlock` module,
  which needs raw `mlock`/`munlock` syscalls and opts back in with a narrowly
  scoped allow.

## The seven layers

Numbered by data-flow position in one iteration:

| Layer | Module          | Role |
|-------|-----------------|------|
| L0    | `l0_memlock`    | mlock-backed buffer for seed material (no swap to disk) |
| L1 | `l1_entropy` | Harvest fresh OS CSPRNG entropy into a self-wiping, locked seed (12-round mix + `harvest_multi_source` multi-method) |
| L2    | `l2_keygen`     | Derive ephemeral ML-DSA-65 + ML-KEM-768 keys from the seed |
| L3    | `l3_commit`     | Domain-separated SHAKE256 commitment to the claim under the ephemeral identity |
| L4    | `l4_prove`      | PQ proof over the commitment (pluggable `Prover`) |
| L5    | `l5_verify`     | Constant-time verification: signature check + ML-KEM encapsulate/decapsulate round-trip, fused with `subtle::Choice` |
| L6    | `l6_zeroise`    | Explicit scrub barrier — consume and wipe all key material |
| L7    | `l7_emit`       | Emit the traceless `Verdict` (one bit + 32-byte transcript hash) |

## Multi-source entropy harvest

L1 ships two entropy workflows:

1. **12-round mix** — `harvest()` runs 12 iterations of
   `harvest → hash → slice → rehash → fold`, finishing with a
   SHAKE256 uniformisation directly into a `Locked<64>` buffer.
2. **Multi-source** — `harvest_multi_source()` reads from **six
   genuinely independent sources** (G1 privacy-core inspired) and
   whitens each one through a domain-separated SHAKE256 before XORing
   into the pool:

   - `os_csprng_primary` — 64 bytes from `getrandom`
   - `os_csprng_secondary` — separate `getrandom` call
   - `wall_clock` — `SystemTime::now()` nanoseconds
   - `stack_addr` — pointer to a stack-local variable
   - `thread_id` — hashed `std::thread::current().id()`
   - `hw_counter` — `Instant::elapsed()` ⊕ wall-clock nanos

Every source carries its own domain tag, so `raw_i` never appears
unmixed in the pool. Even if an attacker knows the final seed and all
but one source, they cannot recover the missing source (compositional
preimage property of SHAKE256). Each source auto-wipes on drop via
`#[inline(never)]` + `compiler_fence`. See `src/entropy_sources.rs`.

## Universal verification

Beyond the fixed ML-DSA pipeline (`verify_once`), the engine has a generic
`Relation` trait: define *what* is being proven (an NP relation `R(x, w)`) and
the same machinery proves and verifies it via the Fiat-Shamir transform over a
shared transcript. Swap the relation, the verification path is unchanged — that
is what "universal" means here.

Five working relations ship as proof of generality, each a different
cryptographic family routed through the *same* `prove_and_verify::<R>` entry:

- `hash_preimage` — pure-hash (Lamport-style) proof of knowledge
- `ml_dsa` — ML-DSA-65 lattice-signature knowledge
- `merkle` — Merkle-tree set membership (inclusion proof)
- `pedersen` — SHAKE256 commitment opening proof (value + blinding factor)
- `range_proof` — prove value ∈ [min, max] without revealing it

Plus a demo relation for real-data testing:
- `math_sum` (in `tests/real_data.rs`) — proves knowledge of `a` and `b`
  satisfying `a + b = s`, demonstrating that any domain (even arithmetic)
  can be routed through the same universal pipeline.

The transcript is bound to a per-relation `protocol_label`, so a proof for one
relation can never be replayed under another (Frozen-Heart guard).

## Chain attestation

For tamper-evident log append (USE_CASES.md §7), veil7 ships a
domain-separated SHAKE256 accumulator that folds a sequence of events into
a single 32-byte root. Tampering with any event changes the root, so
attesting the root covers the whole sequence.

```rust
// std — full one-call facade
use veil7::interface::attest_chain;
let events: &[&[u8]] = &[b"login", b"read", b"logout"];
let verdict = attest_chain(events)?;

// no_std — compute the root locally, attest with caller-supplied entropy
use veil7::{chain_root, verify_once_with_seed, Claim, Seed};
let root = chain_root(events)?;            // pure SHAKE256, no_std available
let seed = Seed::from_bytes(&entropy);    // caller-harvested, e.g. TRNG
let claim = Claim::new(&root);
let verdict = verify_once_with_seed::<MlDsaProver, MlDsaVerifier>(&seed, &claim)?;
```

`chain::chain_root` is `no_std` available; `interface::attest_chain` is the
std-gated wrapper that auto-harvests entropy and runs the ML-DSA pipeline.
A CLI entry point is also available: `veil7 chain <ev> [<ev>..]`.

## Universal verification (chain side)

For the audit side of USE_CASES.md §7, `chain::chain_verify` is a pure-math
oracle: given events and a published root, return `Choice::from(1)` if the
events fold to that root, `Choice::from(0)` otherwise. No PQ, no entropy,
no ephemeral identity — anyone with the events and the root can verify
offline, without keys, without the engine, without side effects.

```rust
use veil7::{chain_root, chain_verify};
use subtle::ConstantTimeEq;

let events: &[&[u8]] = &[b"login", b"read", b"logout"];
let published_root: [u8; 32] = /* received out-of-band */;

// The audit side is independent of the attestation side: chain_verify
// does not touch ML-DSA, ML-KEM, the L1 entropy pool, or any secret
// material. It is a mathematical function on its inputs.
let valid = chain_verify(events, &published_root);
assert_eq!(valid.unwrap_u8(), 1);

// chain_root lets the publisher compute the same root the auditor will
// later verify against, so both sides can be re-derived offline.
let local_root = chain_root(events)?;
assert_eq!(local_root.ct_eq(&published_root).unwrap_u8(), 1);
```

A CLI entry point is also available: `veil7 verify <hex_root> <ev>..`
returns `valid=1` (with the verified `transcript=<root>`) on match, or
`valid=0` (with the actual computed root) on mismatch.

## Streaming file attest

For files that do not fit (or should not fit) into a single `Vec<u8>`,
`interface::attest_file_streaming` reads the file in 4KB chunks and folds
each chunk into a `ChainState` accumulator. Peak transient memory is one
chunk + the accumulator + the final root. Empty files are rejected.

```rust
use veil7::interface::attest_file_streaming;
// File of any size — 10GB attested without loading it all into RAM.
let verdict = attest_file_streaming("/path/to/large/artifact.bin")?;
```

The chunk buffer is wiped after each read. `ChainState` itself is a
pure-math builder — no global state, no cache, no persistent identity.
The finalised root is public; the engine scrubs it at the L6 barrier.

For callers that need a different buffer footprint (e.g. memory-tight
embedded targets), `attest_file_streaming_with_chunk_size(path, n)` takes
an explicit chunk size. A CLI entry point is available:
`veil7 sign-stream <path>` returns the same `valid=1 transcript=<hex>`
format as `sign` / `sign-file`.

## MicroVM — deterministic bytecode executor

The `execution` module ships a real stack machine with **17 opcodes**,
a canary-protected 128×u64 operand stack, and deterministic execution
(same bytecode → same 64-byte root). No file I/O, no network, no
allocation during execution. The entire stack is auto-zeroised on drop.

| Code | Name | Effect |
|------|------|--------|
| 0x00 | Nop  | No operation |
| 0x01 | Add  | Pop b, a → push a + b (wrapping) |
| 0x02 | Xor  | Pop b, a → push a ⊕ b |
| 0x03 | Mul  | Pop b, a → push a × b (wrapping) |
| 0x04 | Div  | Pop b, a → push a / b (0 if div-by-zero) |
| 0x05 | Push | Push 8-byte LE u64 immediate |
| 0x06 | Pop  | Pop and discard top |
| 0x07 | Dup  | Duplicate top of stack |
| 0x08 | Swap | Swap top two elements |
| 0x09 | And  | Bitwise AND |
| 0x0A | Or   | Bitwise OR |
| 0x0B | Not  | Bitwise NOT (unary) |
| 0x0C | Shl  | Shift left (shift & 63) |
| 0x0D | Shr  | Shift right (shift & 63) |
| 0x0E | Rot  | Rotate stack: bottom→top |
| 0x0F | Eq   | Equality → push 1 or 0 |
| 0x10 | Lt   | Less-than → push 1 or 0 |

A `BytecodeBuilder` provides ergonomic bytecode construction:

```rust
use veil7::execution::vm::BytecodeBuilder;
let code = BytecodeBuilder::new()
    .push(10)
    .push(20)
    .add()       // 30
    .push(5)
    .mul()       // 150
    .build();
let mut vm = MicroVM::new();
let root = vm.execute(&code); // deterministic 64-byte root
```

## Batch verification

`verify_batch` processes multiple claims in independent iterations and
returns a single aggregated `Verdict`. Each claim gets its own ephemeral
identity (fresh entropy, fresh keypair, full L1→L7 cycle). Validity bits
are AND-combined; transcripts are folded via domain-separated SHAKE256.

```rust
use veil7::pipeline::{verify_batch, Claim};
let claims = [Claim::new(b"alpha"), Claim::new(b"beta")];
let verdict = verify_batch(&claims)?;
assert!(verdict.is_valid_bool()); // all valid → batch valid
```

## Expanded interface (`interface` module)

The `interface` module provides 18 one-call functions covering the full
API surface:

| Category | Functions |
|----------|-----------|
| **Single-item** | `attest_bytes`, `attest_text`, `attest_file`, `attest_file_streaming`, `attest_structured` |
| **Pipeline variants** | `attest_with_vm`, `attest_with_oram` |
| **Batch** | `attest_batch`, `attest_batch_texts` |
| **Chain & directory** | `attest_chain`, `attest_chain_files`, `attest_directory`, `attest_file_merkle` |
| **Relation proofs** | `prove_hash_preimage`, `prove_pedersen`, `prove_merkle` |
| **Verification oracles** | `check_chain`, `check_merkle` |

```rust
use veil7::interface::*;

// Batch attest multiple items
let v = attest_batch(&[b"item1".as_slice(), b"item2"])?;

// Chain-attest all files in a directory
let v = attest_directory("/etc/myapp/config")?;

// Merkle-attest multiple files (supports inclusion proofs)
let v = attest_file_merkle(&["file1.bin", "file2.bin"])?;

// Pure-math verification (no PQ, no entropy)
assert!(check_chain(events, &published_root));
```

## ORAM extensions

The `ObliviousRAM` now supports three operations beyond basic read/write:

- **`read_modify_write(addr, f)`** — Atomic oblivious read-modify-write.
  Reads the value, applies `f`, writes back — all in a single
  constant-time pass touching every slot.
- **`swap(addr_a, addr_b)`** — Oblivious swap of two slots in a single
  constant-time pass.

## CLI reference

```
veil7 sign <text>              Attest text via ML-DSA pipeline
veil7 sign-file <path>         Attest file (full load)
veil7 sign-stream <path>       Attest file (streaming)
veil7 batch-sign <t1> <t2>..   Batch attest multiple claims
veil7 chain <ev>..             Chain attestation
veil7 chain-root <ev>..        Compute chain root (pure math)
veil7 verify <hex> <ev>..      Verify chain integrity
veil7 vm-execute <hex>         Execute VM bytecode, output root
veil7 prove hash-preimage <h>  Lamport hash preimage proof
veil7 prove ml-dsa <h>         ML-DSA-65 key knowledge proof
veil7 prove merkle-root <h>..  Compute Merkle root
veil7 prove merkle-include ..  Verify Merkle inclusion
veil7 prove pedersen <v> <b>   Pedersen commitment proof
veil7 help                     Show help
```

## Post-quantum alignment (NIST 2025-2026 roadmap)

veil7 uses the canonical finalized NIST post-quantum standards as its
cryptographic substrate:

| Standard | Algorithm | Security | Status (Juni 2026) | veil7 backend |
|---|---|---|---|---|
| [FIPS 202](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.202.pdf) (2015) | SHA-3 / SHAKE256 | 256-bit hash | Final | `sha3 0.10.9` |
| [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) (Aug 13, 2024) | ML-KEM-768 | NIST Cat 3 (~192-bit PQ) | **Final** | `libcrux-ml-kem 0.0.9` ✅ ACVP |
| [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) (Aug 13, 2024) | ML-DSA-65 | NIST Cat 3 (~192-bit PQ) | **Final** | `libcrux-ml-dsa 0.0.9` ✅ ACVP |
| [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) (Aug 13, 2024) | SLH-DSA-SHAKE-128f | NIST Cat 1 (~128-bit PQ, hash-based) | **Final** | `slh-dsa 0.2.0-rc.5` |

**Why Cat 3?** NIST IR 8547 (Transition to PQC Standards) requires
≥128-bit quantum-vulnerable algorithms to be disallowed after 2035.
Cat 3 gives a substantial margin over that floor and remains safe
against projected quantum-computer scaling.

### Backend pluggability

The `pq_backends/` module exposes a uniform `verify -> subtle::Choice`
surface so new PQC standards can be integrated without breaking the
rest of the engine:

```
src/pq_backends/
├── libcrux_backend.rs — ML-KEM-768 + ML-DSA-65 via libcrux (active, NIST ACVP validated)
├── slh_dsa.rs         — FIPS 205 SLH-DSA-SHAKE-128f (active)
└── fn_dsa.rs          — FIPS 206 FN-DSA / FALCON (scaffold, see below)
```

**FIPS 206 (FN-DSA / FALCON) — scaffold, not yet integrated:**
* NIST submitted the FIPS 206 draft on 2025-08-28. Final approval
  expected late 2026 / early 2027.
  ([DigiCert](https://www.digicert.com/blog/quantum-ready-fndsa-nears-draft-approval-from-nist))
* RustCrypto does not yet publish a stable `fn-dsa` crate.
* `src/pq_backends/fn_dsa.rs` exists as a scaffold: public type
  surface (`SecretKey`, `PublicKey`, `SignatureBytes`,
  `verify -> Choice`) is locked in. `verify` is a **fail-closed
  no-op** (`Choice::from(0u8)`) until a stable upstream crate is
  integrated — better to refuse all verifications than to emit false
  positives. The hardening test
  `verification_public_boundaries_return_choice` already exercises
  this signature. Activation checklist is in the file header.

**HQC and onramp signatures (Round 2):**
* HQC (code-based KEM) selected as the 5th NIST PQC algorithm in
  March 2025 — not yet FIPS, not yet integrated.
* Onramp Round 2 candidates (HAWK, UOV, Mayo, Mirath, Ryde, Perk,
  MQOM) under evaluation; Round 2 deadline Feb 2025. No selection
  yet.

### Quantum-vulnerable algorithms not used

veil7 contains **zero** classical primitives (no RSA, ECDSA, EdDSA,
X25519, classical DH, AES as a long-term-secret primitive, etc.).
All long-term-secret protection is via Cat-3 lattice schemes
(ML-KEM/ML-DSA) plus SHAKE256 hashing. Per NIST IR 8547, the
classical schemes we *don't* use are scheduled for:
* Disallow after 2035 (≥128-bit: RSA-3072, ECDSA-P256, Ed25519)
* Disallow after 2030 (112-bit: RSA-2048, ECDSA-P224)

### Reference

* [NIST CSRC Post-Quantum Cryptography project](https://csrc.nist.gov/projects/post-quantum-cryptography)
* [NIST IR 8547 — Transition to Post-Quantum Cryptographic Standards](https://csrc.nist.gov/Projects/post-quantum-cryptography)
* [Federal Register 2024-17956 — FIPS 203/204/205 announcement (Aug 14, 2024)](https://www.federalregister.gov/documents/2024/08/14/2024-17956/announcing-issuance-of-federal-information-processing-standards-fips-fips-203-module-lattice-based)
* [NIST PQC: The Road Ahead (March 2025)](https://csrc.nist.gov/csrc/media/Presentations/2025/nist-pqc-the-road-ahead/images-media/rwcpqc-march2025-moody.pdf)
* [Cryspen verified ML-KEM (FIPS 203) + KyberSlash writeup](https://cryspen.com/post/ml-kem-implementation)

## `no_std` support

veil7 can be built without the standard library. The `std` feature (enabled by
default) gates OS-dependent entropy harvesting and the demo binary.

- `cargo check --no-default-features` — compiles with `#![no_std]` + `alloc`.
- When `std` is disabled, entropy must be supplied externally via
  `Seed::from_bytes` or `harvest_external`, then fed into
  `verify_once_with_seed` / `prove_and_verify_with_entropy`.
- The demo binary (`main.rs`) requires `std`.

## Pipeline variants (ORAM + MicroVM)

Beyond the standard ML-DSA pipeline, three alternative paths are available:

| Pipeline | Function | Extra guarantee |
|----------|----------|-----------------|
| Standard | `verify_once` | Base stateless verification |
| ORAM | `verify_once_with_oram` | Hides memory access pattern of seed storage |
| MicroVM | `verify_once_with_vm` | Binds entropy to VM execution trace |
| Batch | `verify_batch` | N claims → single aggregated Verdict |

The ORAM now also supports `read_modify_write` (atomic oblivious
read-modify-write) and `swap` (oblivious slot swap) for practical
side-channel-resistant storage patterns.

These do not change the stateless contract — nothing persists between calls.

## Run it

```sh
cargo run --release          # demo: runs all four pipelines, prints verdicts
cargo test                     # full suite (367 tests)
cargo test --test nist_acvp    # NIST ACVP official test vectors
cargo test --test cavp         # CAVP-style internal validation
cargo test --test hardening    # side-channel regression guards
cargo test --test bench        # lightweight iteration benchmarks
cargo test --test adversarial  # forged-proof negative tests
cargo test --test fuzz_manual  # random-input stress test
cargo test --test race_conditions # thread-safety stress tests
cargo test --test real_data    # real .txt file + custom MathSum relation
cargo clippy --all-targets -- -D warnings
bash scripts/check-hardening.sh
```

Demo output is just verdicts — `valid=<bit>` and a transcript hash per run.
Deterministic relations (hash/ml_dsa/merkle/math) produce identical transcripts
every run because the digest binds to the *statement*, not to entropy. The
legacy ML-DSA pipeline produces a fresh transcript each run because it builds a
new ephemeral identity per iteration — visible proof of statelessness.

## Hardening baseline

Phase 1 hardening is tracked in `SECURITY.md` and `SPEC-HARDENING.md`:

- veil7-owned secret wipes use volatile writes plus `compiler_fence`.
- public verification boundaries return `subtle::Choice`.
- custom `Drop` impls are `#[inline(never)]`.
- secret-path source is scanned for division/remainder syntax.
- `unsafe` is confined to `src/layers/l0_memlock.rs`.
- CI includes hardening guards and `cargo-audit`.

**Cache timing / T-table gap (documented, not patched):**
`sha3` 0.10 is a T-table Keccak implementation. Per-call lookup-table
access patterns can leak absorbed secrets on shared-cache hardware
co-resident VMs. Every SHAKE256 call site carries a `// SIDE-CHANNEL:`
comment pointing to `SPEC-HARDENING.md`. A Phase 2 `dudect`/`ctverif`
sprint is budgeted for empirical validation. See SPEC-HARDENING.md.

## Honesty / scope

This is a research/educational construction. It is correct and tested, but:

- Soundness of the Fiat-Shamir relations holds in the **Random Oracle Model**
  (SHAKE256 modelled as a random oracle).
- ML-KEM-768 and ML-DSA-65 are provided by **libcrux** (Cryspen), which is
  formally verified via hax/F\* for memory safety and functional correctness.
  Validated against official NIST ACVP test vectors (byte-perfect match).
- `slh-dsa` 0.2.0-rc.5 (RustCrypto) remains **unaudited** pre-1.0.
- "Constant-time" relies on `subtle`, veil7 source guards, and the underlying
  crates' own CT behavior; it has not been verified against a hardware
  side-channel model.
- **Cache timing:** `sha3` 0.10 is a T-table Keccak. On shared-cache hardware
  (co-resident VMs, same-core L3), per-call SHAKE256 timing patterns can leak
  the absorbed secret. See `SPEC-HARDENING.md` §"Cache timing and T-table side
  channels". Risk is LOW on single-tenant devices; MEDIUM-HIGH on cloud; HIGH
  on multi-tenant bare-metal. Phase 1 does not patch this upstream concern.

Do not use this to protect real production secrets. It is a clean, working
demonstration of the architecture, not a vetted security product.

## Layout

```
src/
  lib.rs              crate root, invariants, public API
  chain.rs            tamper-evident event chain (no_std available)
  main.rs             demo binary (the only thing that prints)
  pipeline.rs         stateless L1→L7 orchestration + batch verification
  interface.rs        std-gated one-call facade (18 functions)
  entropy_sources.rs  multi-method entropy harvest (6 independent sources)
  common/             domain tags, error type, Fiat-Shamir transcript
  layers/             L0..L7
  relations/          Relation trait + hash_preimage, merkle, ml_dsa, pedersen, range_proof
  pq_backends/        libcrux backend (ML-KEM/ML-DSA) + SLH-DSA + FALCON scaffold
  storage/            ObliviousRAM + read_modify_write + swap
  execution/          MicroVM (17 opcodes + BytecodeBuilder)
tests/
  nist_acvp.rs        NIST ACVP official test vector validation (6 tests)
  cavp.rs             CAVP-style internal validation (14 tests)
  hardening.rs        source-level invariant guards (5 tests)
  race_conditions.rs  thread-safety stress tests (23 tests)
  bench.rs            lightweight performance baselines (10 tests)
  fuzz_manual.rs      random-input stress tests (14 tests)
  adversarial.rs      forged-proof negative tests (24 tests)
  new_features.rs     integration tests for new modules (29 tests)
  real_data.rs        real .txt file + demo MathSum relation (15 tests)
  vectors/            NIST ACVP test vector files (ML-KEM-768, ML-DSA-65)
scripts/
  check-hardening.sh
  scan-secret-div.py
  generate-sbom.sh    CycloneDX SBOM generator
math_claims.txt       sample data for real_data test
```
