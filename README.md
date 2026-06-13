# veil7

A stateless, 7-layer universal post-quantum verification engine in pure Rust.
One iteration harvests fresh entropy, builds an ephemeral post-quantum identity,
proves a statement, verifies it in constant time, then wipes every secret — and
emits nothing but a single validity bit plus a correlation hash. No logs, no
metadata, no trace, no persisted state.

## Status

Verified on aarch64-android (Termux), Rust 1.95.0:

- `cargo build` / `cargo build --release` — clean
- `cargo test` — 153 tests (106 unit + 47 integration), all passing
- `cargo clippy --all-targets -- -D warnings` — clean (zero warnings)
- `cargo fmt --check` — clean
- `cargo check --no-default-features` — clean (`#![no_std]` + `alloc` compatible)
- Release binary: ~454 KB, stripped (no symbols)
- ~3 050 lines of Rust

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
- **Post-quantum** — ML-KEM-768 (FIPS 203) + ML-DSA-65 (FIPS 204) + SHAKE256,
  all pure-Rust RustCrypto crates (no C dependencies).
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

## Universal verification

Beyond the fixed ML-DSA pipeline (`verify_once`), the engine has a generic
`Relation` trait: define *what* is being proven (an NP relation `R(x, w)`) and
the same machinery proves and verifies it via the Fiat-Shamir transform over a
shared transcript. Swap the relation, the verification path is unchanged — that
is what "universal" means here.

Three working relations ship as proof of generality, each a different
cryptographic family routed through the *same* `prove_and_verify::<R>` entry:

- `hash_preimage` — pure-hash (Lamport-style) proof of knowledge
- `ml_dsa` — ML-DSA-65 lattice-signature knowledge
- `merkle` — Merkle-tree set membership (inclusion proof)

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

## Universal verification via the CLI

`prove <relation>` exposes the three built-in `Relation` implementations
to the shell. Each subcommand takes a hex-encoded witness / proof and
returns the engine's `valid=<0|1> transcript=<hex>` line.

```sh
# Lamport hash preimage: prove knowledge of a 32-byte secret.
veil7 prove hash-preimage 1111...11   # 64 hex chars
# → valid=1 transcript=5f9eb6...cadd

# Merkle root: pure-math tree root from a set of leaves.
veil7 prove merkle-root deadbeef cafebabe 12345678
# → root=c57652...f80e

# Merkle inclusion: verify a leaf authenticates against a root.
veil7 prove merkle-include <hex_leaf> <hex_root> <index> <hex_sib1> [<hex_sib2>..]
# → valid=1 transcript=<root>   (or valid=0)

# ML-DSA-65 key knowledge: prove knowledge of the seed behind a VK.
veil7 prove ml-dsa 1111...11
# → valid=1 transcript=...
```

The same relations are also reachable as `Relation` trait implementations
(`veil7::relations::{hash_preimage, merkle, ml_dsa}`) for callers that
want to compose them into their own pipelines.

## Post-quantum alignment (NIST 2025-2026 roadmap)

veill7 uses the canonical finalized NIST post-quantum standards as its
cryptographic substrate:

| Standard | Algorithm | Security | Status (Juni 2026) | veill7 backend |
|---|---|---|---|---|
| [FIPS 202](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.202.pdf) (2015) | SHA-3 / SHAKE256 | 256-bit hash | Final | `sha3 0.10.9` |
| [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) (Aug 13, 2024) | ML-KEM-768 | NIST Cat 3 (~192-bit PQ) | **Final** | `ml-kem 0.3.2` |
| [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) (Aug 13, 2024) | ML-DSA-65 | NIST Cat 3 (~192-bit PQ) | **Final** | `ml-dsa 0.1.0` |
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
├── slh_dsa.rs   — FIPS 205 SLH-DSA-SHAKE-128f (active)
└── fn_dsa.rs    — FIPS 206 FN-DSA / FALCON (scaffold, see below)
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

veill7 contains **zero** classical primitives (no RSA, ECDSA, EdDSA,
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

## Demo pipelines (ORAM + MicroVM)

Two optional paths exercise the `storage` and `execution` modules:
- `verify_once_with_oram` — stores the harvested seed in `ObliviousRAM` before
  keygen, reading it back via the constant-time ORAM path.
- `verify_once_with_vm` — executes the claim bytes through `MicroVM`, using the
  deterministic VM root as entropy personalization for the iteration.

These are demo integrations; they do not change the stateless contract (nothing
persists between calls).

## Run it

```sh
cargo run --release        # demo: runs all four pipelines, prints verdicts
cargo test                 # full suite (153 tests)
cargo test --test hardening # side-channel regression guards
cargo test --test bench     # lightweight iteration benchmarks
cargo test --test adversarial # forged-proof negative tests
cargo test --test fuzz_manual # random-input stress test
cargo test --test real_data   # real .txt file + custom MathSum relation
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

## Honesty / scope

This is a research/educational construction. It is correct and tested, but:

- Soundness of the Fiat-Shamir relations holds in the **Random Oracle Model**
  (SHAKE256 modelled as a random oracle).
- The PQ crates (`ml-dsa` 0.1, `ml-kem` 0.3, `slh-dsa` 0.2.0-rc.5) are
  **unaudited** pre-1.0 RustCrypto implementations.
- "Constant-time" relies on `subtle`, veil7 source guards, and the underlying
  crates' own CT behavior; it has not been verified against a hardware
  side-channel model.

Do not use this to protect real production secrets. It is a clean, working
demonstration of the architecture, not a vetted security product.

## Layout

```
src/
  lib.rs            crate root, invariants, public API
  chain.rs          tamper-evident event chain (no_std available)
  main.rs           demo binary (the only thing that prints)
  pipeline.rs       stateless L1->L7 orchestration + generic relation pipeline
  interface.rs      std-gated one-call facade (attest_bytes/text/file/chain)
  common/           domain tags, error type, Fiat-Shamir transcript
  layers/           L0..L7
  relations/        Relation trait + hash_preimage, merkle, ml_dsa
  pq_backends/      SLH-DSA backend
  storage/          ObliviousRAM
  execution/        MicroVM
tests/
  hardening.rs      source-level invariant guards
  bench.rs          lightweight performance baselines
  fuzz_manual.rs    random-input stress tests (no cargo-fuzz)
  adversarial.rs    forged-proof negative tests
  real_data.rs      real .txt file + demo MathSum relation
scripts/
  check-hardening.sh
  scan-secret-div.py
math_claims.txt    sample data for real_data test
```
