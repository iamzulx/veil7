# veil7

A stateless, 7-layer universal post-quantum verification engine in pure Rust.

One iteration harvests fresh entropy, builds an ephemeral post-quantum identity,
proves a statement, verifies it in constant time, then wipes every secret — and
emits nothing but a single validity bit plus a correlation hash. No logs, no
metadata, no trace, no persisted state.

## Status

Verified on aarch64-android (Termux), Rust 1.95.0:

- `cargo build` / `cargo build --release` — clean
- `cargo test` — 51 tests, all passing
- `cargo clippy --all-targets -- -D warnings` — clean (zero warnings)
- `cargo fmt` — applied
- Release binary: ~448 KB, stripped (no symbols)
- ~2300 lines of Rust

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
- **Auto-zeroise** — all secret key material is `ZeroizeOnDrop` and is *also*
  explicitly scrubbed at the L6 barrier before the verdict is returned, so
  secrets never coexist with the emitted value.
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
| L1    | `l1_entropy`    | Harvest fresh OS CSPRNG entropy into a self-wiping, locked seed |
| L2    | `l2_keygen`     | Derive ephemeral ML-DSA-65 + ML-KEM-768 keypairs from the seed (deterministic, stateless, zeroising) |
| L3    | `l3_commit`     | Domain-separated SHAKE256 commitment to the claim under the ephemeral identity |
| L4    | `l4_prove`      | Generate the PQ proof (ML-DSA signature over the commitment) |
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

The transcript is bound to a per-relation `protocol_label`, so a proof for one
relation can never be replayed under another (Frozen-Heart guard).

## Run it

```sh
cargo run --release        # demo: runs all four pipelines, prints verdicts
cargo test                 # full suite (51 tests)
cargo clippy --all-targets -- -D warnings
```

Demo output is just verdicts — `valid=<bit>` and a transcript hash per run.
Deterministic relations (hash/ml_dsa/merkle) produce identical transcripts every
run because the digest binds to the *statement*, not to entropy. The legacy
ML-DSA pipeline produces a fresh transcript each run because it builds a new
ephemeral identity per iteration — visible proof of statelessness.

## Honesty / scope

This is a research/educational construction. It is correct and tested, but:

- Soundness of the Fiat-Shamir relations holds in the **Random Oracle Model**
  (SHAKE256 modelled as a random oracle).
- The PQ crates (`ml-dsa` 0.1, `ml-kem` 0.3) are **unaudited** pre-1.0 RustCrypto
  implementations.
- "Constant-time" relies on `subtle` and the underlying crates' own CT behavior;
  it has not been verified against a hardware side-channel model.

Do not use this to protect real production secrets. It is a clean, working
demonstration of the architecture, not a vetted security product.

## Layout

```
src/
  lib.rs            crate root, invariants, public API
  main.rs           demo binary (the only thing that prints)
  pipeline.rs       stateless L1->L7 orchestration + generic relation pipeline
  common/           domain tags, error type, Fiat-Shamir transcript
  layers/           L0..L7
  relations/        Relation trait + hash_preimage, ml_dsa, merkle
```
