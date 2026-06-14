# veil7 — CLAUDE.md

## Read this before changing anything

This repository is built around a blunt privacy philosophy:

> no logs, no metadata, no trace, stateless verification, aggressive autowipe/zeroize,
> absolute privacy orientation, and post-quantum readiness by default.

Do not dilute that philosophy for ergonomics, debugging, observability, or framework convenience.

---

## Core philosophy — absolute, non-negotiable

- **NO logging.** No `log::*`, `println!`, `eprintln!`, `dbg!`, `tracing`, debug output, telemetry, or analytics from library code.
- **NO metadata.** No counters, timestamps, heights, IDs, sessions, cache keys, implicit context, or verbose serialization.
- **NO traces.** No exposed stack traces. No panic text that leaks internals. No rich error chain crossing public boundaries.
- **NO persistent state.** No cache, database, session, recovery file, background index, or retained temp material.
- **WIPE outside boundary.** If data crosses or fails a trusted transition boundary, zeroize it or reject it.
- **Verification through entropy + mathematics.** Avoid trust in runtime narrative, logs, or external state.
- **Math over abstraction.** Add abstraction only when it preserves or strengthens the privacy proof surface.
- **Silence over explanation.** Runtime failure should not explain secrets.

---

## Architecture

```
src/
  lib.rs              crate root, invariants, public API
  main.rs             demo binary (the only thing that prints)
  pipeline.rs         stateless L1→L7 orchestration + generic relation pipeline + batch
  interface.rs        std-gated one-call facade (18 functions)
  chain.rs            tamper-evident event chain (no_std available)
  entropy_sources.rs  multi-method entropy harvest (6 independent sources)
  shake256.rs         SHAKE256 wrapper around libcrux-sha3 (constant-time, no T-tables)
  blind.rs            blind attestation (engine never sees plaintext)
  commit_reveal.rs    two-phase commit-reveal protocol
  hybrid.rs           hybrid PQ+classical dual-layer attestation
  keccak_ct.rs        defense-in-depth masked SHAKE256 wrapper
  shamir.rs           Shamir secret sharing (constant-time GF(2^8))
  threshold.rs        N-of-M threshold verification
  common/             domain tags, error type, Fiat-Shamir transcript
  layers/             L0..L7 (entropy → zeroise → emit)
  relations/          Relation trait + hash_preimage, merkle, ml_dsa, pedersen, range_proof
  pq_backends/        libcrux backend (ML-KEM/ML-DSA) + SLH-DSA + FALCON scaffold
  storage/            ORAM (ObliviousRAM + read_modify_write + swap)
  execution/          MicroVM (17-opcode stack machine + BytecodeBuilder)
fuzz/
  fuzz_targets/       15 fuzz targets (cargo-fuzz / libFuzzer)
docs/
  CRYPTO_POLICY.md    approved algorithms, key lifecycle, compliance
  IAM_RBAC.md         roles, access control, separation of duties
  KEY_INVENTORY.md    all key types, lifecycle, protection mechanisms
  INCIDENT_RESPONSE.md classification, procedures, communication plan
  MONITORING.md       metrics, alerting, Prometheus integration
```

Seven layers, numbered by data-flow position in one iteration:

| Layer | Module | Role |
|-------|--------|------|
| L0 | `l0_memlock` | mlock-backed buffer for seed material |
| L1 | `l1_entropy` | Harvest fresh OS CSPRNG entropy |
| L2 | `l2_keygen` | Derive ephemeral ML-DSA-65 + ML-KEM-768 keypairs |
| L3 | `l3_commit` | Domain-separated SHAKE256 commitment |
| L4 | `l4_prove` | Generate PQ proof |
| L5 | `l5_verify` | Constant-time verification |
| L6 | `l6_zeroise` | Explicit scrub barrier |
| L7 | `l7_emit` | Emit traceless Verdict |

## Universal verification

Beyond the fixed ML-DSA pipeline (`verify_once`), the engine has a generic
`Relation` trait: define *what* is being proven and the same machinery proves
and verifies it via Fiat-Shamir. Swap the relation, the verification path is
unchanged.

Five working relations ship as proof of generality:
- `hash_preimage` — Lamport-style proof of knowledge
- `ml_dsa` — ML-DSA-65 lattice-signature knowledge
- `merkle` — Merkle-tree set membership
- `pedersen` — SHAKE256 commitment opening (value + blinding)
- `range_proof` — prove value in [min, max] without revealing it

## Dependencies policy

Default approved:
- `libcrux-sha3` — SHAKE256 (formally verified, constant-time, no T-tables)
- `libcrux-ml-kem` — ML-KEM-768 (FIPS 203, hax/F* verified)
- `libcrux-ml-dsa` — ML-DSA-65 (FIPS 204, hax/F* verified)
- `slh-dsa` — SLH-DSA-SHAKE-128f (FIPS 205)
- `getrandom` — OS entropy (optional, std feature)
- `zeroize` — wipe secrets
- `subtle` — constant-time
- `libc` — mlock/munlock syscalls (optional, std feature)

Never add without explicit approval:
- logging/tracing crates
- async/network runtimes
- HTTP/RPC clients
- telemetry/crash reporting
- hidden state/cache managers

## Verification matrix

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```

## Side-channel threat model (documented assumption)

veil7 uses `sha3` 0.10 (RustCrypto) which is a **T-table Keccak**
implementation. This is a per-call cache-timing side channel against
the absorbed secret on shared-cache hardware (Flush+Reload, Prime+Probe,
Evict+Time on co-resident VMs / same-core L3). The 12 SHAKE256 call
sites in veil7-owned code each carry a `// SIDE-CHANNEL:` comment
pointing to `SPEC-HARDENING.md` §"Cache timing and T-table side channels",
which lists every call site, the secret class that flows in, and the
risk class per deployment (LOW on single-tenant hardware, MEDIUM-HIGH
on shared-CPU cloud, HIGH on multi-tenant bare-metal).

**The threat is documented as an accepted Phase 1 gap** — patching
requires either a constant-time Keccak upstream (none exists in pure
Rust) or a self-rolled bit-sliced implementation, both of which are
out of scope for hardening. Phase 2 budgets a `dudect`/`ctverif`
hardware validation sprint.

The same caveat applies to all RustCrypto PQ crates (`ml-kem`, `ml-dsa`,
`slh-dsa`) which use the same `sha3` crate internally. Phase 1 does not
fork or replace them.

## When in doubt

- Wipe > leak
- Refuse > guess
- Math > abstraction
- Silence > explanation
- Smaller surface > convenience
