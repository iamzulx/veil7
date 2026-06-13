# Security Policy

## Status

`veil7` is a research/educational post-quantum verification engine. It is not a
vetted security product and must not protect production secrets without an
independent cryptographic and side-channel audit.

Current hardening baseline: **Phase 1 complete for project-owned code**.

## Threat model

### In scope

- Local timing observers: cache, branch predictor, and coarse memory-bus timing.
- Compiler dead-store elimination and reordering around secret wipes.
- Swap/disk recovery of project-owned seed material.
- API regressions that convert constant-time `Choice` verification into `bool`.
- Accidental introduction of `unsafe` outside the memory-locking module.

### Out of scope

- Physical probing, fault injection, EM analysis, and power analysis.
- Malicious or compromised dependencies.
- Formal proof of third-party crate constant-time behavior.
- Remote network timing; the library performs no networking.
- The demo binary's stdout output. The library itself emits no logs.

## Invariants

- No logging crate in direct dependencies.
- No persistent state, telemetry, networking, files, timestamps, counters, or IDs.
- Release profile uses `panic = "abort"`, `strip = true`, and `debug = false`.
- `unsafe` is confined to `src/layers/l0_memlock.rs` for `mlock`/`munlock`.
- Project-owned secret wipes use volatile stores plus `compiler_fence`.
- Custom `Drop` impls are marked `#[inline(never)]`.
- Public verification boundaries return `subtle::Choice`, not `bool`.

## New module security considerations

### Blind Attestation (`src/blind.rs`)
- The engine attests data it never sees. The blind factor is held by the
  caller only; the engine has no access to the original claim.
- **Threat**: if the blind factor leaks, the blinded claim can be correlated
  to the original. The factor is `ZeroizeOnDrop` but lives in caller memory.
- **Mitigation**: callers must wipe the `BlindFactor` after use.

### Commit-Reveal Protocol (`src/commit_reveal.rs`)
- Two-phase attestation: commit returns a token + nonce, reveal verifies
  and runs the full pipeline.
- **Threat**: the nonce must be stored by the caller between phases. If
  lost, the reveal cannot proceed. If leaked, a third party could replay.
- **Mitigation**: the engine stores nothing between phases. Nonce security
  is the caller's responsibility.

### Threshold Verification (`src/threshold.rs`)
- Runs M independent iterations, requires N valid.
- **Threat**: if all M iterations run on the same hardware with correlated
  entropy sources, a single point of failure affects all iterations.
- **Mitigation**: each iteration harvests fresh entropy independently.

### Shamir Secret Sharing (`src/shamir.rs`)
- Splits a 64-byte seed into N shares with threshold T reconstruction.
- **Threat**: shares must be stored securely by the caller. Any T shares
  reconstruct the full secret.
- **Mitigation**: shares are `ZeroizeOnDrop`. GF(2^8) arithmetic has no
  secret-dependent branches or divisions.

### Range Proof (`src/relations/range_proof.rs`)
- Proves min ≤ value ≤ max via bit-decomposition + per-bit commitments.
- **Threat**: the proof reveals individual bits within the engine. Only
  the `Verdict` is emitted.
- **Mitigation**: all nonces are wiped on drop. Proof is verified within
  the same stateless iteration.

### Hybrid PQ+Classical (`src/hybrid.rs`)
- Dual-layer: ML-DSA-65 AND SHAKE256 MAC. Both must be valid.
- **Threat**: the classical MAC key is derived from the same entropy as
  PQ keys. If entropy is compromised, both layers fail.
- **Mitigation**: MAC key is wiped immediately after use. Defense-in-depth
  ensures that compromising one layer does not compromise the other.

### Constant-Time Keccak (`src/keccak_ct.rs`)
- Masked sponge approach: XOR input with random mask before SHAKE256.
- **Threat**: the mask is random per-instance, so T-table access patterns
  leak masked data, not the original secret.
- **Mitigation**: mask is `ZeroizeOnDrop`. This is a practical Phase 2
  mitigation, not a formal proof of constant-time.

## Pinned dependency posture

Pinned versions from `Cargo.lock`:

| Crate | Version | Role | Posture |
|-------|---------|------|---------|
| `ml-kem` | `0.3.2` | ML-KEM-768 / FIPS 203 | Upstream RustCrypto implementation; KyberSlash-class safety is treated as an upstream constant-time assumption. |
| `ml-dsa` | `0.1.0` | ML-DSA-65 / FIPS 204 | Upstream RustCrypto implementation; arithmetic constant-time behavior is an upstream assumption. |
| `slh-dsa` | `0.2.0-rc.5` | SLH-DSA / FIPS 205 candidate backend | Upstream release candidate; verification wrapper normalizes output to `Choice`. |
| `subtle` | `2.6.1` | Constant-time equality and `Choice` | Used at public verification boundaries and accumulators. |
| `zeroize` | `1.8.2` | Upstream key zeroization | Used by dependency key types; veil7-owned wipes use volatile L0 helpers. |

Local source scans show no division/remainder syntax in veil7 secret-path source.
Upstream PQ crates contain division/remainder-like syntax in their source trees;
that is not treated as a proof of leakage, but it means Phase 1 does **not**
claim formal dependency CT verification. Run hardware timing tests before any
high-assurance use.

## KyberSlash-class mitigation

`veil7` does not implement ML-KEM compression, decompression, Montgomery
reduction, or Barrett reduction itself. Project-owned secret paths are scanned
for `/`, `%`, `.div_*`, and `.rem_*` syntax. CI also builds a symbolized
hardening profile and fails if `objdump` reports `div`, `idiv`, `udiv`, or `sdiv`
in veil7 secret-path symbols.

The full binary can still contain division instructions from `std`, allocator
code, formatting code, or dependency public-data code. For that reason the CI
instruction scan is symbol-scoped, not a global `grep div`.

## Memory locking

`Locked<N>` pins seed material with `mlock` when the platform permits it and
wipes before `munlock`. Locking is best-effort: if `mlock` fails due to platform
policy or `RLIMIT_MEMLOCK`, the buffer still works and still wipes on drop.

Known gap: ML-KEM and ML-DSA secret keys are opaque upstream types and cannot be
placed in veil7's locked allocator without forking dependencies or adding broad
unsafe wrappers. They rely on upstream `ZeroizeOnDrop`. High-security deployments
should disable swap or use a process supervisor / OS profile that locks memory
where available.

## Validation commands

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo test --test hardening
cargo build --release
cargo check --no-default-features
bash scripts/check-hardening.sh
cargo audit --deny warnings
```

`cargo audit` requires `cargo-audit`. CI installs it before running.

## Hardware side-channel testing

Before using veil7 for sensitive material on a real target, run dedicated timing
analysis on the target CPU class:

- `dudect` style Welch's t-test harness for fixed-vs-random secrets.
- `ctverif`/formal verification where applicable.
- Target-specific disassembly review for secret-key operations in dependencies.
- Tests on the intended ARM core, frequency governor, and compiler version.

**Cache timing / T-table gap:** `sha3` 0.10 uses a T-table Keccak
implementation. Per-call lookup-table access patterns can leak absorbed
secret bytes on shared-cache hardware. The threat is documented in
`SPEC-HARDENING.md` §"Cache timing and T-table side channels". Phase 2
budgets a `dudect`/`ctverif` validation sprint for the target arch.

## Reporting issues

Do not include secrets, private keys, seed bytes, or full memory dumps in reports.
Provide:

- commit hash,
- Rust version and target triple,
- exact command,
- minimized reproducer,
- whether the issue is in veil7-owned code or a dependency path.
