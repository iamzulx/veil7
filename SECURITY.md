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

**Status: Base layer RESOLVED** — SHAKE256 now backed by libcrux-sha3 (formally
verified, constant-time, no T-tables). The T-table side-channel gap is closed
at the base level.

`keccak_ct.rs` provides an additional **defense-in-depth masked sponge** layer:
- Per-call `call_counter` ensures unique mask stream per `ct_update()` call,
  preventing mask reuse attacks on same-length inputs (audit fix H3).
- `CtShake256` has no `Default` impl (audit fix M1 — fixed mask was security risk).
- `ct_shake256()` returns `Result` (audit fix M2 — no silent fallback to fixed mask).
- Mask is `ZeroizeOnDrop`.

This is a practical defense-in-depth layer on top of libcrux's already
constant-time SHAKE256 implementation.

## Security audit findings (2026-06)

Full codebase security audit performed. Findings by severity:

### Resolved (fixed)

| ID | Severity | Finding | Fix |
|----|----------|---------|-----|
| H1 | HIGH | KEM private key: copy wiped, original persists in heap | `zeroize_slice()` in-place wipe via l0_memlock |
| H2 | HIGH | `Shake256Reader::read_extended()` resets position to 0 | Removed entirely (latent correctness bug) |
| H3 | HIGH | Mask stream reuse on same-length inputs | Added `call_counter` to CtShake256 |
| M1 | MEDIUM | `CtShake256::Default` uses fixed mask `[0xA5; 32]` | Removed `Default` impl |
| M2 | MEDIUM | `ct_shake256()` silently falls back to fixed mask | Returns `Result` (propagates CSPRNG error) |
| L2 | LOW | `Shake256Reader::read()` panics on overflow | Truncates + zero-fills (no panic) |
| L6 | LOW | `Commitment` Debug derive leaks bytes | Manual Debug impl redacts bytes |

### Accepted gaps (documented, not fixable at this layer)

| ID | Severity | Finding | Reason |
|----|----------|---------|--------|
| M3 | MEDIUM | `dsa_verify` timing depends on libcrux internals | Needs libcrux fork to fix |
| M4 | MEDIUM | SHAKE256 buffer in swappable heap | Would need `Locked<Vec>` refactor |
| M5 | MEDIUM | Raw entropy sources in unlocked heap | Would need `Locked` wrappers |
| L3 | LOW | Shared-page `munlock` could unlock another instance | Theoretical, needs per-page tracking |
| L4 | LOW | `derive()` return value in callee stack frame | Compiler likely inlines |
| L5 | LOW | Fragile Drop if `prove()` gains post-sign logic | No post-sign logic exists |

### Resolved at dependency level

| ID | Finding | Resolution |
|----|---------|------------|
| T-table Keccak | `sha3` uses T-tables (cache-timing leak) | Migrated to libcrux-sha3 (constant-time, no T-tables) |
| KyberSlash | Secret-dependent division in ML-KEM | Migrated to libcrux-ml-kem (formally verified CT) |

## Pinned dependency posture

Pinned versions from `Cargo.lock`:

| Crate | Version | Role | Posture |
|-------|---------|------|--------|
| `libcrux-ml-kem` | `0.0.9` | ML-KEM-768 / FIPS 203 | **Formally verified** (hax/F*). Constant-time, no T-tables. NIST ACVP validated (byte-perfect). |
| `libcrux-ml-dsa` | `0.0.9` | ML-DSA-65 / FIPS 204 | **Formally verified** (hax/F*). Constant-time. NIST ACVP validated (byte-perfect). |
| `libcrux-sha3` | `0.0.9` | SHAKE256 / FIPS 202 | **Formally verified** (hax/F*). Constant-time, no T-tables. |
| `slh-dsa` | `0.2.0-rc.5` | SLH-DSA / FIPS 205 | Upstream RustCrypto release candidate; verification wrapper normalizes output to `Choice`. |
| `subtle` | `2.6.1` | Constant-time equality and `Choice` | Used at public verification boundaries and accumulators. |
| `zeroize` | `1.8.2` | Upstream key zeroization | Used by dependency key types; veil7-owned wipes use volatile L0 helpers. |

**Migration note (2026-06):** ML-KEM, ML-DSA, and SHAKE256 have been migrated
from RustCrypto to **libcrux** (Cryspen, hax/F* formally verified). RustCrypto
`ml-kem`, `ml-dsa`, and `sha3` have been removed from `Cargo.toml`. All PQ
operations are now backed by formally verified, constant-time implementations.
NIST ACVP test vectors validated with byte-perfect match.

Local source scans show no division/remainder syntax in veil7 secret-path source.
libcrux is formally verified for constant-time behavior. `slh-dsa` (RustCrypto)
remains an upstream CT assumption until a libcrux or audited alternative is available.

## KyberSlash-class mitigation

**Status: RESOLVED** — ML-KEM and ML-DSA are now provided by libcrux (hax/F*
formally verified), which is constant-time by construction. The KyberSlash-class
vulnerability (secret-dependent division in compression/decompression) does not
apply to libcrux's implementation.

veil7-owned secret paths are still scanned for `/`, `%`, `.div_*`, and `.rem_*`
syntax as defense-in-depth. CI builds a symbolized hardening profile and fails
if `objdump` reports `div`, `idiv`, `udiv`, or `sdiv` in veil7 secret-path symbols.

## Memory locking

`Locked<N>` pins seed material with `mlock` when the platform permits it and
wipes before `munlock`. Locking is best-effort: if `mlock` fails due to platform
policy or `RLIMIT_MEMLOCK`, the buffer still works and still wipes on drop.

**KEM key wipe (audit fix H1):** libcrux's `MlKem768KeyPair` only provides
immutable access to private key bytes. `l0_memlock::zeroize_slice()` obtains a
mutable pointer from the immutable reference and wipes in-place using volatile
stores. The unsafe pointer cast is encapsulated in `l0_memlock` (the only module
permitted to use `unsafe`).

**Remaining gap:** ML-DSA signing key has mutable access and is wiped via
`zeroize_bytes()`. ML-KEM public key is not secret and not wiped.

High-security deployments should disable swap or use a process supervisor / OS
profile that locks memory where available.

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
