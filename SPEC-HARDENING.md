# veil7 Hardening Specification (Phase 1)

## Objective

Reduce side-channel and memory-hygiene risk in the stateless 7-layer pipeline,
with focus on:

- KyberSlash-class timing issues: secret-dependent division/remainder.
- Compiler optimization leaks: zeroize elision and wipe reordering.
- Secret-dependent branches/indexing in veil7-owned code.
- Memory-locking completeness and honest documentation of gaps.
- Regression prevention through tests and CI.

## Phase 1 status

**Complete for veil7-owned code.**

Residual risks remain in third-party PQ crates and target-specific hardware
behavior. Those require upstream audit, target disassembly review, and hardware
side-channel testing (`dudect`, `ctverif`, or equivalent).

## NIST PQC alignment (Juni 2026)

veill7 uses the canonical finalized NIST PQC standards:

| Standard | Algorithm | Security | Status | Used by veill7 |
|---|---|---|---|---|
| FIPS 202 (2015) | SHA-3 / SHAKE256 | 256-bit hash | Final | All layers |
| FIPS 203 (Aug 2024) | ML-KEM-768 | Cat 3 (~192-bit PQ) | **Final** | `l2_keygen` via `ml-kem 0.3.2` |
| FIPS 204 (Aug 2024) | ML-DSA-65 | Cat 3 (~192-bit PQ) | **Final** | `l4_prove` via `ml-dsa 0.1.0` |
| FIPS 205 (Aug 2024) | SLH-DSA-SHAKE-128f | Cat 1 (~128-bit PQ) | **Final** | `pq_backends/slh_dsa` |

**Security level choice**: ML-KEM-768 + ML-DSA-65 = NIST Category 3 (~192-bit
PQ). NIST IR 8547 requires ≥128-bit quantum-vulnerable algorithms be
disallowed after 2035. Cat 3 gives a substantial margin over that floor
and remains safe against projected quantum-computer scaling.

**FIPS 206 (FN-DSA / FALCON) — scaffold only, not integrated:**
* NIST submitted the FIPS 206 draft on 2025-08-28; final expected
  late 2026 / early 2027.
* RustCrypto does not yet publish a stable `fn-dsa` crate; pre-1.0 / RC
  upstream impls exist but pin to the draft and are unsafe to depend
  on for a long-lived codebase.
* `src/pq_backends/fn_dsa.rs` exists as a scaffold: public type
  surface (`SecretKey`, `PublicKey`, `SignatureBytes`,
  `verify -> Choice`) locked in, `verify` is a **fail-closed no-op**
  (`Choice::from(0u8)`) until a stable upstream crate is integrated.
  This is deliberate: a stub verifier must not emit false positives.
* Activation checklist in the file header.

**HQC and additional onramp signatures (Round 2):**
* HQC selected March 2025 as the 5th NIST PQC algorithm (code-based
  KEM) — not yet FIPS, no integration yet.
* Onramp Round 2 candidates (HAWK, UOV, Mayo, Mirath, Ryde, Perk,
  MQOM, etc.) — Round 2 deadline Feb 2025, evaluation ongoing, not
  yet selected.

**Quantum-vulnerable algorithms deprecated by NIST:**
* 112-bit security (RSA-2048, ECDSA-P224, DH-2048): deprecated
  after 2030, disallowed after 2035.
* ≥128-bit (RSA-3072, ECDSA-P256, Ed25519, X25519): disallowed
  after 2035.

veill7 does not use any of these classical primitives — all long-term
secrets (master seed, ephemeral keys) are protected by Cat-3 lattice
schemes (ML-KEM/ML-DSA) which remain post-quantum-secure against
projected quantum-computer scaling.

## Threat model

### In scope

- Local attacker observing timing, cache, branch prediction, or memory bus.
- Compiler dead-store elimination and movement of secret wipes.
- Swap/disk recovery of veil7-owned seed material.
- API regressions that expose `bool` verification instead of `subtle::Choice`.
- Accidental expansion of `unsafe` beyond the memory-locking module.

### Out of scope

- Physical fault injection, EM analysis, and power analysis.
- Malicious dependencies or supply-chain compromise.
- Formal proof of RustCrypto dependency constant-time behavior.
- Remote network timing; the library performs no networking.

## KyberSlash analysis and mitigation

### Exposure surface

| Location | Operation | Secret input | Status |
|----------|-----------|--------------|--------|
| `l1_entropy` | OS CSPRNG + SHAKE256 seed stretch | raw entropy / seed | ✅ veil7 source has no div/rem syntax |
| `l2_keygen` | derive ML-KEM + ML-DSA seeds | locked master seed | ✅ veil7 source has no div/rem syntax; upstream keygen assumed CT |
| `l4_prove` | ML-DSA deterministic sign | signing key | ⚠️ upstream CT assumption |
| `l5_verify` | ML-KEM encapsulate/decapsulate round-trip | KEM secret key | ⚠️ upstream CT assumption |
| `pq_backends/slh_dsa` | SLH-DSA sign/verify wrapper | secret key for signing | ⚠️ upstream CT assumption; wrapper returns `Choice` |
| `relations/*` | SHAKE256 and transcript operations | relation witnesses | ✅ no project-owned secret division |

### Implemented controls

- ✅ veil7 does not implement ML-KEM compression/decompression or lattice
  reductions itself.
- ✅ `tests/hardening.rs` scans veil7 secret-path source for `/`, `%`, `.div_*`,
  and `.rem_*`.
- ✅ `scripts/check-hardening.sh` runs hardening tests in CI.
- ✅ `scripts/scan-secret-div.py` scans symbolized hardening-profile disassembly
  and fails on `div`, `idiv`, `udiv`, or `sdiv` inside veil7 secret-path symbols.
- ✅ `SECURITY.md` documents pinned dependency versions and upstream CT
  assumptions.

### Dependency posture

Pinned dependency versions:

| Crate | Version | Status |
|-------|---------|--------|
| `ml-kem` | `0.3.2` | upstream RustCrypto; FIPS 203 final; KyberSlash-class safety treated as assumption |
| `ml-dsa` | `0.1.0` | upstream RustCrypto; FIPS 204 final; arithmetic CT treated as assumption |
| `slh-dsa` | `0.2.0-rc.5` | upstream RustCrypto; FIPS 205 final; wrapper normalized to `Choice` |
| `subtle` | `2.6.1` | constant-time `Choice` and equality |
| `zeroize` | `1.8.2` | upstream key zeroization |

Local source inspection of upstream PQ crates shows division/remainder-like syntax
exists in their source trees. This does not prove leakage, but it prevents a
formal Phase 1 claim about dependency CT safety. The Phase 1 claim is limited to
veil7-owned source and symbol-scoped disassembly.

## Zeroize completeness and compiler resistance

### Implemented controls

- ✅ `src/layers/l0_memlock.rs` provides `zeroize_bytes()` and `zeroize_u64()`:
  volatile writes plus `compiler_fence(Ordering::SeqCst)`.
- ✅ custom `Drop` implementations use `#[inline(never)]`.
- ✅ direct `.zeroize()` calls were removed from veil7-owned custom wipes.
- ✅ `tests/hardening.rs` fails if direct `.zeroize()` or `use zeroize::Zeroize`
  reappears in project-owned source.
- ✅ `tests/hardening.rs` fails if a custom `Drop` lacks `#[inline(never)]`.
- ✅ L6 remains an explicit scrub barrier that consumes ephemeral keys before the
  verdict is emitted.

### Known gap

`EphemeralKeys` contains opaque RustCrypto key types. Their secret fields are not
owned buffers veil7 can wipe with volatile stores or lock with `mlock` without
forking dependencies or adding broad unsafe wrappers. Phase 1 relies on their
`ZeroizeOnDrop` implementations and documents this in `SECURITY.md`.

## Constant-time verification

### Implemented controls

- ✅ `Verifier::verify` returns `Result<Choice, VeilError>`.
- ✅ `Relation::verify` implementations return `Result<Choice, VeilError>`.
- ✅ `SlhDsaSigner::verify` returns `Choice`.
- ✅ hardening tests include type-level checks for public verification boundaries.
- ✅ hardening tests scan for bool-returning `fn verify(...)-> bool` patterns.

`bool` may still appear for non-secret public predicates such as `is_locked()` or
length-validation helpers. The invariant is specifically: public verification
boundaries must not expose `bool`.

## Secret-dependent branches and indexing

### Implemented controls

- ✅ `storage/oram.rs` read path uses mask-based selection:
  `(old & !mask) | (new & mask)`.
- ✅ verification paths accumulate `Choice` rather than early-exiting on the first
  failed cryptographic check.
- ✅ malformed public inputs can still reject through normal branches; those are
  not secret-dependent.

## Memory locking

### Implemented controls

- ✅ `Locked<N>` keeps veil7-owned seed material in heap memory and attempts
  `mlock`.
- ✅ `Locked<N>::drop` wipes while memory is still resident, then calls
  `munlock` when locking succeeded.
- ✅ locking is best-effort and observable via `is_locked()`.

### Known gap

ML-KEM and ML-DSA secret keys are allocated inside upstream crates. Phase 1 does
not introduce unsafe placement wrappers. Recommended deployment mitigations:

disable swap, raise `RLIMIT_MEMLOCK`, or use a process profile/supervisor that
locks memory where available.

## CI and validation

### Implemented workflow

- ✅ `.github/workflows/rust.yml`: build, test, fmt, clippy, no-feature check.
- ✅ `.github/workflows/hardening.yml`: hardening guard suite and `cargo-audit`.
- ✅ removed self-triggering `workflow_run` loop from CI.

### Validation commands

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

## Acceptance criteria

| Criterion | Verification method | Status |
|-----------|---------------------|--------|
| No secret-dependent `div`/`rem` in veil7-owned secret paths | source guard + symbol-scoped objdump scan | ✅ complete for veil7 code |
| All custom `Drop` impls use `#[inline(never)]` + volatile write | hardening tests + code review | ✅ complete |
| All public `verify` boundaries return `Choice` | type-level hardening tests + source scan | ✅ complete |
| Upstream KyberSlash status documented | `SECURITY.md` pinned dependency posture | ✅ documented as upstream assumption |
| CI includes timing-leak instruction scan | `hardening.yml` + `scripts/scan-secret-div.py` | ✅ complete |
| `cargo-audit` clean | CI audit job + local command | ⏳ requires network/advisory DB at run time |
| Miri zeroize test | `cargo miri test` on nightly | ⏳ documented future validation |
| Hardware timing validation | `dudect`/`ctverif` on target hardware | ⏳ future Phase 2 |

## Phase 2 backlog

- Add target-specific `dudect` harnesses for fixed-vs-random seed/key paths.
- Run `cargo +nightly miri test` for memory safety and wipe-order regressions.
- Review RustCrypto PQ crate disassembly on target ARM cores.
- Track upstream audits or releases for `ml-kem`, `ml-dsa`, and `slh-dsa`.
- Consider dependency replacement or forking if upstream CT guarantees remain
  insufficient for high-assurance deployments.

## References

1. Cryspen KyberSlash / ML-KEM discussion: <https://cryspen.com/post/ml-kem-implementation>
2. FIPS 203: ML-KEM.
3. FIPS 204: ML-DSA.
4. FIPS 205 draft/final context: SLH-DSA.
5. `subtle` crate docs: <https://docs.rs/subtle>
6. `zeroize` crate docs: <https://docs.rs/zeroize>
