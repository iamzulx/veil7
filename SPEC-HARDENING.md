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

## Cache timing and T-table side channels

### Threat description

Modern CPUs expose data-dependent memory access patterns. Keccak-f[1600] (the
permutation underlying SHA-3 / SHAKE256) admits multiple software
implementations; the most common on x86\_64 and aarch64 uses **T-tables**
(256-entry lookup tables of 64-bit lanes) indexed by the state bytes.
Accessing a table entry pulls that cache line into L1/L2; a process on the
same physical core — or on a sibling core sharing L3 — can measure *which*
cache line was loaded and *when* by Flush+Reload, Prime+Probe, Evict+Time,
or simple L3-prime counters.

The result is a **per-byte key-recovery channel** for any secret that
flows into a T-table-indexed permutation. A 2021 paper (Arm/toy implementation
recoveries), the 2023 Raccoon side-channel against ML-KEM, and the 2025
Cloudflare/reduced-round Keccak regression all show that single-trace
cache-timing attacks against hash and lattice primitives are practical
on shared-cache hardware.

### Mechanism in veil7

| File | SHAKE256 role | Secret flowing in |
|------|---------------|-------------------|
| `entropy_sources.rs` | per-source whitening; final pool finalize | raw OS CSPRNG bytes, OS jitter, time-of-day |
| `layers/l1_entropy.rs` | entropy mix steps 1, 2, 3 | pool bytes |
| `layers/l2_keygen.rs` | KDF: domain-tagged seed → ML-KEM/ML-DSA sub-seeds | locked master seed |
| `layers/l3_commit.rs` | commitment hash binding identity + claim | claim bytes, identity context |
| `layers/l5_verify.rs` | transcript recompute (2 sites) | public message + prior transcript state |
| `layers/l7_emit.rs` | final emit hash | verdict + chain root |
| `relations/hash_preimage.rs` | preimage relation challenge hash | relation witness |
| `relations/merkle.rs` | Merkle node hash | tree node bytes |
| `common/transcript.rs` | global Fiat-Shamir transcript | public message bytes |
| `chain.rs` | chain-root accumulator | prior chain state |
| `execution/vm.rs` | VM state hash (lookup) | VM state bytes |
| `storage/oram.rs` | ORAM slot hash on read | slot contents, slot address |

The current `sha3` crate (RustCrypto, v0.10 series) is a **plain
lookup-table** implementation on both x86\_64 and aarch64. It is the
canonical pure-Rust Keccak and is the upstream choice across
RustCrypto PQ crates — `ml-kem`, `ml-dsa`, and `slh-dsa` all use the
same `sha3` crate internally, so this concern is not specific to
veil7's own SHAKE256 calls; it applies to the lattice and hash-based
signature operations too.

### What an attacker can extract

For a single SHAKE256 call where `secret` flows into the permutation:

- **Per-byte timing leakage** of the T-table index for each state byte.
- Across enough samples, recovery of the secret input (or of the
  intermediate state, which is sufficient to invert the KDF and recover
  the seed).
- Combined across calls, the attacker recovers the master seed →
  derives the ML-KEM/ML-DSA long-term secret keys via L2 → forges
  signatures via L4.

This is the same attacker model that makes **cloud multi-tenant
deployments** and **shared-CPU VMs** insecure for any constant-time
cryptographic library whose hash function is not bit-sliced. It is *not*
a concern on a single-tenant device (phone, dedicated hardware) where
the attacker has no co-resident code.

### Threat scenarios

| Deployment | Attacker capability | Risk |
|------------|---------------------|------|
| Single-tenant mobile (Termux, iOS, Android) | local app, no co-residency | **LOW** |
| Standalone laptop or workstation | local user only | **LOW** |
| Co-located VMs on shared-CPU cloud (AWS, GCP, Azure, Hetzner) | co-resident VM | **MEDIUM–HIGH** |
| Multi-tenant bare-metal host | same physical core, shared L3 | **HIGH** |
| Process inside a TEE/SGX enclave | enclave-internal malware | MEDIUM (mitigated by enclave boundary) |
| FDE/full-disk-encryption recovery of swapped memory | local root | covered by `Locked<N>` + mlock |

### Veil7 stance (documented, not patched)

Cache timing is **out of scope for Phase 1** of hardening, for three
reasons:

1. **Upstream-driven, not veil7-driven.** The leak lives inside the
   `sha3` crate, inside ML-KEM, ML-DSA, and SLH-DSA, and in our own 12
   SHAKE256 call sites. Patching the lookup-table implementation
   requires either a constant-time Keccak upstream (none exists in
   pure Rust at the time of writing) or a self-rolled bit-sliced
   Keccak, which is a multi-month cryptographic-engineering effort
   that is out of band for a hardening phase.
2. **Risk is deployment-shaped, not source-shaped.** The same code is
   low-risk on a phone and high-risk on a shared-CPU cloud. Patching
   would change the *source* but not the *risk profile* — the risk
   is decided by the deployment, not by the library.
3. **Existing hardening tests cannot detect this class.** Cache
   timing is not a property of the source; it is a property of the
   compiled binary running on a specific microarchitecture. Validating
   it requires hardware (`dudect`, `ctverif`) or static analysis that
   works on the disassembly, not on Rust source.

### What Phase 1 does do

- ✅ **Documents** the threat in this section so the risk is
  visible to every reviewer of `SPEC-HARDENING.md`.
- ✅ **Lists** every SHAKE256 call site (above table) so the
  blast-radius of any future constant-time Keccak replacement is
  explicit.
- ✅ **Documents** `sha3 = "0.10"` as a pinned dependency and notes
  the lookup-table implementation characteristic.
- ✅ **Flags** cache timing as a **Phase 2 backlog** item with
  `dudect`/`ctverif` as the validation path.
- ✅ **Recommends** deployment mitigations: single-tenant hardware,
  dedicated CPUs, cache-partitioning kernels (research/embedded),
  or process isolation in cloud deployments.

### What Phase 1 explicitly does not do

- ❌ Does not fork `sha3` to a bit-sliced implementation.
- ❌ Does not self-roll a constant-time Keccak inside veil7.
- ❌ Does not assert cache-timing safety in any acceptance criterion.
- ❌ Does not run `dudect`/`ctverif` (these require network access
  for advisories and target hardware that is not available in CI).

### Validation path (Phase 2)

```text
1. Pick a target microarchitecture (e.g. aarch64 Snapdragon 636 or
   x86_64 server class).
2. Implement a `dudect` harness: fixed-vs-random input to
   `Shake256::default().absorb(secret).squeeze(...)` with timing
   measurement on a tight loop.
3. Threshold: p < 0.0001 across ≥1M samples.
4. Same harness for `MlKem::derive`, `MlDsa::sign`, `SlhDsa::sign`
   using the upstream crate's internal SHAKE256 calls.
5. If leak detected: pin a CT-keccak fork, or accept the risk and
   document deployment requirements.
```

This is a **research-grade validation** requiring hardware access,
not a CI run. Phase 2 budgets a sprint to set it up.

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
