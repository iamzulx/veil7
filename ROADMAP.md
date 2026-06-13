# veil7 → Production Roadmap

> **Status:** Research-grade prototype. NOT production-ready.
> **Last updated:** 2026-06-14

---

## Current State

veil7 previously used RustCrypto crates which **explicitly** state:

> *"the implementation contained in this crate has never been independently audited! USE AT YOUR OWN RISK!"*
> — RustCrypto `ml-kem` README

**Update (2026-06-13):** ML-KEM-768 and ML-DSA-65 have been migrated to **libcrux** (hax/F* formally verified). RustCrypto `sha3` and `slh-dsa` remain as dependencies (no audited alternatives exist yet).

veil7 is a **research-grade prototype** with solid architecture (8.5/10).
To reach production, **4 phases** must be completed.

---

## 📊 Gap Analysis: Outstanding Items

| Category | Count | Status |
|----------|-------|--------|
| Security gaps (Phase 1 residual) | 7 | ⚠️ In progress |
| Phase 2 backlog items | 8 | 📋 Not started |
| Threat model exclusions | 7 | ⏸️ Accepted risk |
| Hardware validation required | 5 | 🔬 Needs physical tools |

---

## 🚦 PHASE 1: Foundation (1-2 months, ~$5K-15K)

**Goal:** Eliminate all gaps that can be resolved without external certification.

### 1.1 — Replace PQ Dependencies (CRITICAL 🔴)

| Before | Issue | Replaced With |
|--------|-------|---------------|
| `ml-kem 0.3` (RustCrypto) | Unaudited, +42% latency | `libcrux-ml-kem 0.0.9` (hax/F* verified) |
| `ml-dsa 0.1` (RustCrypto) | Unaudited | `libcrux-ml-dsa 0.0.9` (hax/F* verified) |
| `sha3 0.10` (RustCrypto) | T-table Keccak, cache-timing leak | Phase 2 (fork or libcrux SHA-3) |
| `slh-dsa 0.2-rc5` | Pre-release, unaudited | Awaiting stable release |

**Status:** ✅ COMPLETE — L2/L3/L4/L5 fully migrated to libcrux

- `src/pq_backends/libcrux_backend.rs` — adapter module (11 tests)
- `src/layers/l2_keygen.rs` — EphemeralKeys uses libcrux key pairs + Drop impl
- `src/layers/l3_commit.rs` — commitment uses libcrux key serialization
- `src/layers/l4_prove.rs` — Proof wraps MLDSA65Signature + Drop impl
- `src/layers/l5_verify.rs` — verify + KEM roundtrip via libcrux
- 347/347 tests pass (all layers verified end-to-end)
- fmt clean, clippy clean, no_std clean, release build clean

### 1.2 — CAVP Algorithm Validation (HIGH 🟠)

NIST provides **test vectors** (ACVP) for FIPS 203/204/205.
The implementation MUST produce identical output.

**Action:**
```
- [ ] Download NIST ACVP test vectors for ML-KEM-768, ML-DSA-65
- [ ] Write test harness: feed test vector → compare output
- [ ] Document results per algorithm
- [ ] Store as evidence for auditor
```

**Status:** ⏳ PENDING

### 1.3 — Supply Chain Security (HIGH 🟠)

```
- [x] cargo audit in CI (with RUSTSEC-2026-0173 ignore for libcrux transitive dep)
- [ ] cargo vet (dependency auditing)
- [ ] Pin exact versions in Cargo.lock
- [ ] Setup Dependabot/Renovate for monitoring
- [ ] Verify: no pqcrypto-* crates (unmaintained)
- [ ] SBOM (Software Bill of Materials) generation
```

**Status:** 🔄 IN PROGRESS (cargo audit done, remaining items pending)

### 1.4 — Miri Memory Safety (MEDIUM 🟡)

```
- [ ] cargo +nightly miri test
- [ ] Fix all Miri findings
- [ ] Add Miri to CI (nightly channel)
```

**Status:** ⏳ PENDING

### 1.5 — Missing Drop Implementations (MEDIUM 🟡)

```
- [x] l4_prove::Proof — zeroize 3309B ML-DSA signature (DONE in libcrux migration)
- [ ] blind::blind_claim return — wrap in Zeroizing<Vec<u8>>
- [ ] Verify all heap-allocated secrets have Drop
```

**Status:** 🔄 PARTIAL (Proof Drop added, remaining items pending)

---

## 🏗️ PHASE 2: Hardening (2-4 months, ~$25K-75K)

### 2.1 — Constant-Time Keccak (CRITICAL 🔴)

| Option | Effort | Risk |
|--------|--------|------|
| A. Fork sha3 → bit-sliced | 3-6 months | Lowest risk, most work |
| B. Use libcrux SHA-3 | 1-2 weeks | Medium risk, depends on libcrux |
| C. Accept risk + document | 0 | Only for single-tenant |

### 2.2 — dudect Hardware Validation (HIGH 🟠)

```
- [ ] Setup dudect harness (aarch64 + x86_64)
- [ ] Threshold: p < 0.0001 across ≥1M samples
- [ ] Test upstream: MlKem::derive, MlDsa::sign, SlhDsa::sign
```

### 2.3 — Formal Verification (MEDIUM 🟡)

```
- [ ] Kani model checking for L0→L7 pipeline
- [ ] Prove: no secret-dependent branches
- [ ] Prove: all secrets zeroized before scope exit
```

### 2.4 — Fuzzing Infrastructure (MEDIUM 🟡)

```
- [ ] cargo-fuzz (libFuzzer) for all public APIs
- [ ] AFL++ for CLI binary
- [ ] Minimum 72-hour fuzz run before release
```

---

## 📜 PHASE 3: Certification (6-18 months, $100K-$500K)

### 3.1 — FIPS 140-3

| Step | Timeline | Cost |
|------|----------|------|
| Define module boundary | 1-2 weeks | Internal |
| Select security level | 1 week | Internal |
| Engage NVLAP lab | 2-4 weeks | $50K-$200K |
| CAVP testing | 1-3 months | Included |
| Lab testing + report | 3-6 months | Lab cost |
| CMVP submission | 3-6 months | $10K-$50K |

### 3.2 — Side-Channel (Level 3+)

```
- [ ] ISO 17825 TVLA testing
- [ ] PQC-specific test vectors
- [ ] Fault injection resistance (Level 4)
```

### 3.3 — Compliance Documentation

```
- [ ] Cryptographic Policy document
- [ ] Key inventory
- [ ] IAM/RBAC policies
- [ ] Incident response plan
```

---

## 🚀 PHASE 4: Deployment (1-2 months, ~$10K-30K)

### 4.1 — Build & Release

```
- [ ] Reproducible builds
- [ ] Multi-arch binaries
- [ ] WASM build
- [ ] Docker image
- [ ] Signed releases
```

### 4.2 — Monitoring

```
- [ ] Metrics: latency, error rate, entropy quality
- [ ] Alerting: CSPRNG failure, timing variance
- [ ] Audit trail
```

### 4.3 — Deployment Constraints

| Environment | Risk | Readiness |
|-------------|------|-----------|
| Single-tenant phone/laptop | 🟢 LOW | ✅ After Phase 1 |
| Dedicated server | 🟢 LOW | ✅ After Phase 1 |
| Co-located cloud VM | 🟠 MED-HIGH | ⚠️ Needs Phase 2 |
| Multi-tenant bare metal | 🔴 HIGH | ❌ Needs Phase 2+3 |
| TEE/SGX enclave | 🟡 MEDIUM | ⚠️ Needs Phase 2 |

---

## 💰 Budget Summary

| Phase | Timeline | Cost | Priority |
|-------|----------|------|----------|
| Phase 1: Foundation | 1-2 months | $5K-$15K | 🔴 Must |
| Phase 2: Hardening | 2-4 months | $25K-$75K | 🟠 Should |
| Phase 3: Certification | 6-18 months | $100K-$500K | 🔵 If required |
| Phase 4: Deployment | 1-2 months | $10K-$30K | 🔴 Must |
| **TOTAL (minimal)** | **4-8 months** | **$40K-$120K** | |
| **TOTAL (full cert)** | **12-24 months** | **$140K-$620K** | |

---

## 📋 Master Checklist

### Pre-Production (Must-Have)
```
[x] Replace RustCrypto PQ with audited implementation (libcrux)
[x] Verify KyberSlash patches (libcrux is clean)
[ ] Pass NIST ACVP test vectors
[x] cargo audit clean (with documented exceptions)
[ ] cargo vet clean
[ ] Miri clean
[ ] dudect validation on target hardware
[x] All tests passing (347/347)
[ ] Fuzzing ≥ 72 hours
[ ] Documented cryptographic policy
[ ] Signed release binaries
[ ] SBOM generated
```

### Production Certification (Nice-to-Have)
```
[ ] FIPS 140-3 CMVP certificate
[ ] ISO 17825 side-channel report
[ ] Common Criteria EAL4+
[ ] SOC 2 Type II report
[ ] ISO 27001 certification
[ ] Penetration test report
```

---

## 📝 Changelog

| Date | Update |
|------|--------|
| 2026-06-13 | Initial roadmap created. Phase 1.1 started (replace RustCrypto PQ). |
| 2026-06-13 | ✅ libcrux adapter module complete (11/11 tests). |
| 2026-06-13 | ✅ L2/L3/L4/L5 fully migrated to libcrux. 347/347 tests pass. |
| 2026-06-14 | ✅ CI: Node.js 24 opt-in, RUSTSEC-2026-0173 ignored (libcrux transitive dep). |
| 2026-06-14 | Roadmap translated to English. Phase 1.2 (CAVP) and 1.3 (Supply Chain) started. |
