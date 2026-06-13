# veil7 → Production Roadmap

> **Status:** Research-grade prototype. NOT production-ready.
> **Last updated:** 2026-06-13

---

## Realita Saat Ini

veil7 menggunakan RustCrypto crates yang **secara eksplisit** menyatakan:

> *"the implementation contained in this crate has never been independently audited! USE AT YOUR OWN RISK!"*
> — RustCrypto `ml-kem` README

veil7 adalah **research-grade prototype** dengan arsitektur yang solid (8.5/10).
Untuk masuk production, ada **4 fase** yang harus dilalui.

---

## 📊 Gap Analysis: 29 Outstanding Items

| Kategori | Count | Status |
|----------|-------|--------|
| Gap keamanan (Phase 1 residual) | 9 | ⚠️ Belum selesai |
| Phase 2 backlog items | 8 | 📋 Belum dimulai |
| Threat model exclusions | 7 | ⏸️ Accepted risk |
| Hardware validation required | 5 | 🔬 Butuh alat fisik |

---

## 🚦 FASE 1: Fondasi (1-2 bulan, ~$5K-15K)

**Tujuan:** Hapus semua gap yang bisa diselesaikan tanpa sertifikasi eksternal.

### 1.1 — Ganti Dependency PQ (CRITICAL 🔴)

| Sekarang | Masalah | Ganti Dengan |
|----------|---------|-------------|
| `ml-kem 0.3` (RustCrypto) | Unaudited, +42% latency overhead | `aws-lc-rs` (AWS-backed) atau `libcrux` (formal verified) |
| `ml-dsa 0.1` (RustCrypto) | Unaudited | `aws-lc-rs` atau `libcrux` |
| `sha3 0.10` (RustCrypto) | T-table Keccak, cache-timing leak | Fork constant-time atau `libcrux` |
| `slh-dsa 0.2-rc5` | Pre-release, unaudited | Tunggu stable release |

**Action:**
```
- Fork veil7 → branch production-ready
- Replace ml-kem/ml-dsa with aws-lc-rs wrappers
- Verify KyberSlash patches (Dec 2023/Jan 2024)
- Benchmark: target < 100ms per verify_once
```

**Status:** ✅ COMPLETE — L2/L3/L4/L5 fully migrated to libcrux

- `src/pq_backends/libcrux_backend.rs` — adapter module (11 tests)
- `src/layers/l2_keygen.rs` — EphemeralKeys uses libcrux key pairs + Drop impl
- `src/layers/l3_commit.rs` — commitment uses libcrux key serialization
- `src/layers/l4_prove.rs` — Proof wraps MLDSA65Signature + Drop impl
- `src/layers/l5_verify.rs` — verify + KEM roundtrip via libcrux
- 347/347 tests pass (all layers verified end-to-end)
- fmt clean, clippy clean, no_std clean, release build clean

### 1.2 — CAVP Algorithm Validation (HIGH 🟠)

NIST menyediakan **test vectors** (ACVP) untuk FIPS 203/204/205.
Implementation HARUS menghasilkan output yang identik.

**Action:**
```
- Download NIST ACVP test vectors untuk ML-KEM-768, ML-DSA-65
- Tulis test harness: feed test vector → compare output
- Dokumentasikan hasil per algorithm
- Simpan sebagai evidence untuk auditor
```

**Status:** ⏳ PENDING

### 1.3 — Supply Chain Security (HIGH 🟠)

```
- [ ] Implementasi cargo audit di CI
- [ ] Implementasi cargo vet (dependency auditing)
- [ ] Pin exact versions di Cargo.lock
- [ ] Setup Dependabot/Renovate untuk monitoring
- [ ] Verifikasi: tidak ada pqcrypto-* crates (unmaintained)
- [ ] SBOM (Software Bill of Materials) generation
```

**Status:** ⏳ PENDING

### 1.4 — Miri Memory Safety (MEDIUM 🟡)

```
- [ ] cargo +nightly miri test
- [ ] Fix semua Miri findings
- [ ] Add Miri ke CI (nightly channel)
```

**Status:** ⏳ PENDING

### 1.5 — Missing Drop Implementations (MEDIUM 🟡)

```
- [ ] l4_prove::Proof — zeroize 3309B ML-DSA signature
- [ ] blind::blind_claim return — wrap in Zeroizing<Vec<u8>>
- [ ] Verify semua heap-allocated secrets have Drop
```

**Status:** ⏳ PENDING

---

## 🏗️ FASE 2: Hardening (2-4 bulan, ~$25K-75K)

### 2.1 — Constant-Time Keccak (CRITICAL 🔴)

| Opsi | Effort | Risk |
|------|--------|------|
| A. Fork sha3 → bit-sliced | 3-6 bulan | Lowest risk, most work |
| B. Pakai libcrux SHA-3 | 1-2 minggu | Medium risk, depends on libcrux |
| C. Accept risk + document | 0 | Only for single-tenant |

### 2.2 — dudect Hardware Validation (HIGH 🟠)

```
- [ ] Setup dudect harness (aarch64 + x86_64)
- [ ] Threshold: p < 0.0001 across ≥1M samples
- [ ] Test upstream: MlKem::derive, MlDsa::sign, SlhDsa::sign
```

### 2.3 — Formal Verification (MEDIUM 🟡)

```
- [ ] Kani model checking untuk L0→L7 pipeline
- [ ] Prove: no secret-dependent branches
- [ ] Prove: all secrets zeroized before scope exit
```

### 2.4 — Fuzzing Infrastructure (MEDIUM 🟡)

```
- [ ] cargo-fuzz (libFuzzer) untuk semua public API
- [ ] AFL++ untuk binary CLI
- [ ] Minimum 72-hour fuzz run sebelum release
```

---

## 📜 FASE 3: Sertifikasi (6-18 bulan, $100K-$500K)

### 3.1 — FIPS 140-3

| Step | Timeline | Cost |
|------|----------|------|
| Define module boundary | 1-2 minggu | Internal |
| Pilih security level | 1 minggu | Internal |
| Engage NVLAP lab | 2-4 minggu | $50K-$200K |
| CAVP testing | 1-3 bulan | Included |
| Lab testing + report | 3-6 bulan | Lab cost |
| CMVP submission | 3-6 bulan | $10K-$50K |

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

## 🚀 FASE 4: Deployment (1-2 bulan, ~$10K-30K)

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
| Single-tenant phone/laptop | 🟢 LOW | ✅ Setelah Fase 1 |
| Dedicated server | 🟢 LOW | ✅ Setelah Fase 1 |
| Co-located cloud VM | 🟠 MED-HIGH | ⚠️ Butuh Fase 2 |
| Multi-tenant bare metal | 🔴 HIGH | ❌ Butuh Fase 2+3 |
| TEE/SGX enclave | 🟡 MEDIUM | ⚠️ Butuh Fase 2 |

---

## 💰 Budget Summary

| Phase | Timeline | Cost | Priority |
|-------|----------|------|----------|
| Fase 1: Fondasi | 1-2 bulan | $5K-$15K | 🔴 Must |
| Fase 2: Hardening | 2-4 bulan | $25K-$75K | 🟠 Should |
| Fase 3: Sertifikasi | 6-18 bulan | $100K-$500K | 🔵 If required |
| Fase 4: Deployment | 1-2 bulan | $10K-$30K | 🔴 Must |
| **TOTAL (minimal)** | **4-8 bulan** | **$40K-$120K** | |
| **TOTAL (full cert)** | **12-24 bulan** | **$140K-$620K** | |

---

## 📋 Master Checklist

### Pre-Production (Must-Have)
```
□ Replace RustCrypto PQ with audited implementation
□ Verify KyberSlash patches
□ Pass NIST ACVP test vectors
□ cargo audit clean
□ cargo vet clean
□ Miri clean
□ dudect validation on target hardware
□ All tests passing
□ Fuzzing ≥ 72 hours
□ Documented cryptographic policy
□ Signed release binaries
□ SBOM generated
```

### Production Certification (Nice-to-Have)
```
□ FIPS 140-3 CMVP certificate
□ ISO 17825 side-channel report
□ Common Criteria EAL4+
□ SOC 2 Type II report
□ ISO 27001 certification
□ Penetration test report
```

---

## 📝 Changelog

| Date | Update |
|------|--------|
| 2026-06-13 | Initial roadmap created. Fase 1.1 started (replace RustCrypto PQ). |
