# Cryptographic Policy — veil7

> **Version:** 1.0
> **Effective Date:** 2026-06-14
> **Review Cycle:** Annual or upon NIST guidance update

---

## 1. Approved Algorithms

| Purpose | Algorithm | Standard | Security Level | Implementation |
|---------|-----------|----------|---------------|----------------|
| Key Encapsulation | ML-KEM-768 | FIPS 203 | NIST Cat 3 (~192-bit PQ) | libcrux-ml-kem 0.0.9 (hax/F* verified) |
| Digital Signature | ML-DSA-65 | FIPS 204 | NIST Cat 3 (~192-bit PQ) | libcrux-ml-dsa 0.0.9 (hax/F* verified) |
| Hash / XOF | SHAKE256 | FIPS 202 | 256-bit | libcrux-sha3 0.0.9 (hax/F* verified) |
| Signature (alt) | SLH-DSA-SHAKE-128f | FIPS 205 | NIST Cat 1 (~128-bit PQ) | slh-dsa 0.2.0-rc.5 (RustCrypto) |
| Constant-time ops | subtle | — | — | subtle 2.x |
| Memory zeroization | zeroize | — | — | zeroize 1.x |
| OS entropy | getrandom | — | — | getrandom 0.2.x |
| Memory locking | mlock/munlock | POSIX | — | libc 0.2.x |

### Prohibited Algorithms

The following are **explicitly prohibited** in veil7:

- **RSA** (any key size) — quantum-vulnerable, deprecated by NIST IR 8547
- **ECDSA** (P-256, P-384, etc.) — quantum-vulnerable
- **EdDSA / Ed25519 / X25519** — quantum-vulnerable
- **AES** as long-term-secret primitive — not post-quantum
- **SHA-2** as sole hash — not post-quantum collision-resistant
- **Any classical DH** — quantum-vulnerable

---

## 2. Key Management Lifecycle

### Key Generation

- All keys are **ephemeral** — generated fresh per iteration from OS entropy.
- No long-term key storage. No key files. No key databases.
- Key derivation uses domain-separated SHAKE256 from a 64-byte master seed.
- Master seed is `mlock`'d to prevent swap-to-disk (best-effort).

### Key Usage

- Keys exist only for the lifetime of a single verification iteration.
- Each iteration: generate → use → zeroize → discard.
- No key reuse across iterations.
- No key export or serialization.

### Key Destruction

- All secret material is zeroized via volatile writes + `compiler_fence(SeqCst)`.
- `#[inline(never)]` on all `Drop` impls to prevent compiler elision.
- `mlock`'d pages are `munlock`'d after zeroization.
- 11 secret-containing types have verified `Drop` implementations.

### Key Sizes

| Key Type | Size | Standard |
|----------|------|----------|
| ML-KEM-768 encapsulation key | 1184 bytes | FIPS 203 |
| ML-KEM-768 decapsulation key | 2400 bytes | FIPS 203 |
| ML-KEM-768 ciphertext | 1088 bytes | FIPS 203 |
| ML-KEM-768 shared secret | 32 bytes | FIPS 203 |
| ML-DSA-65 verification key | 1952 bytes | FIPS 204 |
| ML-DSA-65 signing key | 4032 bytes | FIPS 204 |
| ML-DSA-65 signature | 3309 bytes | FIPS 204 |
| Master seed | 64 bytes | Internal |

---

## 3. Roles and Responsibilities

### Engine (veil7 library)

- Generates ephemeral keys from OS entropy.
- Performs all cryptographic operations.
- Zeroizes all secrets after use.
- Emits only `Verdict` (validity bit + transcript hash).
- **No logging, no metadata, no persistent state.**

### Caller (application)

- Provides claim data to attest.
- Receives `Verdict` (validity + transcript).
- Responsible for any application-level key management.
- Responsible for secure deployment environment.

### Operator (infrastructure)

- Ensures single-tenant deployment (or accepts shared-cache risk).
- Maintains OS entropy source quality.
- Monitors for CSPRNG failures.

---

## 4. Deployment Requirements

### Minimum Security Environment

| Requirement | Rationale |
|-------------|-----------|
| Single-tenant hardware or dedicated VM | Eliminates cache-timing attacks |
| OS with quality CSPRNG (`/dev/urandom` or equivalent) | Entropy for key generation |
| Sufficient `RLIMIT_MEMLOCK` | Allows `mlock` for seed protection |
| No swap (preferred) or encrypted swap | Prevents seed leakage to disk |

### Recommended Additional Measures

- Disable swap entirely (`swapoff -a`)
- Set `RLIMIT_MEMLOCK` to unlimited
- Use hardware RNG if available
- Run on isolated CPU cores (if available)
- Disable SMT/HyperThreading (if available)

---

## 5. Incident Response

### Key Compromise

Since all keys are ephemeral and zeroized after use:

1. **No key extraction possible** — keys don't persist beyond iteration.
2. **No key rotation needed** — each iteration uses fresh keys.
3. **No revocation needed** — no long-term keys to revoke.

### Entropy Source Failure

If OS CSPRNG fails:

1. `getrandom()` returns error → `harvest()` returns `VeilError::Entropy`.
2. No keys are generated. No operations proceed.
3. **Action:** Investigate OS entropy source. Restart if needed.

### Side-Channel Detection

If cache-timing attack is suspected:

1. Move to single-tenant hardware immediately.
2. Enable `keccak_ct` masked sponge (already default).
3. Consider `dudect` testing on target hardware.

---

## 6. Compliance References

| Standard | Status | Notes |
|----------|--------|-------|
| NIST FIPS 202 (SHA-3) | ✅ Compliant | libcrux-sha3 (formally verified) |
| NIST FIPS 203 (ML-KEM) | ✅ Compliant | libcrux-ml-kem (formally verified) |
| NIST FIPS 204 (ML-DSA) | ✅ Compliant | libcrux-ml-dsa (formally verified) |
| NIST FIPS 205 (SLH-DSA) | ⚠️ Partial | RustCrypto (unaudited, awaiting stable) |
| NIST IR 8547 (PQC Transition) | ✅ Compliant | No classical primitives used |
| FIPS 140-3 | ❌ Not certified | Requires external NVLAP lab |
| ISO 17825 (Side-Channel) | ❌ Not tested | Requires hardware testing |

---

## 7. Supply Chain

### Dependency Audit

- `cargo audit` runs in CI on every push.
- `cargo vet` runs in CI (supply chain verification).
- Dependabot monitors for security updates weekly.
- SBOM generated in CycloneDX format (61 dependencies).

### Dependency Policy

- Only approved crates listed in Section 1.
- No async runtimes, no network clients, no telemetry.
- Major version upgrades require manual review.
- `sha3` and `getrandom` major versions are blocked (conflict with libcrux).

---

## 8. Review History

| Date | Change | Reviewer |
|------|--------|----------|
| 2026-06-14 | Initial policy created | veil7 team |
| 2026-06-14 | Phase 2.1: SHAKE256 migrated to libcrux-sha3 | veil7 team |
