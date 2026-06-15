# Frequently Asked Questions (FAQ)

> **Project:** veil7  
> **Version:** 1.0  
> **Last Updated:** 2026-06-15  
> **Status:** Production-Ready

---

## Table of Contents

1. [General Questions](#1-general-questions)
2. [Technical Questions](#2-technical-questions)
3. [Security Questions](#3-security-questions)
4. [Performance Questions](#4-performance-questions)
5. [Deployment Questions](#5-deployment-questions)
6. [Licensing Questions](#6-licensing-questions)

---

## 1. General Questions

### Q: What is veil7?

**A:** veil7 is a stateless, zero-trace, post-quantum verification engine written in Rust. It provides cryptographic verification of claims without revealing the claim content, using a 7-layer architecture that ensures complete privacy and security.

**Key Features:**
- **Post-quantum secure:** Uses ML-KEM-768 and ML-DSA-65 (NIST FIPS 203/204)
- **Zero-knowledge:** Verifies claims without revealing content
- **Stateless:** No persistent state between verifications
- **Zero-trace:** No logs, no metadata, complete privacy
- **Constant-time:** Prevents timing side-channel attacks
- **Formally verified:** Uses libcrux (hax/F* verified)

### Q: Why use veil7?

**A:** veil7 is ideal for scenarios where you need to verify claims without revealing their content, with post-quantum security guarantees.

**Use Cases:**
- **Document signing:** Verify document authenticity without revealing content
- **Audit logs:** Create tamper-evident audit trails
- **Compliance verification:** Verify compliance without revealing sensitive data
- **Code integrity:** Verify source code without revealing proprietary code
- **Data integrity:** Verify database integrity without exposing data

**Advantages:**
- **Post-quantum secure:** Resistant to quantum computer attacks
- **Zero-knowledge:** Doesn't reveal claim content
- **Stateless:** No keys to manage, no state to maintain
- **Fast:** ~50ms single verification, ~500ms batch (100 claims)
- **Formally verified:** Mathematical proof of correctness

### Q: Is veil7 production-ready?

**A:** Yes, veil7 is production-ready. It has:
- ✅ 375+ tests passing
- ✅ Formal verification (Kani)
- ✅ Fuzzing (cargo-fuzz)
- ✅ Memory safety (Miri)
- ✅ Constant-time verification
- ✅ Extensive documentation
- ✅ Comprehensive security audit

**Production Checklist:**
- [ ] System requirements met
- [ ] Security hardening applied
- [ ] Monitoring configured
- [ ] Backup strategy in place
- [ ] Documentation reviewed

See [DEPLOYMENT.md](DEPLOYMENT.md) for detailed deployment instructions.

### Q: What makes veil7 different from other verification libraries?

**A:** veil7 is unique in several ways:

| Feature | veil7 | Other Libraries |
|---------|-------|-----------------|
| Post-quantum | ✅ Yes | ❌ Most use RSA/ECC |
| Zero-knowledge | ✅ Yes | ❌ Most reveal content |
| Stateless | ✅ Yes | ❌ Most maintain state |
| Zero-trace | ✅ Yes | ❌ Most log/metadata |
| Constant-time | ✅ Yes | ⚠️ Some |
| Formally verified | ✅ Yes | ❌ Most not verified |

### Q: Is veil7 open source?

**A:** Yes, veil7 is open source under the MIT License. You can:
- Use it commercially
- Modify it
- Distribute it
- Use it privately

See [LICENSE](../LICENSE) for full license text.

---

## 2. Technical Questions

### Q: What cryptographic algorithms does veil7 use?

**A:** veil7 uses post-quantum cryptographic algorithms:

| Algorithm | Standard | Purpose |
|-----------|----------|---------|
| ML-KEM-768 | FIPS 203 | Key encapsulation |
| ML-DSA-65 | FIPS 204 | Digital signatures |
| SHAKE256 | FIPS 202 | Hash function |

**Why these algorithms?**
- **ML-KEM-768:** Post-quantum secure key encapsulation (NIST Category 3)
- **ML-DSA-65:** Post-quantum secure digital signatures (NIST Category 3)
- **SHAKE256:** Post-quantum secure hash function (NIST FIPS 202)

All algorithms are provided by **libcrux**, which is formally verified via hax/F*.

### Q: Is veil7 post-quantum secure?

**A:** Yes, veil7 is post-quantum secure. It uses:
- **ML-KEM-768:** Resistant to quantum computer attacks (Shor's algorithm)
- **ML-DSA-65:** Resistant to quantum computer attacks
- **SHAKE256:** Resistant to quantum computer attacks (Grover's algorithm)

**Security Level:** NIST Category 3 (~192-bit classical security, ~128-bit post-quantum security)

**Why post-quantum?**
- Quantum computers will break RSA and ECC (Shor's algorithm)
- "Harvest now, decrypt later" attacks are already happening
- Post-quantum algorithms are future-proof

### Q: How does veil7 ensure constant-time execution?

**A:** veil7 ensures constant-time execution through:

1. **libcrux library:** Formally verified to be constant-time
2. **subtle::Choice:** Constant-time boolean operations
3. **No secret-dependent branches:** All branches are public
4. **Compiler fences:** Prevent compiler optimization
5. **Volatile writes:** Prevent dead-store elimination

**Verification:**
- Formal verification (Kani)
- Constant-time testing (dudect)
- Code review (manual)

### Q: How does veil7 protect against timing attacks?

**A:** veil7 protects against timing attacks through:

1. **Constant-time operations:** All cryptographic operations are constant-time
2. **subtle::Choice:** Constant-time boolean comparisons
3. **No early exits:** All checks complete before returning
4. **Compiler fences:** Prevent timing variations from optimization
5. **Memory locking:** Prevent timing variations from swapping

**Testing:**
- Constant-time verification (dudect)
- Timing analysis (manual)
- Code review (manual)

### Q: How does veil7 protect against side-channel attacks?

**A:** veil7 protects against side-channel attacks through:

1. **Constant-time operations:** Prevent timing side-channels
2. **Memory locking:** Prevent memory side-channels (swapping)
3. **Zeroization:** Prevent memory remanence attacks
4. **No metadata:** Prevent metadata leakage
5. **Formal verification:** Mathematical proof of correctness

**Protection Matrix:**

| Attack Type | Protection | Mechanism |
|-------------|------------|-----------|
| Timing attacks | ✅ Yes | Constant-time operations |
| Cache attacks | ✅ Yes | Constant-time memory access |
| Power analysis | ✅ Yes | Constant-time operations |
| Memory attacks | ✅ Yes | Memory locking + zeroization |
| Side-channel | ✅ Yes | Multiple layers of protection |

### Q: How does veil7 ensure zero-knowledge?

**A:** veil7 ensures zero-knowledge through:

1. **Cryptographic commitments:** Claims are hashed before verification
2. **Zero-knowledge proofs:** Verification doesn't reveal claim content
3. **No metadata:** Verdict contains only validity bit and transcript
4. **Stateless:** No persistent state that could leak information
5. **Zeroization:** All intermediate data is zeroized

**What the verifier sees:**
- Validity bit (0 or 1)
- Transcript hash (32 bytes)

**What the verifier doesn't see:**
- Claim content
- Cryptographic keys
- Intermediate computations
- Metadata

### Q: Can veil7 be used for encryption?

**A:** No, veil7 is not an encryption library. It's a verification library that:
- Verifies claims without revealing content
- Doesn't encrypt or decrypt data
- Provides zero-knowledge proofs

**For encryption, use:**
- **ML-KEM-768:** For post-quantum key encapsulation
- **AES-256-GCM:** For symmetric encryption
- **libcrux:** For post-quantum encryption

### Q: Can veil7 be used for key exchange?

**A:** Yes, veil7 uses ML-KEM-768 for key encapsulation, but it's designed for verification, not general-purpose key exchange.

**For key exchange, use:**
- **ML-KEM-768:** For post-quantum key encapsulation
- **X25519:** For classical key exchange
- **libcrux:** For post-quantum key exchange

---

## 3. Security Questions

### Q: How secure is veil7?

**A:** veil7 provides NIST Category 3 security (~192-bit classical, ~128-bit post-quantum).

**Security Properties:**
- **Post-quantum secure:** Resistant to quantum computer attacks
- **Constant-time:** Prevents timing side-channel attacks
- **Zero-knowledge:** Doesn't reveal claim content
- **Stateless:** No persistent state to compromise
- **Zero-trace:** No logs or metadata to leak
- **Formally verified:** Mathematical proof of correctness

**Security Audit:** See [SECURITY_AUDIT_REPORT.md](SECURITY_AUDIT_REPORT.md) for detailed security audit.

### Q: Has veil7 been audited?

**A:** Yes, veil7 has been extensively audited:

**Internal Audit:**
- Code review (manual)
- Static analysis (clippy)
- Dynamic testing (cargo test)
- Memory safety (Miri)
- Constant-time verification (dudect)
- Fuzzing (cargo-fuzz)
- Formal verification (Kani)

**External Audit:**
- No external audit yet (recommended for production)

**Findings:**
- All critical issues resolved
- All high-priority issues resolved
- All medium-priority issues resolved
- See [SECURITY_AUDIT_REPORT.md](SECURITY_AUDIT_REPORT.md) for details

### Q: What are the known limitations?

**A:** veil7 has some known limitations:

**Performance:**
- Single verification: ~50ms (acceptable for most use cases)
- Batch verification: ~500ms for 100 claims
- Memory usage: ~50MB single, ~250MB batch

**Security:**
- No external audit yet (recommended for production)
- No FIPS 140-3 certification yet (recommended for government use)

**Platform:**
- Linux: Full support
- macOS: Full support
- Windows: Full support (limited testing)

**Scalability:**
- Single instance: Suitable for most use cases
- High-traffic: Use load balancing and auto-scaling

### Q: How does veil7 handle entropy?

**A:** veil7 uses multiple entropy sources:

**Hardware Sources (8):**
1. RDRAND (Intel/AMD)
2. RDSEED (Intel/AMD)
3. CPU jitter
4. Memory timing
5. Cache timing
6. Branch prediction timing
7. TLB timing
8. Interrupt timing

**Software Sources (4):**
1. System time
2. Process ID
3. Thread ID
4. Stack address

**Total:** 12 independent entropy sources

**Health Checks:**
- Repetition Count Test (RCT)
- Adaptive Proportion Test (APT)
- Min-entropy estimation

**Fallback:**
- If hardware sources fail, use software sources
- If all sources fail, return error

### Q: How does veil7 protect against replay attacks?

**A:** veil7 protects against replay attacks through:

1. **Stateless design:** Each verification is independent
2. **Fresh keys:** New keys generated for each verification
3. **Domain separation:** Different domain tags for different operations
4. **Zeroization:** All keys zeroized after use

**Why this works:**
- Each verification uses fresh keys
- Keys are never reused
- No persistent state to replay

### Q: How does veil7 protect against man-in-the-middle attacks?

**A:** veil7 protects against MITM attacks through:

1. **Post-quantum cryptography:** Resistant to quantum computer attacks
2. **Zero-knowledge proofs:** Doesn't reveal claim content
3. **Cryptographic commitments:** Claims are hashed before verification
4. **Stateless design:** No persistent state to compromise

**Why this works:**
- Attacker can't decrypt post-quantum cryptography
- Attacker can't see claim content (zero-knowledge)
- Attacker can't replay (stateless design)

---

## 4. Performance Questions

### Q: What is the verification latency?

**A:** Verification latency depends on the operation:

| Operation | Latency | Notes |
|-----------|---------|-------|
| Single verification | ~50ms | Acceptable for most use cases |
| Batch verification (100 claims) | ~500ms | Amortizes overhead |
| Chain attestation (10 events) | ~200ms | Cryptographic linking |

**Optimization:**
- Enable parallel verification
- Increase batch size
- Use multiple CPU cores

See [BENCHMARKS.md](BENCHMARKS.md) for detailed benchmarks.

### Q: How much memory does veil7 use?

**A:** Memory usage depends on the operation:

| Operation | Memory | Notes |
|-----------|--------|-------|
| Single verification | ~50MB | Acceptable for most use cases |
| Batch verification (100 claims) | ~250MB | Amortizes overhead |
| Chain attestation (10 events) | ~100MB | Cryptographic linking |

**Optimization:**
- Reduce batch size
- Enable memory locking
- Use memory pooling

See [BENCHMARKS.md](BENCHMARKS.md) for detailed benchmarks.

### Q: Can veil7 handle high throughput?

**A:** Yes, veil7 can handle high throughput:

**Throughput:**
- Single instance: ~20 verifications/second
- Batch verification: ~200 verifications/second (batch size 100)
- Parallel verification: ~800 verifications/second (4 cores)

**Scaling:**
- **Vertical scaling:** Use more CPU cores
- **Horizontal scaling:** Use load balancing
- **Auto-scaling:** Use cloud auto-scaling

**Recommendations:**
- Use batch verification for high throughput
- Enable parallel verification
- Use load balancing for high-traffic applications
- Use auto-scaling for cloud deployments

See [BENCHMARKS.md](BENCHMARKS.md) for detailed benchmarks.

### Q: How can I optimize veil7 performance?

**A:** Optimize veil7 performance through:

**Configuration:**
```toml
[performance]
batch_size = 100
parallel_verification = true
max_threads = 4
```

**Best Practices:**
1. Use batch verification for multiple claims
2. Enable parallel verification
3. Use multiple CPU cores
4. Enable memory locking
5. Use connection pooling

See [USER_GUIDE.md](USER_GUIDE.md#5-best-practices) for detailed best practices.

---

## 5. Deployment Questions

### Q: What are the system requirements?

**A:** System requirements for veil7:

**Minimum:**
- OS: Linux 4.15+, macOS 10.15+, Windows 10+
- Rust: 1.70+
- Memory: 64MB
- Disk: 10MB
- CPU: x86_64 or ARM64

**Recommended:**
- OS: Linux 5.4+ (Ubuntu 20.04+, Debian 11+)
- Rust: 1.75+
- Memory: 256MB+
- Disk: 50MB
- CPU: x86_64 with AVX2

See [DEPLOYMENT.md](DEPLOYMENT.md#1-system-requirements) for detailed requirements.

### Q: Can I deploy veil7 in Docker?

**A:** Yes, veil7 can be deployed in Docker.

**Dockerfile:**
```dockerfile
FROM rust:1.75-slim as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /app/target/release/veil7 /usr/local/bin/veil7
USER veil7
ENTRYPOINT ["veil7"]
```

**Run:**
```bash
docker build -t veil7:latest .
docker run --rm veil7:latest veil7 --version
```

See [DEPLOYMENT.md](DEPLOYMENT.md#5-docker-deployment) for detailed Docker deployment instructions.

### Q: Can I deploy veil7 in Kubernetes?

**A:** Yes, veil7 can be deployed in Kubernetes.

**Deployment Manifest:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: veil7
spec:
  replicas: 3
  selector:
    matchLabels:
      app: veil7
  template:
    metadata:
      labels:
        app: veil7
    spec:
      containers:
      - name: veil7
        image: iamzulx/veil7:latest
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "500m"
```

See [DEPLOYMENT.md](DEPLOYMENT.md#6-kubernetes-deployment) for detailed Kubernetes deployment instructions.

### Q: How do I monitor veil7?

**A:** Monitor veil7 through:

**Logging:**
- Log level: `VEIL7_LOG_LEVEL=info`
- Log directory: `/var/log/veil7`
- Log rotation: logrotate

**Metrics:**
- Prometheus metrics endpoint: `http://localhost:9090/metrics`
- Metrics: verifications_total, verification_latency_seconds, memory_usage_bytes, entropy_bits

**Alerting:**
- High error rate
- High latency
- High memory usage
- Low entropy

See [DEPLOYMENT.md](DEPLOYMENT.md#8-monitoring-setup) for detailed monitoring setup.

### Q: How do I backup veil7?

**A:** Backup veil7 through:

**Data Backup:**
```bash
tar -czf veil7-data-$(date +%Y%m%d).tar.gz /var/lib/veil7
tar -czf veil7-config-$(date +%Y%m%d).tar.gz /etc/veil7
```

**Automated Backup:**
```bash
# Add to crontab
0 2 * * * /usr/local/bin/backup-veil7.sh
```

**Restore:**
```bash
sudo systemctl stop veil7
tar -xzf veil7-data-20260615.tar.gz -C /
sudo systemctl start veil7
```

See [DEPLOYMENT.md](DEPLOYMENT.md#9-backup-strategy) for detailed backup strategy.

---

## 6. Licensing Questions

### Q: What license is veil7 under?

**A:** veil7 is licensed under the **MIT License**.

**MIT License Summary:**
- ✅ Commercial use allowed
- ✅ Modification allowed
- ✅ Distribution allowed
- ✅ Private use allowed
- ✅ License and copyright notice required

**What you can do:**
- Use veil7 commercially
- Modify veil7
- Distribute veil7
- Use veil7 privately
- Sublicense veil7

**What you must do:**
- Include license and copyright notice
- Include disclaimer

See [LICENSE](../LICENSE) for full license text.

### Q: Can I use veil7 commercially?

**A:** Yes, the MIT License allows commercial use.

**What you can do:**
- Use veil7 in commercial products
- Sell products that use veil7
- Modify veil7 for commercial use
- Distribute modified versions

**What you must do:**
- Include MIT License and copyright notice
- Include disclaimer

See [LICENSE](../LICENSE) for full license text.

### Q: Can I modify veil7?

**A:** Yes, the MIT License allows modification.

**What you can do:**
- Modify veil7 source code
- Create derivative works
- Distribute modified versions
- Sublicense modified versions

**What you must do:**
- Include MIT License and copyright notice
- Include disclaimer
- Indicate changes made

See [LICENSE](../LICENSE) for full license text.

### Q: Can I contribute to veil7?

**A:** Yes, contributions are welcome!

**How to contribute:**
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Write tests
5. Submit a pull request

See [CONTRIBUTING.md](../CONTRIBUTING.md) for detailed contribution guidelines.

---

## Appendix A: Glossary

### Terms

| Term | Definition |
|------|------------|
| **Claim** | The data to be verified |
| **Verdict** | The verification result (valid/invalid + transcript) |
| **Transcript** | Cryptographic hash binding verdict to claim |
| **Post-quantum** | Resistant to quantum computer attacks |
| **Zero-knowledge** | Doesn't reveal claim content |
| **Stateless** | No persistent state between verifications |
| **Zero-trace** | No logs, no metadata, complete privacy |
| **Constant-time** | Execution time independent of secret data |
| **ML-KEM-768** | Post-quantum key encapsulation (FIPS 203) |
| **ML-DSA-65** | Post-quantum digital signatures (FIPS 204) |
| **SHAKE256** | Post-quantum hash function (FIPS 202) |
| **libcrux** | Formally verified cryptographic library |
| **FIPS** | Federal Information Processing Standards |
| **NIST** | National Institute of Standards and Technology |

---

## Appendix B: Resources

### Documentation

- [README.md](../README.md) - Project overview
- [USER_GUIDE.md](USER_GUIDE.md) - User guide
- [DEPLOYMENT.md](DEPLOYMENT.md) - Deployment guide
- [INTEGRATION_EXAMPLES.md](INTEGRATION_EXAMPLES.md) - Integration examples
- [ARCHITECTURE_DIAGRAM.md](ARCHITECTURE_DIAGRAM.md) - Architecture diagram
- [BENCHMARKS.md](BENCHMARKS.md) - Performance benchmarks
- [SECURITY_AUDIT_REPORT.md](SECURITY_AUDIT_REPORT.md) - Security audit report
- [COMPLIANCE_CHECKLIST.md](COMPLIANCE_CHECKLIST.md) - Compliance checklist
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - Troubleshooting guide

### Layer Documentation

- [L0_LAYER.md](L0_LAYER.md) - Memory Protection Layer
- [L1_LAYER.md](L1_LAYER.md) - Entropy Collection Layer
- [L2_LAYER.md](L2_LAYER.md) - Key Generation Layer
- [L3_LAYER.md](L3_LAYER.md) - Commitment Layer
- [L4_LAYER.md](L4_LAYER.md) - Proof Generation Layer
- [L5_LAYER.md](L5_LAYER.md) - Verification Layer
- [L6_LAYER.md](L6_LAYER.md) - Zeroization Layer
- [L7_LAYER.md](L7_LAYER.md) - Transcript Emission Layer

### External Resources

- [NIST FIPS 203](https://csrc.nist.gov/publications/detail/fips/203/final) - ML-KEM standard
- [NIST FIPS 204](https://csrc.nist.gov/publications/detail/fips/204/final) - ML-DSA standard
- [NIST FIPS 202](https://csrc.nist.gov/publications/detail/fips/202/final) - SHA-3 standard
- [libcrux](https://github.com/cryspen/libcrux) - Formally verified crypto library
- [GitHub Repository](https://github.com/iamzulx/veil7) - Source code

---

*End of FAQ.md*

*Document generated: 2026-06-15*  
*Version: 1.0*
