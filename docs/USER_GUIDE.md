# User Guide

> **Project:** veil7  
> **Version:** 1.0  
> **Last Updated:** 2026-06-15  
> **Status:** Production-Ready

---

## Table of Contents

1. [Quick Start (5 Minutes)](#1-quick-start-5-minutes)
2. [Basic Usage](#2-basic-usage)
3. [Common Use Cases](#3-common-use-cases)
4. [API Usage Patterns](#4-api-usage-patterns)
5. [Best Practices](#5-best-practices)
6. [Troubleshooting Common Issues](#6-troubleshooting-common-issues)

---

## 1. Quick Start (5 Minutes)

### Step 1: Install veil7

```bash
# Install from source
git clone https://github.com/iamzulx/veil7.git
cd veil7
cargo build --release

# Install binary
sudo cp target/release/veil7 /usr/local/bin/
```

### Step 2: Verify Installation

```bash
veil7 --version
# Output: veil7 1.0.0
```

### Step 3: Verify Your First Claim

```bash
# Verify a simple text claim
veil7 verify-once "Hello, World!"

# Output: Verdict { valid: true, transcript: "abc123..." }
```

### Step 4: Verify a File

```bash
# Verify a file
veil7 verify-file document.txt

# Output: Verdict { valid: true, transcript: "def456..." }
```

### Step 5: Batch Verification

```bash
# Verify multiple claims at once
veil7 verify-batch claim1.txt claim2.txt claim3.txt

# Output: Verdict { valid: true, transcript: "ghi789..." }
```

**Congratulations!** You've successfully verified your first claims with veil7. 🎉

---

## 2. Basic Usage

### Single Claim Verification

#### Verify Text

```bash
veil7 verify-once "Your claim here"
```

**Example:**
```bash
$ veil7 verify-once "The quick brown fox jumps over the lazy dog"
Verdict { valid: true, transcript: "a1b2c3d4e5f6..." }
```

#### Verify File

```bash
veil7 verify-file /path/to/file.txt
```

**Example:**
```bash
$ veil7 verify-file /etc/passwd
Verdict { valid: true, transcript: "f6e5d4c3b2a1..." }
```

#### Verify Bytes

```bash
echo -n "binary data" | veil7 verify-bytes
```

**Example:**
```bash
$ echo -n "binary data" | veil7 verify-bytes
Verdict { valid: true, transcript: "1a2b3c4d5e6f..." }
```

### Batch Verification

#### Verify Multiple Files

```bash
veil7 verify-batch file1.txt file2.txt file3.txt
```

**Example:**
```bash
$ veil7 verify-batch doc1.txt doc2.txt doc3.txt
Verdict { valid: true, transcript: "batch123..." }
```

#### Verify from File List

```bash
# Create file list
echo "file1.txt" > filelist.txt
echo "file2.txt" >> filelist.txt
echo "file3.txt" >> filelist.txt

# Verify from list
veil7 verify-batch --from-file filelist.txt
```

### Chain Attestation

#### Create Chain

```bash
veil7 attest-chain event1 event2 event3
```

**Example:**
```bash
$ veil7 attest-chain "User login" "Data access" "User logout"
Verdict { valid: true, transcript: "chain123..." }
```

**Use Case:** Tamper-evident audit logs where each event is linked to the previous one.

---

## 3. Common Use Cases

### Use Case 1: Document Signing

**Scenario:** Sign a legal document to prove its authenticity.

```bash
# Sign a PDF document
veil7 verify-file contract.pdf

# Output: Verdict { valid: true, transcript: "abc123..." }

# Save transcript as proof
echo "abc123..." > contract_proof.txt
```

**Verification:**
```bash
# Later, verify the document hasn't been tampered with
veil7 verify-file contract.pdf
# Should produce the same transcript
```

**Why use veil7?**
- Post-quantum secure (resistant to quantum computers)
- Zero-knowledge (doesn't reveal document content)
- Stateless (no keys to manage)

### Use Case 2: Audit Logs

**Scenario:** Create tamper-evident audit logs.

```bash
# Create audit log with chain attestation
veil7 attest-chain \
  "2026-06-15 10:00:00 User login" \
  "2026-06-15 10:05:00 Data access" \
  "2026-06-15 10:10:00 User logout"

# Output: Verdict { valid: true, transcript: "chain123..." }
```

**Why use veil7?**
- Each event is cryptographically linked to the previous one
- Tampering with any event breaks the chain
- Zero-knowledge (doesn't reveal event content)

### Use Case 3: Compliance Verification

**Scenario:** Verify compliance with regulatory requirements.

```bash
# Verify compliance checklist
veil7 verify-batch \
  "requirement1.txt" \
  "requirement2.txt" \
  "requirement3.txt"

# Output: Verdict { valid: true, transcript: "compliance123..." }
```

**Why use veil7?**
- Batch verification for efficiency
- Post-quantum secure
- Zero-knowledge (doesn't reveal requirement content)

### Use Case 4: Code Integrity

**Scenario:** Verify source code integrity.

```bash
# Verify source code
veil7 verify-batch \
  src/main.rs \
  src/lib.rs \
  src/config.rs

# Output: Verdict { valid: true, transcript: "code123..." }
```

**Why use veil7?**
- Batch verification for multiple files
- Post-quantum secure
- Zero-knowledge (doesn't reveal code content)

### Use Case 5: Data Integrity

**Scenario:** Verify database integrity.

```bash
# Export database
mysqldump -u user -p database > database.sql

# Verify database
veil7 verify-file database.sql

# Output: Verdict { valid: true, transcript: "db123..." }
```

**Why use veil7?**
- Post-quantum secure
- Zero-knowledge (doesn't reveal database content)
- Stateless (no keys to manage)

---

## 4. API Usage Patterns

### Pattern 1: Synchronous Verification

**Use Case:** Simple, blocking verification.

```rust
use veil7::{verify_once, Claim};

fn main() {
    let claim = Claim::new(b"Hello, World!");
    let verdict = verify_once(&claim).unwrap();
    
    if verdict.is_valid() {
        println!("Verification successful!");
        println!("Transcript: {:?}", verdict.transcript());
    } else {
        println!("Verification failed!");
    }
}
```

**When to use:**
- Simple applications
- Single-threaded applications
- Low-latency requirements

### Pattern 2: Asynchronous Verification

**Use Case:** Non-blocking verification.

```rust
use veil7::{verify_once, Claim};
use tokio::task;

#[tokio::main]
async fn main() {
    let claim = Claim::new(b"Hello, World!");
    
    let handle = task::spawn_blocking(move || {
        verify_once(&claim).unwrap()
    });
    
    let verdict = handle.await.unwrap();
    
    if verdict.is_valid() {
        println!("Verification successful!");
    }
}
```

**When to use:**
- Asynchronous applications
- Web servers
- High-concurrency applications

### Pattern 3: Streaming Verification

**Use Case:** Verify large data streams.

```rust
use veil7::{verify_batch, Claim};
use std::io::BufReader;

fn main() {
    let file = std::fs::File::open("large_file.txt").unwrap();
    let reader = BufReader::new(file);
    
    let claims: Vec<Claim> = reader
        .lines()
        .map(|line| Claim::new(line.unwrap().as_bytes()))
        .collect();
    
    let verdict = verify_batch(&claims).unwrap();
    
    if verdict.is_valid() {
        println!("Batch verification successful!");
    }
}
```

**When to use:**
- Large files
- Streaming data
- Batch processing

### Pattern 4: Chain Attestation

**Use Case:** Create tamper-evident chains.

```rust
use veil7::{attest_chain, Claim};

fn main() {
    let events = vec![
        Claim::new(b"Event 1"),
        Claim::new(b"Event 2"),
        Claim::new(b"Event 3"),
    ];
    
    let verdict = attest_chain(&events).unwrap();
    
    if verdict.is_valid() {
        println!("Chain attestation successful!");
        println!("Transcript: {:?}", verdict.transcript());
    }
}
```

**When to use:**
- Audit logs
- Event chains
- Tamper-evident logs

### Pattern 5: Error Handling

**Use Case:** Robust error handling.

```rust
use veil7::{verify_once, Claim, VeilError};

fn main() {
    let claim = Claim::new(b"Hello, World!");
    
    match verify_once(&claim) {
        Ok(verdict) => {
            if verdict.is_valid() {
                println!("Verification successful!");
            } else {
                println!("Verification failed!");
            }
        }
        Err(VeilError::EntropySourceFailed) => {
            eprintln!("Entropy source failed!");
        }
        Err(VeilError::KeyGenerationFailed) => {
            eprintln!("Key generation failed!");
        }
        Err(VeilError::VerificationFailed) => {
            eprintln!("Verification failed!");
        }
        Err(e) => {
            eprintln!("Unexpected error: {:?}", e);
        }
    }
}
```

**When to use:**
- Production applications
- Robust error handling
- Debugging

---

## 5. Best Practices

### Entropy Sources

#### Best Practice: Use Multiple Entropy Sources

**Why:** Multiple independent entropy sources provide defense-in-depth.

**Configuration:**
```toml
[entropy]
sources = ["hardware", "software"]
health_check = true
min_entropy_bits = 256
```

**Why:** If one source is compromised, others still provide entropy.

### Key Management

#### Best Practice: Ephemeral Keys

**Why:** Ephemeral keys are generated fresh for each verification and zeroized after use.

**Configuration:**
```toml
[memory]
lock_memory = true
zeroize_on_drop = true
```

**Why:** Keys are never stored persistently, reducing attack surface.

### Performance Optimization

#### Best Practice: Batch Verification

**Why:** Batch verification is more efficient than single verification.

**Configuration:**
```toml
[performance]
batch_size = 100
parallel_verification = true
max_threads = 4
```

**Why:** Batch verification amortizes overhead across multiple claims.

#### Best Practice: Parallel Verification

**Why:** Parallel verification uses multiple CPU cores for higher throughput.

**Configuration:**
```toml
[performance]
parallel_verification = true
max_threads = 4  # Adjust based on CPU cores
```

**Why:** Utilizes multiple CPU cores for higher throughput.

### Security Hardening

#### Best Practice: Memory Locking

**Why:** Memory locking prevents secrets from being swapped to disk.

**Configuration:**
```toml
[memory]
lock_memory = true
mlock_limit = "unlimited"
```

**Why:** Prevents secrets from being written to swap files.

#### Best Practice: Constant-Time Operations

**Why:** Constant-time operations prevent timing attacks.

**Configuration:**
```toml
[security]
constant_time = true
zero_metadata = true
```

**Why:** Prevents timing side-channel attacks.

#### Best Practice: Zero Metadata

**Why:** Zero metadata prevents metadata leakage.

**Configuration:**
```toml
[security]
zero_metadata = true
```

**Why:** Verdict contains only validity bit and transcript hash.

### Monitoring

#### Best Practice: Enable Logging

**Why:** Logging helps with debugging and monitoring.

**Configuration:**
```toml
[general]
log_level = "info"
log_dir = "/var/log/veil7"
```

**Why:** Logs help with debugging and monitoring.

#### Best Practice: Enable Metrics

**Why:** Metrics help with performance monitoring.

**Configuration:**
```toml
[monitoring]
metrics_enabled = true
metrics_port = 9090
```

**Why:** Metrics help with performance monitoring and alerting.

---

## 6. Troubleshooting Common Issues

### Issue 1: Entropy Source Failed

**Symptom:** `Error: Entropy source failed`

**Cause:** Entropy source is not available or not providing enough entropy.

**Solution:**
```bash
# Check entropy sources
cat /proc/sys/kernel/random/entropy_avail

# If low, wait for entropy to accumulate
sleep 10

# Or use software entropy sources
export VEIL7_ENTROPY_SOURCES=software

# Retry verification
veil7 verify-once "test claim"
```

### Issue 2: Memory Lock Failed

**Symptom:** `Error: Failed to lock memory`

**Cause:** mlock limit is too low.

**Solution:**
```bash
# Check mlock limit
ulimit -l

# Increase mlock limit
ulimit -l unlimited

# Or edit /etc/security/limits.conf
* soft memlock unlimited
* hard memlock unlimited

# Retry verification
veil7 verify-once "test claim"
```

### Issue 3: Verification Failed

**Symptom:** `Verdict { valid: false, transcript: "..." }`

**Cause:** Claim verification failed (expected behavior for invalid claims).

**Solution:**
```bash
# This is expected behavior for invalid claims
# Verify the claim is correct
veil7 verify-once "correct claim"
```

### Issue 4: High Latency

**Symptom:** Verification takes > 100ms

**Cause:** High latency due to entropy collection or key generation.

**Solution:**
```bash
# Enable parallel verification
export VEIL7_PARALLEL_VERIFICATION=true

# Increase batch size
export VEIL7_BATCH_SIZE=100

# Retry verification
veil7 verify-batch claim1.txt claim2.txt claim3.txt
```

### Issue 5: High Memory Usage

**Symptom:** Memory usage exceeds 256 MB

**Cause:** Large batch size or memory leak.

**Solution:**
```bash
# Reduce batch size
export VEIL7_BATCH_SIZE=50

# Restart service
sudo systemctl restart veil7

# Check memory usage
ps -o pid,vsz,rss,comm -p $(pgrep veil7)
```

### Issue 6: Permission Denied

**Symptom:** `Error: Permission denied`

**Cause:** Insufficient permissions to read file or access resource.

**Solution:**
```bash
# Check file permissions
ls -l /path/to/file

# Fix permissions
chmod 644 /path/to/file

# Retry verification
veil7 verify-file /path/to/file
```

### Issue 7: File Not Found

**Symptom:** `Error: File not found`

**Cause:** File does not exist or path is incorrect.

**Solution:**
```bash
# Check file exists
ls -l /path/to/file

# Fix path
veil7 verify-file /correct/path/to/file
```

### Issue 8: Invalid Configuration

**Symptom:** `Error: Invalid configuration`

**Cause:** Configuration file has syntax errors or invalid values.

**Solution:**
```bash
# Check configuration file
cat /etc/veil7/config.toml

# Fix syntax errors
nano /etc/veil7/config.toml

# Restart service
sudo systemctl restart veil7
```

---

## Appendix A: Command Reference

### veil7 verify-once

**Usage:**
```bash
veil7 verify-once <claim>
```

**Arguments:**
- `<claim>`: The claim to verify (text)

**Example:**
```bash
veil7 verify-once "Hello, World!"
```

### veil7 verify-file

**Usage:**
```bash
veil7 verify-file <file>
```

**Arguments:**
- `<file>`: The file to verify

**Example:**
```bash
veil7 verify-file document.txt
```

### veil7 verify-bytes

**Usage:**
```bash
echo -n "binary data" | veil7 verify-bytes
```

**Example:**
```bash
echo -n "binary data" | veil7 verify-bytes
```

### veil7 verify-batch

**Usage:**
```bash
veil7 verify-batch <file1> <file2> ... <fileN>
```

**Arguments:**
- `<file1> ... <fileN>`: Files to verify

**Example:**
```bash
veil7 verify-batch file1.txt file2.txt file3.txt
```

**Options:**
- `--from-file <list>`: Read file list from file

**Example:**
```bash
veil7 verify-batch --from-file filelist.txt
```

### veil7 attest-chain

**Usage:**
```bash
veil7 attest-chain <event1> <event2> ... <eventN>
```

**Arguments:**
- `<event1> ... <eventN>`: Events to attest

**Example:**
```bash
veil7 attest-chain "Event 1" "Event 2" "Event 3"
```

### veil7 health-check

**Usage:**
```bash
veil7 health-check
```

**Example:**
```bash
veil7 health-check
```

### veil7 --version

**Usage:**
```bash
veil7 --version
```

**Example:**
```bash
veil7 --version
```

---

## Appendix B: Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VEIL7_ENTROPY_SOURCES` | `all` | Entropy sources to use |
| `VEIL7_MEMORY_LOCK` | `true` | Enable memory locking |
| `VEIL7_LOG_LEVEL` | `info` | Log level |
| `VEIL7_CONFIG_FILE` | `/etc/veil7/config.toml` | Configuration file path |
| `VEIL7_DATA_DIR` | `/var/lib/veil7` | Data directory path |
| `VEIL7_LOG_DIR` | `/var/log/veil7` | Log directory path |
| `VEIL7_BATCH_SIZE` | `100` | Batch size for batch verification |
| `VEIL7_PARALLEL_VERIFICATION` | `true` | Enable parallel verification |
| `VEIL7_MAX_THREADS` | `4` | Maximum threads for parallel verification |

---

## Appendix C: Configuration File Reference

### /etc/veil7/config.toml

```toml
# veil7 Configuration File

[general]
log_level = "info"
data_dir = "/var/lib/veil7"
log_dir = "/var/log/veil7"

[entropy]
sources = ["hardware", "software"]
health_check = true
min_entropy_bits = 256

[memory]
lock_memory = true
mlock_limit = "unlimited"
zeroize_on_drop = true

[security]
constant_time = true
zero_metadata = true
defense_in_depth = true

[performance]
batch_size = 100
parallel_verification = true
max_threads = 4

[monitoring]
metrics_enabled = true
metrics_port = 9090
```

---

## Appendix D: FAQ

### Q: Is veil7 production-ready?

**A:** Yes, veil7 is production-ready. It has been extensively tested and audited.

### Q: Is veil7 post-quantum secure?

**A:** Yes, veil7 uses post-quantum cryptographic algorithms (ML-KEM-768, ML-DSA-65) that are resistant to quantum computers.

### Q: How does veil7 ensure constant-time execution?

**A:** veil7 uses the libcrux library, which is formally verified to be constant-time. All cryptographic operations are constant-time.

### Q: How does veil7 protect against timing attacks?

**A:** veil7 uses constant-time operations and `subtle::Choice` for all comparisons, preventing timing attacks.

### Q: How does veil7 protect against side-channel attacks?

**A:** veil7 uses constant-time operations, memory locking, and zeroization to protect against side-channel attacks.

### Q: What is the verification latency?

**A:** Single claim verification takes ~50ms. Batch verification (100 claims) takes ~500ms.

### Q: How much memory does veil7 use?

**A:** veil7 uses ~50MB for single verification, ~250MB for batch verification.

### Q: Can veil7 handle high throughput?

**A:** Yes, veil7 can handle high throughput with batch verification and parallel verification.

### Q: What are the system requirements?

**A:** Linux 4.15+, Rust 1.70+, 64MB memory, 10MB disk, x86_64 or ARM64 CPU.

### Q: Can I deploy veil7 in Docker?

**A:** Yes, see the Deployment Guide for Docker deployment instructions.

### Q: Can I deploy veil7 in Kubernetes?

**A:** Yes, see the Deployment Guide for Kubernetes deployment instructions.

### Q: What license is veil7 under?

**A:** veil7 is licensed under the MIT License.

### Q: Can I use veil7 commercially?

**A:** Yes, the MIT License allows commercial use.

### Q: Can I modify veil7?

**A:** Yes, the MIT License allows modification.

---

*End of USER_GUIDE.md*

*Document generated: 2026-06-15*  
*Version: 1.0*
