# Monitoring — veil7 Deployment

> **Version:** 1.0
> **Effective Date:** 2026-06-14

---

## 1. Overview

veil7 is a stateless library with no built-in metrics or telemetry.
Monitoring is the responsibility of the **integrating application**.
This document provides recommended metrics, alerting rules, and
implementation guidance.

---

## 2. Recommended Metrics

### Application-Level

| Metric | Type | Description |
|--------|------|-------------|
| `veil7_attest_total` | Counter | Total attestation calls |
| `veil7_attest_errors` | Counter | Failed attestation calls |
| `veil7_attest_duration_seconds` | Histogram | Attestation latency |
| `veil7_attest_valid` | Counter | Successful (valid=1) attestations |
| `veil7_attest_invalid` | Counter | Failed (valid=0) attestations |

### System-Level

| Metric | Type | Description |
|--------|------|-------------|
| `process_resident_memory_bytes` | Gauge | Process RSS |
| `process_cpu_seconds_total` | Counter | CPU time |
| `node_entropy_available` | Gauge | Available entropy |
| `node_memory_MemAvailable_bytes` | Gauge | Available system memory |

---

## 3. Alerting Rules

| Alert | Condition | Severity |
|-------|-----------|----------|
| High Error Rate | errors/total > 5% for 5m | Critical |
| High Latency | duration > 5s for 5m | Warning |
| Low Entropy | entropy < 200 for 5m | Critical |
| Memory Pressure | mem_available < 100MB | Warning |
| Process Down | up == 0 for 1m | Critical |

---

## 4. Implementation Example (Prometheus)

```rust
use prometheus::{Counter, Histogram, HistogramOpts, opts};
use prometheus::{register_counter, register_histogram};

lazy_static! {
    static ref ATTEST_TOTAL: Counter = register_counter!(
        opts!("veil7_attest_total", "Total attestation calls")
    ).unwrap();
    static ref ATTEST_ERRORS: Counter = register_counter!(
        opts!("veil7_attest_errors", "Failed attestation calls")
    ).unwrap();
    static ref ATTEST_DURATION: Histogram = register_histogram!(
        HistogramOpts::new("veil7_attest_duration_seconds", "Attestation latency")
    ).unwrap();
}

fn attest_with_metrics(claim: &[u8]) -> Result<veil7::Verdict, veil7::VeilError> {
    ATTEST_TOTAL.inc();
    let timer = ATTEST_DURATION.start_timer();
    let result = veil7::interface::attest_bytes(claim);
    timer.observe_duration();
    if result.is_err() { ATTEST_ERRORS.inc(); }
    result
}
```

---

## 5. Log Format

```json
{
  "timestamp": "2026-06-14T12:00:00Z",
  "level": "info",
  "event": "attest",
  "valid": true,
  "duration_ms": 45,
  "claim_size": 256
}
```

**Do NOT log:** claim content, transcript hashes, key material, seed values.
