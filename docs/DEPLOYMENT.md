# Deployment Guide

> **Project:** veil7  
> **Version:** 1.0  
> **Last Updated:** 2026-06-15  
> **Status:** Production-Ready

---

## Table of Contents

1. [System Requirements](#1-system-requirements)
2. [Installation Methods](#2-installation-methods)
3. [Configuration](#3-configuration)
4. [Production Deployment Checklist](#4-production-deployment-checklist)
5. [Docker Deployment](#5-docker-deployment)
6. [Kubernetes Deployment](#6-kubernetes-deployment)
7. [Security Hardening for Production](#7-security-hardening-for-production)
8. [Monitoring Setup](#8-monitoring-setup)
9. [Backup Strategy](#9-backup-strategy)
10. [Performance Tuning](#10-performance-tuning)

---

## 1. System Requirements

### Minimum Requirements

| Component | Requirement | Notes |
|-----------|-------------|-------|
| **OS** | Linux 4.15+, macOS 10.15+, Windows 10+ | Linux recommended |
| **Rust** | 1.70+ | Stable channel |
| **Memory** | 64 MB | Minimum for single verification |
| **Disk** | 10 MB | Binary + dependencies |
| **CPU** | x86_64 or ARM64 | AVX2 recommended |

### Recommended Requirements

| Component | Requirement | Notes |
|-----------|-------------|-------|
| **OS** | Linux 5.4+ (Ubuntu 20.04+, Debian 11+) | LTS recommended |
| **Rust** | 1.75+ | Latest stable |
| **Memory** | 256 MB+ | For batch verification |
| **Disk** | 50 MB | Binary + cache + logs |
| **CPU** | x86_64 with AVX2 | For optimal performance |

### Platform-Specific Notes

#### Linux
- **Kernel:** 4.15+ for `mlock()` support
- **mlock limit:** Increase with `ulimit -l unlimited` or `/etc/security/limits.conf`
- **Capabilities:** `CAP_IPC_LOCK` for `mlockall()` without root

#### macOS
- **Version:** 10.15+ (Catalina)
- **mlock limit:** 256 KB default, increase with `sysctl kern.ipc.maxsockbuf`
- **Note:** macOS has stricter memory locking limits than Linux

#### Windows
- **Version:** Windows 10+
- **mlock:** Use `VirtualLock()` (automatic in Rust)
- **Note:** Windows memory locking is less restrictive but less secure

---

## 2. Installation Methods

### Method 1: From Source (Recommended)

#### Prerequisites
```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Install dependencies (Linux)
sudo apt-get install -y build-essential pkg-config libssl-dev

# Install dependencies (macOS)
brew install pkg-config openssl
```

#### Build from Source
```bash
# Clone repository
git clone https://github.com/iamzulx/veil7.git
cd veil7

# Build release binary
cargo build --release

# Binary location
ls -lh target/release/veil7
```

#### Install Binary
```bash
# Install to /usr/local/bin
sudo cp target/release/veil7 /usr/local/bin/

# Verify installation
veil7 --version
```

### Method 2: From Binary Release

#### Download Binary
```bash
# Download latest release
wget https://github.com/iamzulx/veil7/releases/latest/download/veil7-linux-x86_64

# Make executable
chmod +x veil7-linux-x86_64

# Move to PATH
sudo mv veil7-linux-x86_64 /usr/local/bin/veil7

# Verify installation
veil7 --version
```

### Method 3: From Cargo (If Published)

```bash
# Install from crates.io (if published)
cargo install veil7

# Verify installation
veil7 --version
```

### Method 4: Docker

```bash
# Pull Docker image
docker pull iamzulx/veil7:latest

# Run container
docker run --rm iamzulx/veil7:latest veil7 --version
```

---

## 3. Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VEIL7_ENTROPY_SOURCES` | `all` | Entropy sources to use (`all`, `hardware`, `software`) |
| `VEIL7_MEMORY_LOCK` | `true` | Enable memory locking (`true`, `false`) |
| `VEIL7_LOG_LEVEL` | `info` | Log level (`error`, `warn`, `info`, `debug`, `trace`) |
| `VEIL7_CONFIG_FILE` | `/etc/veil7/config.toml` | Configuration file path |
| `VEIL7_DATA_DIR` | `/var/lib/veil7` | Data directory path |
| `VEIL7_LOG_DIR` | `/var/log/veil7` | Log directory path |

### Configuration File

Create `/etc/veil7/config.toml`:

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
```

### System Configuration (Linux)

#### Increase mlock Limit

Edit `/etc/security/limits.conf`:
```
# Increase mlock limit for veil7
veil7 soft memlock unlimited
veil7 hard memlock unlimited
* soft memlock unlimited
* hard memlock unlimited
```

#### Systemd Service

Create `/etc/systemd/system/veil7.service`:
```ini
[Unit]
Description=veil7 Verification Service
After=network.target

[Service]
Type=simple
User=veil7
Group=veil7
ExecStart=/usr/local/bin/veil7 server
Restart=always
RestartSec=5
LimitMEMLOCK=infinity
LimitNOFILE=65536

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

[Install]
WantedBy=multi-user.target
```

Enable and start service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable veil7
sudo systemctl start veil7
sudo systemctl status veil7
```

---

## 4. Production Deployment Checklist

### Pre-Deployment

- [ ] **System Requirements Met**
  - [ ] OS version compatible
  - [ ] Rust version installed
  - [ ] Memory requirements met
  - [ ] Disk space available

- [ ] **Security Hardening**
  - [ ] mlock limit increased
  - [ ] System capabilities configured
  - [ ] Firewall rules configured
  - [ ] SELinux/AppArmor configured

- [ ] **User and Permissions**
  - [ ] Dedicated user created (`veil7`)
  - [ ] Directory permissions set
  - [ ] File ownership correct
  - [ ] No world-readable secrets

- [ ] **Monitoring Setup**
  - [ ] Logging configured
  - [ ] Metrics endpoint configured
  - [ ] Alerting configured
  - [ ] Log rotation configured

### Deployment

- [ ] **Binary Installation**
  - [ ] Binary downloaded/compiled
  - [ ] Binary installed to PATH
  - [ ] Binary verified (`veil7 --version`)
  - [ ] Binary permissions correct

- [ ] **Configuration**
  - [ ] Configuration file created
  - [ ] Environment variables set
  - [ ] Configuration validated
  - [ ] Secrets secured

- [ ] **Service Setup**
  - [ ] Systemd service created
  - [ ] Service enabled
  - [ ] Service started
  - [ ] Service verified

### Post-Deployment

- [ ] **Verification**
  - [ ] Service running
  - [ ] Health check passing
  - [ ] Logs accessible
  - [ ] Metrics accessible

- [ ] **Security Verification**
  - [ ] Memory locking active
  - [ ] Zeroization working
  - [ ] No metadata leakage
  - [ ] Constant-time verified

- [ ] **Performance Verification**
  - [ ] Latency acceptable
  - [ ] Throughput acceptable
  - [ ] Memory usage acceptable
  - [ ] CPU usage acceptable

- [ ] **Documentation**
  - [ ] Deployment documented
  - [ ] Runbook created
  - [ ] Incident response plan created
  - [ ] Backup strategy documented

---

## 5. Docker Deployment

### Dockerfile

Create `Dockerfile`:

```dockerfile
# Build stage
FROM rust:1.75-slim as builder

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy source code
COPY . .

# Build release binary
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 veil7

# Copy binary from builder
COPY --from=builder /app/target/release/veil7 /usr/local/bin/veil7

# Set permissions
RUN chmod +x /usr/local/bin/veil7

# Switch to non-root user
USER veil7

# Set entrypoint
ENTRYPOINT ["veil7"]
CMD ["--help"]
```

### Build and Run

```bash
# Build Docker image
docker build -t veil7:latest .

# Run container
docker run --rm \
  --name veil7 \
  --memory 256m \
  --memory-swap 256m \
  --cap-add IPC_LOCK \
  veil7:latest \
  veil7 verify-once "test claim"
```

### Docker Compose

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  veil7:
    build: .
    image: veil7:latest
    container_name: veil7
    restart: always
    mem_limit: 256m
    memswap_limit: 256m
    cap_add:
      - IPC_LOCK
    volumes:
      - veil7-data:/var/lib/veil7
      - veil7-logs:/var/log/veil7
    environment:
      - VEIL7_LOG_LEVEL=info
      - VEIL7_MEMORY_LOCK=true
    ports:
      - "8080:8080"
    healthcheck:
      test: ["CMD", "veil7", "health-check"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  veil7-data:
  veil7-logs:
```

Run with Docker Compose:
```bash
docker-compose up -d
docker-compose logs -f
```

---

## 6. Kubernetes Deployment

### Deployment Manifest

Create `k8s/deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: veil7
  labels:
    app: veil7
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
      securityContext:
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000
      containers:
      - name: veil7
        image: iamzulx/veil7:latest
        imagePullPolicy: Always
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "500m"
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            add:
              - IPC_LOCK
            drop:
              - ALL
        env:
        - name: VEIL7_LOG_LEVEL
          value: "info"
        - name: VEIL7_MEMORY_LOCK
          value: "true"
        ports:
        - containerPort: 8080
          name: http
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
        volumeMounts:
        - name: data
          mountPath: /var/lib/veil7
        - name: logs
          mountPath: /var/log/veil7
      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: veil7-data
      - name: logs
        emptyDir: {}
```

### Service Manifest

Create `k8s/service.yaml`:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: veil7
  labels:
    app: veil7
spec:
  selector:
    app: veil7
  ports:
  - port: 80
    targetPort: 8080
    name: http
  type: ClusterIP
```

### PersistentVolumeClaim

Create `k8s/pvc.yaml`:

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: veil7-data
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
```

### Deploy to Kubernetes

```bash
# Apply manifests
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/pvc.yaml

# Verify deployment
kubectl get pods -l app=veil7
kubectl get svc veil7
kubectl logs -l app=veil7 -f
```

---

## 7. Security Hardening for Production

### Memory Protection

```bash
# Increase mlock limit
sudo sysctl -w kernel.shmmax=68719476736
sudo sysctl -w kernel.shmall=4294967296

# Verify mlock limit
ulimit -l
```

### System Hardening

```bash
# Disable core dumps
echo '* hard core 0' | sudo tee -a /etc/security/limits.conf

# Disable swap (optional, for maximum security)
sudo swapoff -a

# Enable ASLR
echo 2 | sudo tee /proc/sys/kernel/randomize_va_space
```

### Firewall Configuration

```bash
# Allow only necessary ports
sudo ufw allow 8080/tcp  # HTTP API
sudo ufw allow 9090/tcp  # Metrics
sudo ufw enable
```

### SELinux Configuration

```bash
# Set SELinux to enforcing mode
sudo setenforce 1

# Create SELinux policy for veil7
sudo semodule -i veil7.pp
```

### AppArmor Configuration

Create `/etc/apparmor.d/usr.local.bin.veil7`:

```
#include <tunables/global>

/usr/local/bin/veil7 {
  #include <abstractions/base>
  
  # Allow read access to configuration
  /etc/veil7/** r,
  
  # Allow read/write to data directory
  /var/lib/veil7/** rw,
  
  # Allow write to log directory
  /var/log/veil7/** w,
  
  # Deny network access (if not needed)
  deny network,
  
  # Deny ptrace
  deny ptrace,
  
  # Deny mount
  deny mount,
}
```

Load AppArmor profile:
```bash
sudo apparmor_parser -r /etc/apparmor.d/usr.local.bin.veil7
```

---

## 8. Monitoring Setup

### Logging

#### Log Format
```json
{
  "timestamp": "2026-06-15T12:00:00Z",
  "level": "INFO",
  "module": "veil7::l5_verify",
  "message": "Verification successful",
  "metadata": {
    "claim_hash": "abc123...",
    "latency_ms": 45.2
  }
}
```

#### Log Rotation

Create `/etc/logrotate.d/veil7`:

```
/var/log/veil7/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 veil7 veil7
    sharedscripts
    postrotate
        systemctl reload veil7
    endscript
}
```

### Metrics

#### Prometheus Metrics

Expose metrics endpoint at `http://localhost:9090/metrics`:

```prometheus
# HELP veil7_verifications_total Total number of verifications
# TYPE veil7_verifications_total counter
veil7_verifications_total{status="success"} 1234
veil7_verifications_total{status="failure"} 5

# HELP veil7_verification_latency_seconds Verification latency in seconds
# TYPE veil7_verification_latency_seconds histogram
veil7_verification_latency_seconds_bucket{le="0.01"} 100
veil7_verification_latency_seconds_bucket{le="0.05"} 500
veil7_verification_latency_seconds_bucket{le="0.1"} 900
veil7_verification_latency_seconds_bucket{le="+Inf"} 1000

# HELP veil7_memory_usage_bytes Memory usage in bytes
# TYPE veil7_memory_usage_bytes gauge
veil7_memory_usage_bytes 52428800

# HELP veil7_entropy_bits Entropy bits collected
# TYPE veil7_entropy_bits gauge
veil7_entropy_bits 256
```

#### Prometheus Configuration

Create `prometheus.yml`:

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'veil7'
    static_configs:
      - targets: ['localhost:9090']
```

### Alerting

Create `alerting.yml`:

```yaml
groups:
- name: veil7
  rules:
  - alert: HighErrorRate
    expr: rate(veil7_verifications_total{status="failure"}[5m]) > 0.1
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High error rate detected"
      description: "Error rate is {{ $value }} errors per second"

  - alert: HighLatency
    expr: histogram_quantile(0.95, rate(veil7_verification_latency_seconds_bucket[5m])) > 0.1
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High latency detected"
      description: "95th percentile latency is {{ $value }} seconds"

  - alert: HighMemoryUsage
    expr: veil7_memory_usage_bytes > 268435456
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High memory usage detected"
      description: "Memory usage is {{ $value }} bytes"
```

---

## 9. Backup Strategy

### Data Backup

```bash
# Backup data directory
sudo tar -czf veil7-data-$(date +%Y%m%d).tar.gz /var/lib/veil7

# Backup configuration
sudo tar -czf veil7-config-$(date +%Y%m%d).tar.gz /etc/veil7

# Backup logs (optional)
sudo tar -czf veil7-logs-$(date +%Y%m%d).tar.gz /var/log/veil7
```

### Automated Backup Script

Create `/usr/local/bin/backup-veil7.sh`:

```bash
#!/bin/bash

BACKUP_DIR="/backup/veil7"
DATE=$(date +%Y%m%d)

# Create backup directory
mkdir -p $BACKUP_DIR

# Backup data
tar -czf $BACKUP_DIR/veil7-data-$DATE.tar.gz /var/lib/veil7

# Backup configuration
tar -czf $BACKUP_DIR/veil7-config-$DATE.tar.gz /etc/veil7

# Remove old backups (keep 30 days)
find $BACKUP_DIR -name "veil7-*.tar.gz" -mtime +30 -delete

echo "Backup completed: $DATE"
```

Add to crontab:
```bash
# Backup daily at 2 AM
0 2 * * * /usr/local/bin/backup-veil7.sh
```

### Restore Procedure

```bash
# Stop service
sudo systemctl stop veil7

# Restore data
sudo tar -xzf veil7-data-20260615.tar.gz -C /

# Restore configuration
sudo tar -xzf veil7-config-20260615.tar.gz -C /

# Restart service
sudo systemctl start veil7
```

---

## 10. Performance Tuning

### Kernel Tuning

```bash
# Increase file descriptor limit
ulimit -n 65536

# Increase mlock limit
ulimit -l unlimited

# Optimize network stack
sudo sysctl -w net.core.somaxconn=65535
sudo sysctl -w net.core.netdev_max_backlog=65535
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=65535
```

### Application Tuning

#### Batch Size Tuning

Edit `/etc/veil7/config.toml`:

```toml
[performance]
batch_size = 1000  # Increase for higher throughput
parallel_verification = true
max_threads = 8  # Adjust based on CPU cores
```

#### Memory Tuning

Edit `/etc/veil7/config.toml`:

```toml
[memory]
lock_memory = true
mlock_limit = "unlimited"
zeroize_on_drop = true
preallocate_memory = true  # Preallocate memory pools
```

### Monitoring Performance

```bash
# Monitor CPU usage
top -p $(pgrep veil7)

# Monitor memory usage
watch -n 1 'ps -o pid,vsz,rss,comm -p $(pgrep veil7)'

# Monitor system calls
strace -p $(pgrep veil7) -e trace=mlock,munlock,write

# Monitor network
netstat -anp | grep veil7
```

### Profiling

```bash
# Install profiling tools
cargo install flamegraph

# Generate flamegraph
cargo flamegraph --bin veil7 -- verify-once "test claim"

# Profile with perf
perf record -g target/release/veil7 verify-once "test claim"
perf report
```

---

## Appendix A: Troubleshooting

### Common Issues

#### Issue: mlock() fails

**Symptom:** `Error: Failed to lock memory`

**Solution:**
```bash
# Check mlock limit
ulimit -l

# Increase mlock limit
ulimit -l unlimited

# Or edit /etc/security/limits.conf
* soft memlock unlimited
* hard memlock unlimited
```

#### Issue: High memory usage

**Symptom:** Memory usage exceeds 256 MB

**Solution:**
```bash
# Check memory usage
ps -o pid,vsz,rss,comm -p $(pgrep veil7)

# Reduce batch size in config
[performance]
batch_size = 50

# Restart service
sudo systemctl restart veil7
```

#### Issue: High latency

**Symptom:** Verification latency > 100ms

**Solution:**
```bash
# Check CPU usage
top -p $(pgrep veil7)

# Enable parallel verification
[performance]
parallel_verification = true
max_threads = 8

# Restart service
sudo systemctl restart veil7
```

---

## Appendix B: Security Checklist

### Pre-Deployment Security Checklist

- [ ] mlock limit increased
- [ ] Core dumps disabled
- [ ] Swap disabled (optional)
- [ ] ASLR enabled
- [ ] Firewall configured
- [ ] SELinux/AppArmor configured
- [ ] Dedicated user created
- [ ] Directory permissions set
- [ ] No world-readable secrets
- [ ] Binary permissions correct

### Runtime Security Checklist

- [ ] Memory locking active
- [ ] Zeroization working
- [ ] No metadata leakage
- [ ] Constant-time verified
- [ ] No timing attacks
- [ ] No side-channel attacks
- [ ] No memory attacks
- [ ] No entropy attacks
- [ ] No replay attacks
- [ ] No metadata attacks

---

*End of DEPLOYMENT.md*

*Document generated: 2026-06-15*  
*Version: 1.0*
