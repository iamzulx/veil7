# Incident Response Plan — veil7

> **Version:** 1.0
> **Effective Date:** 2026-06-14
> **Review Cycle:** Annual or after any incident

---

## 1. Overview

This plan covers security incidents related to the veil7 cryptographic library
and its deployment. Since veil7 uses exclusively ephemeral keys with no
persistent state, the attack surface is significantly reduced compared to
traditional cryptographic systems.

---

## 2. Incident Classification

| Severity | Definition | Response Time | Examples |
|----------|-----------|---------------|----------|
| **Critical** | Active exploitation, key material exposed | 1 hour | Side-channel key recovery, CSPRNG compromise |
| **High** | Vulnerability discovered, not yet exploited | 24 hours | CVE in dependency, Miri finding |
| **Medium** | Policy violation, configuration issue | 72 hours | Non-compliant deployment, access control gap |
| **Low** | Documentation gap, minor bug | 2 weeks | Missing doc, non-security bug |

---

## 3. Incident Response Team

| Role | Responsibility | Contact |
|------|---------------|---------|
| **Incident Commander** | Coordinates response, makes decisions | Security lead |
| **Technical Lead** | Investigates technical details, implements fixes | Lead developer |
| **Communications** | Internal/external communications | Project manager |
| **Forensics** | Evidence collection, log analysis | Security auditor |

---

## 4. Response Procedures

### 4.1 Critical: Active Key Compromise

Since veil7 uses ephemeral keys, "key compromise" means:

1. **Identify the affected iteration(s)** — which iterations may have been compromised
2. **Stop the affected deployment** — halt the application using veil7
3. **Assess impact** — determine what verdicts were produced with potentially compromised keys
4. **Notify affected parties** — inform users of potentially invalid verdicts
5. **Investigate root cause** — side-channel? CSPRNG failure? Memory leak?
6. **Implement fix** — patch the vulnerability
7. **Redeploy** — deploy patched version
8. **Post-incident review** — within 48 hours

**Note:** Since keys are ephemeral, compromise is limited to the specific
iteration(s) affected. No key rotation or revocation is needed.

### 4.2 High: Dependency Vulnerability

1. **Assess severity** — check CVE details, affected versions
2. **Check if veil7 is affected** — verify dependency version in Cargo.lock
3. **Implement fix** — update dependency or apply workaround
4. **Test** — verify fix doesn't break functionality
5. **Release** — publish patched version
6. **Notify users** — security advisory via GitHub Security Advisories

### 4.3 High: Miri/Fuzzing Finding

1. **Reproduce** — confirm the finding locally
2. **Classify** — is it a real vulnerability or false positive?
3. **Fix** — implement fix with test coverage
4. **Verify** — re-run Miri/fuzzing to confirm fix
5. **Release** — publish patched version

### 4.4 Medium: Policy Violation

1. **Document** — record the violation
2. **Assess risk** — determine potential impact
3. **Remediate** — fix the configuration or process
4. **Verify** — confirm remediation
5. **Update policy** — prevent recurrence

---

## 5. Communication Plan

### Internal

| Audience | Method | Timing |
|----------|--------|--------|
| Development team | Direct message | Immediate |
| Management | Email | Within 4 hours (Critical) |
| Security team | Direct message | Immediate |

### External

| Audience | Method | Timing |
|----------|--------|--------|
| Users | GitHub Security Advisory | Within 24 hours (High+) |
| Downstream integrators | Email + advisory | Within 24 hours (High+) |
| Public | GitHub Security Advisory | After fix is available |

### Disclosure Policy

- **Coordinated disclosure**: 90-day embargo for vulnerabilities
- **CVE assignment**: Request CVE for all High+ vulnerabilities
- **Advisory format**: GitHub Security Advisory (GHSA)

---

## 6. Evidence Collection

| Evidence Type | Source | Retention |
|---------------|--------|-----------|
| Application logs | Deployment logs | 1 year |
| CI/CD logs | GitHub Actions | 90 days |
| Miri/fuzzing output | CI artifacts | 90 days |
| Git history | GitHub | Permanent |
| Communication records | Email, messages | 1 year |
| Incident reports | Incident tracking | 3 years |

---

## 7. Post-Incident Review

Within 48 hours of incident resolution:

1. **Timeline** — document complete incident timeline
2. **Root cause** — identify and document root cause
3. **Impact assessment** — quantify impact (users, data, systems)
4. **Lessons learned** — what worked, what didn't
5. **Action items** — specific improvements to prevent recurrence
6. **Policy updates** — update relevant policies
7. **Report** — publish post-incident report (internal)

---

## 8. Specific Scenarios

### CSPRNG Failure

**Detection:** `harvest()` returns `VeilError::Entropy`
**Impact:** No keys generated, no operations proceed
**Response:**
1. Investigate OS entropy source (`/dev/urandom`, `getrandom()`)
2. Check `RLIMIT_MEMLOCK` (may affect `mlock`)
3. Restart application if needed
4. Monitor for recurrence

### Side-Channel Attack Detected

**Detection:** `dudect` test failure, anomalous timing measurements
**Impact:** Potential key recovery for affected iterations
**Response:**
1. Move to single-tenant hardware immediately
2. Enable `keccak_ct` masked sponge (already default)
3. Investigate attack vector
4. Implement additional mitigations
5. Consider hardware upgrade

### Supply Chain Compromise

**Detection:** `cargo audit` alert, `cargo vet` failure
**Impact:** Potentially compromised dependency
**Response:**
1. Pin to known-good dependency version
2. Investigate compromise scope
3. Audit code changes in affected dependency
4. Update to patched version when available
5. Review all verdicts produced during compromise window

---

## 9. Tools and Resources

| Tool | Purpose | Location |
|------|---------|----------|
| GitHub Security Advisories | Vulnerability disclosure | github.com/iamzulx/veil7/security |
| `cargo audit` | Dependency vulnerability scanning | CI pipeline |
| `cargo vet` | Supply chain verification | CI pipeline |
| Miri | Memory safety checking | CI pipeline |
| cargo-fuzz | Fuzz testing | CI pipeline |

---

## 10. Review History

| Date | Change | Reviewer |
|------|--------|----------|
| 2026-06-14 | Initial plan created | veil7 team |
