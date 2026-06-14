# Identity and Access Management (IAM) & Role-Based Access Control (RBAC)

> **Version:** 1.0
> **Effective Date:** 2026-06-14
> **Review Cycle:** Annual or upon organizational change

---

## 1. Overview

veil7 is a **stateless cryptographic library** with no built-in identity management,
user accounts, or access control. All IAM/RBAC responsibilities lie with the
**integrating application** and **deployment infrastructure**.

This document defines the recommended IAM/RBAC framework for applications
integrating veil7.

---

## 2. Roles

| Role | Description | Access Level |
|------|-------------|-------------|
| **Library Integrator** | Developer integrating veil7 into an application | Source code, build system |
| **Application Operator** | Deploys and manages the application using veil7 | Production environment, configuration |
| **Security Auditor** | Reviews cryptographic policy and compliance | Read-only access to policy docs, audit logs |
| **Infrastructure Admin** | Manages servers, CI/CD, deployment pipelines | Infrastructure, CI/CD secrets |
| **End User** | Uses the application (not veil7 directly) | Application-level access only |

---

## 3. Access Control Matrix

| Resource | Integrator | Operator | Auditor | Infra Admin | End User |
|----------|:----------:|:--------:|:-------:|:-----------:|:--------:|
| veil7 source code | RW | R | R | R | — |
| CI/CD pipelines | RW | R | R | RW | — |
| Production deployment | — | RW | R | RW | — |
| CRYPTO_POLICY.md | RW | R | RW | R | — |
| IAM_RBAC.md (this doc) | RW | R | RW | RW | — |
| SBOM / audit artifacts | R | R | RW | R | — |
| Application secrets | — | RW | R | R | — |
| End-user data | — | R | R | — | RW (own data) |

---

## 4. Separation of Duties

| Principle | Implementation |
|-----------|---------------|
| **Build ≠ Deploy** | CI/CD builds artifacts; separate pipeline deploys |
| **Develop ≠ Operate** | Developers write code; operators manage production |
| **Audit ≠ Operate** | Auditors review but cannot modify production |
| **Key Generation ≠ Key Usage** | veil7 generates ephemeral keys; application uses verdicts |

---

## 5. Authentication Requirements

| Context | Requirement |
|---------|-------------|
| Source code repository | MFA-required GitHub account |
| CI/CD secrets | Encrypted, access-controlled per environment |
| Production servers | SSH key-based auth, MFA for console access |
| Policy document changes | PR review required (minimum 1 reviewer) |
| Dependency updates | Dependabot PR + manual review for major versions |

---

## 6. Privileged Access

### Elevated Privileges

| Action | Requires | Approval |
|--------|----------|----------|
| Merge to `main` branch | PR review | 1+ reviewer |
| Modify CI/CD secrets | Infra Admin | Written approval |
| Change CRYPTO_POLICY.md | PR review | Security Auditor approval |
| Deploy to production | Infra Admin + Operator | Written approval |
| Disable security checks | Infra Admin + Security Auditor | Written approval + incident report |

### Temporary Access

- Temporary elevated access must be time-bounded (max 24 hours).
- All temporary access must be logged and reviewed within 48 hours.
- No standing elevated access for any role.

---

## 7. Access Review

| Frequency | Scope | Responsible |
|-----------|-------|-------------|
| Quarterly | GitHub repository access | Integrator lead |
| Quarterly | Production server access | Infra Admin |
| Annually | Full IAM/RBAC policy review | Security Auditor |
| On change | Role changes, departures | HR + Infra Admin |

---

## 8. Logging and Monitoring

| Event | Logged | Retention |
|-------|--------|-----------|
| Code commit / merge | GitHub audit log | 1 year |
| CI/CD pipeline run | GitHub Actions log | 90 days |
| Production deployment | Deployment log | 1 year |
| Policy document change | Git history | Permanent |
| Access grant / revoke | IAM system log | 1 year |
| Failed authentication | Auth system log | 90 days |

---

## 9. Compliance Mapping

| Requirement | Control | Evidence |
|-------------|---------|----------|
| SOC 2 CC6.1 (Logical Access) | RBAC matrix above | This document |
| SOC 2 CC6.3 (Access Removal) | Quarterly access review | Review records |
| ISO 27001 A.9.1 (Access Control) | Role definitions | This document |
| ISO 27001 A.9.2 (User Access) | Authentication requirements | This document |
| ISO 27001 A.9.4 (System Access) | Privileged access controls | This document |

---

## 10. Review History

| Date | Change | Reviewer |
|------|--------|----------|
| 2026-06-14 | Initial policy created | veil7 team |
