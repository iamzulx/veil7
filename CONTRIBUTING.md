# Contributing to veil7

> **Project:** veil7  
> **Version:** 1.0  
> **Last Updated:** 2026-06-15  
> **Status:** Open for Contributions

---

Thank you for your interest in contributing to veil7! This document provides guidelines and information for contributors.

---

## Table of Contents

1. [Code of Conduct](#1-code-of-conduct)
2. [How to Contribute](#2-how-to-contribute)
3. [Development Setup](#3-development-setup)
4. [Code Style Guidelines](#4-code-style-guidelines)
5. [Testing Requirements](#5-testing-requirements)
6. [Pull Request Process](#6-pull-request-process)
7. [Security Disclosure Policy](#7-security-disclosure-policy)
8. [Getting Help](#8-getting-help)

---

## 1. Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

**Key Principles:**
- Be respectful and inclusive
- Use welcoming and inclusive language
- Be collaborative
- Be patient and helpful
- Focus on what's best for the community

**Unacceptable Behavior:**
- Harassment, discrimination, or offensive comments
- Trolling, insulting/derogatory comments, personal or political attacks
- Public or private harassment
- Publishing others' private information without permission
- Other conduct which could reasonably be considered inappropriate

**Reporting:**
- Report unacceptable behavior to: security@iamzulx.com
- All reports will be reviewed and investigated
- Confidentiality will be maintained

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for full details.

---

## 2. How to Contribute

### Types of Contributions

We welcome many types of contributions:

#### Code Contributions
- Bug fixes
- New features
- Performance improvements
- Code refactoring
- Documentation improvements

#### Documentation Contributions
- README improvements
- API documentation
- Tutorial writing
- Example code
- Translation

#### Bug Reports
- Bug reports with reproduction steps
- Feature requests
- Performance issues
- Security vulnerabilities (see Security Disclosure Policy)

#### Community Contributions
- Answering questions
- Reviewing pull requests
- Improving documentation
- Helping new contributors

### Contribution Workflow

```
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Write tests
5. Run tests locally
6. Submit a pull request
7. Address review feedback
8. Merge
```

---

## 3. Development Setup

### Prerequisites

- **Rust:** 1.75+ (stable)
- **Git:** Latest version
- **OS:** Linux, macOS, or Windows

### Installation

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Clone repository
git clone https://github.com/iamzulx/veil7.git
cd veil7

# Build
cargo build

# Run tests
cargo test
```

### Development Tools

**Recommended Tools:**
- **rust-analyzer:** Rust language server for IDE support
- **cargo-watch:** Auto-rebuild on file changes
- **cargo-edit:** Manage dependencies
- **cargo-expand:** Expand macros
- **cargo-outdated:** Check for outdated dependencies

**Installation:**
```bash
# Install cargo-edit
cargo install cargo-edit

# Install cargo-watch
cargo install cargo-watch

# Install cargo-expand
cargo install cargo-expand

# Install cargo-outdated
cargo install cargo-outdated
```

### IDE Setup

**VS Code:**
1. Install rust-analyzer extension
2. Install CodeLLDB extension (for debugging)
3. Open project in VS Code

**IntelliJ IDEA:**
1. Install Rust plugin
2. Open project in IntelliJ IDEA

**Vim/Neovim:**
1. Install rust-analyzer
2. Configure LSP client

---

## 4. Code Style Guidelines

### Rust Style

**Formatting:**
- Use `cargo fmt` to format code
- Follow Rust style guidelines
- Use rustfmt.toml for project-specific rules

**Naming Conventions:**
- **Types:** PascalCase (e.g., `Verdict`, `Claim`)
- **Functions:** snake_case (e.g., `verify_once`, `verify_batch`)
- **Constants:** SCREAMING_SNAKE_CASE (e.g., `MAX_THREADS`)
- **Variables:** snake_case (e.g., `claim_data`, `verdict_result`)

**Documentation:**
- Document all public APIs
- Use `///` for documentation comments
- Include examples in documentation
- Document security properties

**Error Handling:**
- Use `Result<T, VeilError>` for error handling
- Use `?` operator for error propagation
- Document error conditions
- Use custom error types

**Example:**
```rust
/// Verifies a claim and returns a verdict.
///
/// # Arguments
/// * `claim` - The claim to verify
///
/// # Returns
/// * `Ok(Verdict)` - Verification result
/// * `Err(VeilError)` - Verification failed
///
/// # Example
/// ```rust
/// let claim = Claim::new(b"Hello, World!");
/// let verdict = verify_once(&claim)?;
/// ```
pub fn verify_once(claim: &Claim) -> Result<Verdict, VeilError> {
    // Implementation
}
```

### Security Guidelines

**Memory Safety:**
- Use `Zeroize` trait for sensitive data
- Use `mlock()` for memory locking
- Use volatile writes for zeroization
- Use compiler fences

**Constant-Time:**
- Use `subtle::Choice` for boolean operations
- Avoid secret-dependent branches
- Use constant-time comparisons
- Document constant-time properties

**Error Handling:**
- Don't leak sensitive information in errors
- Use generic error messages
- Document error conditions
- Use custom error types

---

## 5. Testing Requirements

### Test Coverage

**Minimum Coverage:**
- Line coverage: 90%
- Branch coverage: 85%
- Function coverage: 100%

**Test Types:**
- Unit tests (for each function)
- Integration tests (for pipelines)
- Property tests (QuickCheck)
- Formal verification (Kani)
- Fuzzing (cargo-fuzz)
- Memory safety (Miri)

### Writing Tests

**Unit Tests:**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_verify_once() {
        let claim = Claim::new(b"test");
        let verdict = verify_once(&claim).unwrap();
        assert!(verdict.is_valid());
    }
}
```

**Integration Tests:**
```rust
#[test]
fn test_full_pipeline() {
    let claim = Claim::new(b"test");
    let verdict = verify_once(&claim).unwrap();
    assert!(verdict.is_valid());
    assert_eq!(verdict.transcript().len(), 32);
}
```

**Property Tests:**
```rust
quickcheck! {
    fn prop_verify_once(claim: Vec<u8>) -> bool {
        let claim = Claim::new(&claim);
        let verdict = verify_once(&claim).unwrap();
        verdict.is_valid()
    }
}
```

### Running Tests

```bash
# Run all tests
cargo test

# Run unit tests
cargo test --lib

# Run integration tests
cargo test --test '*'

# Run specific test
cargo test test_verify_once

# Run with output
cargo test -- --nocapture

# Run with coverage
cargo tarpaulin --out Html
```

---

## 6. Pull Request Process

### Before Submitting

**Checklist:**
- [ ] Code follows style guidelines
- [ ] All tests pass
- [ ] Tests added for new functionality
- [ ] Documentation updated
- [ ] No security vulnerabilities
- [ ] Performance impact assessed
- [ ] Changelog updated (if applicable)

### Pull Request Template

```markdown
## Description
Brief description of changes.

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Performance improvement
- [ ] Documentation
- [ ] Refactoring

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] All tests pass

## Documentation
- [ ] Documentation updated
- [ ] Examples added (if applicable)

## Security
- [ ] No security vulnerabilities introduced
- [ ] Security impact assessed

## Performance
- [ ] Performance impact assessed
- [ ] Benchmarks run (if applicable)

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex code
- [ ] Changelog updated (if applicable)
```

### Review Process

**Review Criteria:**
- Code quality and style
- Test coverage
- Documentation quality
- Security considerations
- Performance impact

**Review Timeline:**
- Initial review: 2-3 business days
- Subsequent reviews: 1-2 business days
- Merge: After approval

**Review Feedback:**
- Address all feedback
- Update PR with changes
- Request re-review

---

## 7. Security Disclosure Policy

### Responsible Disclosure

**If you discover a security vulnerability:**

1. **DO NOT** create a public GitHub issue
2. **DO NOT** disclose the vulnerability publicly
3. **DO** email: security@iamzulx.com
4. **DO** include:
   - Description of vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### Response Timeline

- **Acknowledgment:** 24 hours
- **Initial assessment:** 48 hours
- **Detailed response:** 7 days
- **Fix timeline:** Depends on severity

### Severity Levels

| Severity | Response Time | Fix Timeline |
|----------|---------------|--------------|
| Critical | 24 hours | 7 days |
| High | 48 hours | 14 days |
| Medium | 7 days | 30 days |
| Low | 14 days | 60 days |

### Disclosure Process

1. **Report:** Email security@iamzulx.com
2. **Acknowledge:** We acknowledge receipt within 24 hours
3. **Assess:** We assess the vulnerability within 48 hours
4. **Fix:** We develop and test a fix
5. **Release:** We release a security update
6. **Disclose:** We disclose the vulnerability after the fix is released

### Recognition

- Contributors who report security vulnerabilities will be credited
- Credit will be added to SECURITY.md
- Credit will be added to CHANGELOG.md
- Credit will be added to release notes

---

## 8. Getting Help

### Communication Channels

**GitHub Issues:**
- Bug reports
- Feature requests
- General questions
- https://github.com/iamzulx/veil7/issues

**Email:**
- General: info@iamzulx.com
- Security: security@iamzulx.com
- Support: support@iamzulx.com

**Documentation:**
- README.md - Project overview
- USER_GUIDE.md - User guide
- DEPLOYMENT.md - Deployment guide
- API documentation - Generated with `cargo doc`

### Getting Started

**New Contributors:**
1. Read CONTRIBUTING.md (this document)
2. Read CODE_OF_CONDUCT.md
3. Browse open issues
4. Start with "good first issue" label
5. Ask questions in issues

**Finding Issues:**
- "good first issue" - Good for new contributors
- "help wanted" - Help needed
- "bug" - Bug fixes
- "enhancement" - New features
- "documentation" - Documentation improvements

### Mentorship

**New Contributors:**
- Mentorship available for new contributors
- Ask for help in issues
- Pair programming available
- Code review available

---

## Appendix A: Development Workflow

### Feature Development

```bash
# 1. Fork repository
git clone https://github.com/yourusername/veil7.git
cd veil7

# 2. Create feature branch
git checkout -b feature/my-feature

# 3. Make changes
# ... edit files ...

# 4. Write tests
# ... add tests ...

# 5. Run tests
cargo test

# 6. Commit changes
git add .
git commit -m "feat: add my feature"

# 7. Push to fork
git push origin feature/my-feature

# 8. Create pull request
# ... create PR on GitHub ...
```

### Bug Fix Development

```bash
# 1. Fork repository
git clone https://github.com/yourusername/veil7.git
cd veil7

# 2. Create bug fix branch
git checkout -b fix/bug-description

# 3. Fix bug
# ... edit files ...

# 4. Write test for bug
# ... add test ...

# 5. Run tests
cargo test

# 6. Commit changes
git add .
git commit -m "fix: fix bug description"

# 7. Push to fork
git push origin fix/bug-description

# 8. Create pull request
# ... create PR on GitHub ...
```

---

## Appendix B: Code Review Guidelines

### For Reviewers

**Review Checklist:**
- [ ] Code follows style guidelines
- [ ] Tests added for new functionality
- [ ] Documentation updated
- [ ] Security considerations addressed
- [ ] Performance impact assessed
- [ ] No breaking changes (or documented)

**Review Focus:**
- Code quality and readability
- Test coverage and quality
- Documentation completeness
- Security considerations
- Performance impact
- API design

**Feedback Guidelines:**
- Be constructive and respectful
- Explain the "why" behind feedback
- Provide examples when helpful
- Suggest improvements, don't demand

### For Contributors

**Addressing Feedback:**
- Address all feedback
- Ask for clarification if needed
- Update PR with changes
- Request re-review

**Review Timeline:**
- Initial review: 2-3 business days
- Subsequent reviews: 1-2 business days
- Merge: After approval

---

## Appendix C: Resources

### Documentation

- [README.md](../README.md) - Project overview
- [USER_GUIDE.md](docs/USER_GUIDE.md) - User guide
- [DEPLOYMENT.md](docs/DEPLOYMENT.md) - Deployment guide
- [ARCHITECTURE_DIAGRAM.md](docs/ARCHITECTURE_DIAGRAM.md) - Architecture diagram
- [BENCHMARKS.md](docs/BENCHMARKS.md) - Performance benchmarks
- [SECURITY_AUDIT_REPORT.md](docs/SECURITY_AUDIT_REPORT.md) - Security audit report

### External Resources

- [Rust Book](https://doc.rust-lang.org/book/) - Rust programming language
- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/) - API design guidelines
- [Rust Security](https://doc.rust-lang.org/nomicon/) - Rust security guide
- [libcrux](https://github.com/cryspen/libcrux) - Formally verified crypto library
- [Kani](https://github.com/model-checking/kani) - Formal verification tool

---

*End of CONTRIBUTING.md*

*Document generated: 2026-06-15*  
*Version: 1.0*
