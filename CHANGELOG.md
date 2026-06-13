# Changelog

## Unreleased

### Added

- **`attest_chain` for tamper-evident log append** (USE_CASES.md §7)
  - New `veil7::interface::attest_chain(&[&[u8]]) -> Result<Verdict, VeilError>`
    folds a sequence of events through a domain-separated SHAKE256
    accumulator (`CHAIN_HEAD` + `CHAIN_STEP` per event) and attests the
    final 32-byte root in a single ML-DSA iteration. Tampering with any
    event in the chain changes the root, so the single returned `Verdict`
    covers the whole sequence.
  - `attest_chain` is **std-gated** via the `interface` module because it
    calls the ML-DSA pipeline (`verify_once`) which auto-harvests entropy.
  - The pure accumulator is split into a separate `no_std`-available
    module: `veil7::chain::chain_root(&[&[u8]]) -> Result<[u8; 32], VeilError>`.
    `no_std` callers can compute the root locally and feed it into
    `verify_once_with_seed` for attestation. The root is a public anchor
    (reproducible by anyone holding the events) so it is not wiped on
    return; the engine scrubs it at the L6 barrier.
  - New `chain` CLI subcommand: `veil7 chain <ev> [<ev>..]` returns the
    anchor `Verdict` plus the raw `root=` (64 hex chars) so the auditor
    can extract it for the offline `verify` step.
  - **Universal verification oracle**: `veil7::chain::chain_verify(&[&[u8]],
    &[u8;32]) -> subtle::Choice`. Pure SHAKE256 math — no PQ, no entropy,
    no ephemeral identity. `Choice::from(1)` if `events` fold to
    `expected_root`, `Choice::from(0)` otherwise (including empty events).
    Auditors can check tamper-detection offline without keys, without
    the engine, without side effects.
  - New `verify` CLI subcommand: `veil7 verify <hex_root> <ev>..` returns
    `valid=1` (with the verified `transcript=<root>`) if events fold to
    root, or `valid=0` (with the actual computed root) if they don't.
    No PQ, no entropy, pure math.
  - New domain tags `CHAIN_HEAD` / `CHAIN_STEP` in `common::domain` for
    cross-protocol separation.
  - Empty input returns `VeilError::Crypto` — no chain to attest.
  - Unit tests in `src/chain.rs` cover `chain_verify` (4 tests) and
    `chain_root` (4 tests); the existing `real_data_attest_chain_tampered_
    event_changes_root` test in `tests/real_data.rs` is extended to
    exercise `chain_verify` as the universal-verification oracle.

- **Public re-export of `Seed`**
  - `veil7::Seed` is now reachable without importing
    `veil7::l1_entropy::Seed`. Useful for `no_std` callers using
    - **L1 entropy workflow rebuilt as multi-round mix**
      - `harvest()` now runs `MIX_ITERATIONS = 12` independent rounds of the
        pattern **harvest → hash → slice → rehash → fold**:
        1. read 48 bytes of OS CSPRNG + 24 bytes of jitter,
        2. SHAKE256(ENTROPY_MIX || counter || personalization || os || jitter)
           into 64 bytes `h1`,
        3. split `h1` into the first 32 and last 32 bytes,
        4. SHAKE256(ENTROPY_FOLD || counter || first_half) into 32 bytes `h2`,
        5. XOR `h2` into `pool[..32]` and raw `h1[32..]` into `pool[32..]`,
        6. zeroize all intermediates and repeat.
      - A final SHAKE256(ENTROPY_FINALIZE || personalization || pool) absorbs
        the XOR-folded pool directly into the locked 64-byte seed buffer.
      - Per-iteration counter and two distinct domain tags (`ENTROPY_MIX`,
        `ENTROPY_FOLD`, `ENTROPY_FINALIZE`) prevent cross-round collapse and
        cross-protocol collision. `ENTROPY_STRETCH` was removed in favour of
        the three split tags.
      - The CSPRNG remains the only cryptographic source. The 12 rounds
        deepen the defence-in-depth margin against a single failed / biased
        sample: every pool byte is touched by ≥12 independent entropy reads
        before uniformisation.
      - New test `different_personalization_produces_different_seed` proves
        the per-round personalization binding. New test
        `mix_workflow_completes_under_budget` pins the 12-round timing under
        500ms (aarch64) so CI catches catastrophic regressions.

    - **Multi-method entropy harvest with per-method untraceability**
      (G1 privacy-core inspired)
      - New `crate::entropy_sources` module exposes six independent entropy
        methods, each reading a **genuinely different raw source**:
        1. `os_csprng_primary`   — 64 bytes from `getrandom`
        2. `os_csprng_secondary` — 64 bytes from a separate `getrandom` call
        3. `wall_clock`          — `SystemTime::now()` nanoseconds
        4. `stack_addr`          — pointer to a stack-local variable
        5. `thread_id`           — hashed `std::thread::current().id()`
        6. `hw_counter`          — `Instant::elapsed()` ⊕ wall-clock nanos
      - `l1_entropy::harvest_multi_source(personalization)` folds all six
        methods into a 64-byte pool via **per-method untraceable whitening**:
        `whiten_i = SHAKE256(ENTROPY_SOURCE_i || raw_i)`. The final seed is
        `SHAKE256(ENTROPY_FINALIZE || personalization || pool)`.
      - **Untraceability property**: an observer who knows the final seed
        and all but one of the source's raw inputs **cannot recover the
        missing input**. The SHAKE256 preimage resistance of each per-method
        whiten, combined with the final `ENTROPY_FINALIZE` squeeze over the
        XOR-folded pool, makes the seed a one-way function of all six raw
        inputs jointly. No single source's contribution is identifiable in
        the final output.
      - Each method's raw buffer is `ZeroizeOnDrop` (via `EntropySource`'s
        `Drop` impl) and explicitly wiped after whitening.
      - `no_std` stubs return zero-raw buffers for the non-cSPRNG methods
        and `Err` for the cSPRNG methods (no OS entropy = fail-closed).
      - 7 unit tests in `src/entropy_sources.rs::tests` (whiten is
        deterministic, tag separates, raw separates, shared-reference
        borrow, wipe zeros, drop zeros, all 6 constructors valid).
      - 6 unit tests in `src/layers/l1_entropy.rs::tests` for
        `harvest_multi_source` (full seed, two-runs-differ,
        personalization-binds, seed-wipes, budget, avalanche).

- **`chain::ChainState` incremental accumulator + streaming file attest**
  - `ChainState::new()` / `absorb(&[u8])` / `finalize() -> [u8; 32]` is
    the streaming counterpart to `chain_root`. Lets callers (large files,
    network feeds) keep their event buffer bounded to one chunk.
  - `interface::attest_file_streaming` uses `ChainState` to read files
    in 4KB chunks and attest the file without ever loading the whole
    content into memory. Empty files are rejected (`VeilError::Crypto`).
  - The chunk buffer is wiped after each read; the finalised root is
    public so it is not wiped; the engine scrubs it at the L6 barrier.
  - `attest_file_streaming_with_chunk_size(path, n)` lets callers tune
    the buffer footprint for their device.
  - 4 new unit tests in `src/chain.rs` for `ChainState`; 5 new tests
    in `tests/real_data.rs` for the streaming path (loaded vs
    streaming, multi-chunk, missing, empty, merkle round-trip).

- **Universal-verification CLI surface (`prove <relation>`)**
  - `veil7 prove hash-preimage <hex_seed>` runs the Lamport
    hash-preimage relation. Verifies knowledge of a 32-byte secret whose
    derived public key is the statement.
  - `veil7 prove merkle-root <hex_leaves..>` computes the Merkle root
    of a leaf set. Pure math, no PQ, no entropy.
  - `veil7 prove merkle-include <hex_leaf> <hex_root> <index> <hex_sib>..`
    verifies a Merkle inclusion proof. Pure math, constant-time
    `Choice`. Auditors can check certificate-transparency / log
    inclusion proofs offline without the engine, without keys.
  - `veil7 prove ml-dsa <hex_seed>` runs the ML-DSA-65 key-knowledge
    relation. Verifies knowledge of a seed that derives the verifying
    key the engine bound to its transcript.
  - All four subcommands return the engine's `valid=<0|1> transcript=<hex>`
    format. Output is parseable, single-line, no metadata.

- **`chain-root <ev>..` standalone CLI subcommand**
  - Computes the chain root only — no PQ, no entropy, no ephemeral
    identity. Symmetric to `chain` (attest via PQ) and `verify` (check
    against known root). For auditors who want the root without the
    full pipeline.

- **Pure-math Merkle helpers (`merkle_root`, `merkle_verify_path`)**
  - `merkle_root(leaves: &[&[u8]]) -> [u8; 32]` — prover side of the
    Merkle inclusion relation, exposed standalone for streaming
    composition.
  - `merkle_verify_path(leaf, root, index, siblings, leaf_count) ->
    subtle::Choice` — verifier side, same `Choice` contract as
    `chain_verify`. The auditor side of certificate-transparency
    proofs.
  - 4 new unit tests in `src/relations/merkle.rs` for the helpers
    (relation round-trip, tampered sibling, empty input).

- **FIPS 206 FN-DSA / FALCON scaffold (`src/pq_backends/fn_dsa.rs`)**
  - Locked-in public type surface (`SecretKey`, `PublicKey`,
    `SignatureBytes`, `verify -> Choice`) ready to swap in the real
    FALCON math when NIST finalises FIPS 206 (draft submitted
    2025-08-28, final expected late 2026 / early 2027) and a stable
    upstream crate is published.
  - `verify` is a **fail-closed no-op** (`Choice::from(0u8)`) until
    then — better to refuse all verifications than to emit false
    positives. Hardening test
    `verification_public_boundaries_return_choice` exercises the
    `Choice` signature so the no-op keeps the engine contract honest.
  - 5 new unit tests in `src/pq_backends/fn_dsa.rs` (fail-closed
    verify, fail-closed for zero-length sig, `derive` returns `None`,
    `sign` returns `None`, scaffold buffer untouched).
  - `pq_backends/mod.rs` updated to document the current backend set
    and the activation checklist for FN-DSA.

### Fixed

- **clippy `-D warnings` now passes**
  - `src/main.rs:37` had a `"help" | _ => …` arm that tripped
    `clippy::wildcard_in_or_patterns`. Split into two arms.

- **`no_std` support**
  - Added `std` feature (default) to `Cargo.toml`.
  - Gated OS entropy (`getrandom`, `SystemTime`) behind `#[cfg(feature = "std")]`.
  - Exposed `Seed::from_bytes` and `harvest_external` for external entropy in
    `no_std` builds.
  - Added `verify_once_with_seed` and `prove_and_verify_with_entropy` as
    `no_std`-compatible entry points.
  - Made `Debug` for `Verdict` zero-allocation (`core::fmt::Write`).
  - Verified: `cargo check --no-default-features` compiles clean.

- **Demo pipelines wiring ORAM + MicroVM**
  - `verify_once_with_oram` — stores seed in `ObliviousRAM`, reads back via
    constant-time path before keygen.
  - `verify_once_with_vm` — runs claim through `MicroVM`, uses deterministic
    VM root as entropy personalization.

- **New test suites**
  - `tests/bench.rs` — lightweight latency benchmarks via `std::time::Instant`
    (no Criterion).
  - `tests/fuzz_manual.rs` — random-input stress tests using OS CSPRNG;
    no `cargo-fuzz` / nightly required.
  - `tests/adversarial.rs` — 15 negative tests covering forged proofs,
    tampered siblings/roots/leaves, wrong indices, malformed signatures, and
    deterministic relation transcript stability.
  - `tests/real_data.rs` — reads `math_claims.txt`, tests both legacy
    `verify_once` attestation and a custom `MathSum` relation via
    `prove_and_verify`.
  - `math_claims.txt` — sample arithmetic data for real-data test.

- **Custom relation demo (`MathSum`)**
  - Implemented in `tests/real_data.rs` as a proof-of-knowledge relation:
    witness = `{a, b}`, statement = `{s = a + b}`.
  - Constant-time verification via `subtle::ConstantTimeEq` on `u64` bytes.

### Hardened

- Added volatile wipe helpers in `l0_memlock` and routed veil7-owned secret
  scrubbing through them.
- Marked custom security-critical `Drop` impls as `#[inline(never)]`.
- Standardized public verification boundaries on `subtle::Choice`.
- Reworked ORAM reads to use mask-based selection instead of branchful index
  selection.
- Confined `unsafe` to `src/layers/l0_memlock.rs`.
- Added `tests/hardening.rs` source-level regression guards for:
  - `Choice` verification boundaries,
  - no bool-returning `verify` APIs,
  - no direct `.zeroize()` in project-owned source,
  - `#[inline(never)]` custom drops,
  - no secret-path div/rem syntax,
  - no unsafe outside L0.
- Added `scripts/check-hardening.sh` and `scripts/scan-secret-div.py` for CI
  hardening checks.
- Added `.github/workflows/hardening.yml` with hardening guards and
  `cargo-audit`.
- Added `SECURITY.md` documenting threat model, dependency assumptions, memory
  locking gaps, and hardware timing-test requirements.
