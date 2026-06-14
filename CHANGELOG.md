# Changelog

## Unreleased

### Security Audit Fixes (2026-06)

Full codebase security audit performed. All HIGH and MEDIUM findings resolved:

- **H1:** KEM private key wipe — `l0_memlock::zeroize_slice()` for in-place wipe
  of libcrux private key bytes (unsafe encapsulated in l0_memlock)
- **H2:** Removed `Shake256Reader::read_extended()` (latent correctness bug)
- **H3:** Added `call_counter` to `CtShake256` — prevents mask stream reuse
- **M1:** Removed `Default` impl from `CtShake256` (fixed mask was security risk)
- **M2:** `ct_shake256()` now returns `Result` (no silent fallback to fixed mask)
- **L2:** `Shake256Reader::read()` no longer panics (truncates + zero-fills)
- **L6:** `Commitment` Debug impl redacts bytes (no metadata leakage)

### Dependency Migration (2026-06)

- **ML-KEM-768:** Migrated from RustCrypto `ml-kem 0.3` to `libcrux-ml-kem 0.0.9`
  (hax/F* formally verified, constant-time, NIST ACVP validated byte-perfect)
- **ML-DSA-65:** Migrated from RustCrypto `ml-dsa 0.1` to `libcrux-ml-dsa 0.0.9`
  (hax/F* formally verified, constant-time, NIST ACVP validated byte-perfect)
- **SHAKE256:** Migrated from RustCrypto `sha3 0.10` to `libcrux-sha3 0.0.9`
  (hax/F* formally verified, constant-time, no T-tables)
- RustCrypto `ml-kem`, `ml-dsa`, `sha3` removed from Cargo.toml
- T-table cache-timing side channel: **RESOLVED** at base level

### Added (v0.2.0 development)

- **NIST ACVP official test vector validation** (`tests/nist_acvp.rs`)
  - 6 tests against official NIST ACVP vectors sourced from BoringSSL
    (Google) → `usnistgov/ACVP-Server`.
  - **ML-DSA-65 KeyGen #1**: seed → public key — **byte-perfect match**
    with NIST expected output.
  - **ML-KEM-768 KeyGen #1**: seed → encapsulation key — **byte-perfect
    match** with NIST expected output.
  - Additional tests: determinism, size validation, cross-vector checks,
    sign/verify and KEM roundtrip with NIST-derived keys.
  - Raw test vector files stored in `tests/vectors/` for auditor evidence.

- **CAVP-style internal validation** (`tests/cavp.rs`)
  - 14 tests: ML-KEM-768 keygen (zero/ones seeds), encaps/decaps roundtrip,
    wrong-key implicit rejection, public key validation.
  - ML-DSA-65 keygen determinism, sign/verify roundtrip (5 message/context
    cases), wrong message/context/key rejection, tampered signature (6 byte
    positions), different randomness produces different signatures.
  - Cross-validation: key avalanche property, shared secret non-triviality.

- **Thread-safety stress tests** (`tests/race_conditions.rs`)
  - 23 tests: concurrent entropy harvesting (8 threads, 160 seeds all unique),
    concurrent full pipeline (8+16 threads), batch verification, ORAM
    read/write/read_modify_write/swap, MicroVM deterministic execution
    (400 runs all identical), Shamir split/reconstruct, blind attestation,
    commit-reveal, threshold, hybrid, chain operations, keccak_ct.
  - Mixed workload: 16 threads running all modules simultaneously.
  - Timing variance analysis: Shamir 1.01x ratio (constant-time confirmed),
    verify_once 1.17x ratio (acceptable).
  - State leak detection: 20 sequential transcripts all unique.

- **Miri memory safety CI** (`.github/workflows/rust.yml`)
  - Miri job runs 13 module-specific test suites under nightly Rust.
  - `-Zmiri-disable-isolation` for getrandom/OS entropy calls.
  - `l0_memlock`: `#[cfg(miri)]` guard skips `mlock` syscall under Miri.
  - Scoped to non-libcrux modules (libcrux uses cpuid inline assembly
    unsupported by Miri): common, chain, shamir, keccak_ct, storage,
    execution, relations (hash_preimage, pedersen, range_proof, merkle),
    layers (l0_memlock, l6_zeroise), entropy_sources.

- **Supply chain security infrastructure**
  - `.github/dependabot.yml` — weekly dependency monitoring with ignore rules
    for sha3 and getrandom major versions (conflict with libcrux).
  - `scripts/generate-sbom.sh` — CycloneDX SBOM generator (61 dependencies).
  - SBOM generation job added to CI (`hardening.yml`).
  - Labels created: `dependencies`, `rust`, `ci`.
  - Dependabot PRs managed: #3 (checkout v4→v6), #4 (upload-artifact v4→v7),
    #5 (rust-minor-patch) merged; #6 (getrandom 0.2→0.4), #7 (sha3 0.10→0.11)
    closed as breaking changes.

- **Range proof relation** (`src/relations/range_proof.rs`)
  - New `Relation` implementation: proves value ∈ [min, max] without
    revealing the value.
  - Bit-decomposition + per-bit SHAKE256 commitments.
  - Constant-time nonce corruption for out-of-range invalidation.
  - Fifth built-in relation. 8 unit tests.

- **Expanded interface module** (`src/interface.rs`) — 18 one-call functions:
  - `attest_structured` — attestation with personalization binding.
  - `attest_with_vm`, `attest_with_oram` — pipeline variant wrappers.
  - `attest_batch`, `attest_batch_texts` — batch attestation.
  - `attest_chain_files`, `attest_directory`, `attest_file_merkle` — chain/directory.
  - `prove_hash_preimage`, `prove_pedersen`, `prove_merkle` — relation proofs.
  - `check_chain`, `check_merkle` — pure-math verification oracles.
  - 20 integration tests.

- **libcrux PQ backend** (`src/pq_backends/libcrux_backend.rs`)
  - Adapter wrapping libcrux-ml-kem 0.0.9 and libcrux-ml-dsa 0.0.9.
  - Replaces RustCrypto ml-kem/ml-dsa in L2/L3/L4/L5 layers.
  - NIST ACVP validated: byte-perfect match with official test vectors.
  - 11 unit tests.

- **Constant-time masked SHAKE256** (`src/keccak_ct.rs`)
  - Masked sponge approach: XOR input with random mask before SHAKE256.
  - T-table access patterns leak masked data, not original secrets.
  - Phase 2 mitigation for cache-timing side channel.
  - 6 unit tests.

- **Shamir secret sharing** (`src/shamir.rs`)
  - Constant-time GF(2⁸) multiplication and inversion.
  - T-of-N secret splitting for entropy.
  - 8 unit tests.

- **Threshold verification** (`src/threshold.rs`)
  - N-of-M distributed verification with Choice accumulation.
  - 7 unit tests.

- **Commit-reveal protocol** (`src/commit_reveal.rs`)
  - Two-phase attestation: commit_phase() → reveal_phase().
  - 5 unit tests.

- **Blind attestation** (`src/blind.rs`)
  - Engine attests data it never sees (XOR blinding).
  - 6 unit tests.

- **Hybrid PQ+classical attestation** (`src/hybrid.rs`)
  - Dual-layer: ML-DSA-65 + SHAKE256 MAC.
  - 3 unit tests.

- **MicroVM proper opcode execution** (`src/execution/vm.rs`)
  - Complete rewrite of the execution engine from a byte-XOR stub to a
    real 17-opcode stack machine with a 128×u64 operand stack.
  - **12 new opcodes**: `Push` (immediate u64), `Pop`, `Dup`, `Swap`,
    `And`, `Or`, `Not`, `Shl`, `Shr`, `Rot`, `Eq`, `Lt`. All opcodes
    are fully interpreted — the VM actually executes them as a stack
    machine, not just XOR bytes into a buffer.
  - `BytecodeBuilder` ergonomic API for constructing bytecode from
    chained method calls (`.push(10).push(20).add().build()`).
  - Execution trace absorbed into SHAKE256 for deterministic root
    derivation: same bytecode → same 64-byte root.
  - All existing safety properties preserved: canary protection,
    fail-closed on stack overflow/underflow/invalid opcode, auto-zeroise
    on drop, max 4096 bytes of bytecode.
  - 22 new unit tests (arithmetic, bitwise, comparison, stack ops,
    overflow, truncation, determinism, zeroize verification).

- **Pedersen commitment relation** (`src/relations/pedersen.rs`)
  - New `Relation` implementation: proves knowledge of `(value, blinding)`
    such that `C = SHAKE256(PEDERSEN_OPEN ‖ value ‖ blinding)`.
  - Fourth built-in relation alongside `hash_preimage`, `ml_dsa`, and
    `merkle` — demonstrates a two-part witness structure distinct from
    the existing three.
  - Proof contains the full opening (value + blinding); in veil7's
    stateless model the proof never leaves the engine. Opening is wiped
    at the L6 barrier.
  - 8 new unit tests (honest verify, wrong value, wrong blinding,
    wrong statement, deterministic proof, different witnesses,
    manual compute match, protocol label uniqueness).
  - New domain tag `PEDERSEN_OPEN` in `common::domain`.

- **Batch verification** (`src/pipeline.rs`)
  - `verify_batch(claims: &[Claim]) -> Result<Verdict, VeilError>`
    processes N claims in independent iterations, each with its own
    ephemeral identity (fresh entropy, fresh keypair, full L1→L7).
  - Validity bits AND-combined via `subtle::Choice`.
  - Transcripts folded through domain-separated SHAKE256 accumulator
    (`BATCH_HEAD` + `BATCH_STEP` per verdict) into a single 32-byte
    batch transcript.
  - `Verdict::from_batch` constructor in `l7_emit` (std-gated).
  - Empty input returns `VeilError::Crypto` (fail-closed).
  - New domain tags `BATCH_HEAD` / `BATCH_STEP` in `common::domain`.

- **ORAM extensions** (`src/storage/oram.rs`)
  - `read_modify_write(addr, f)` — Atomic oblivious read-modify-write.
    Reads the hashed value at `addr`, applies `f`, re-hashes and writes
    back — all in a single constant-time pass touching every slot.
    Returns the post-modification value.
  - `swap(addr_a, addr_b)` — Oblivious swap of two slots. Reads both
    values, writes back swapped — single constant-time pass. Self-swap
    is identity.
  - Both operations maintain uniform bus traffic (padding touched on
    every slot) and wipe intermediates on completion.
  - 6 new unit tests (RMW applies function, RMW on empty slot, RMW
    isolation, swap exchanges values, swap self is noop, swap isolation).

- **Expanded interface** (`src/interface.rs`) — 12 new one-call functions:
  - `attest_structured(label, payload)` — attestation with personalization
    binding (label influences ephemeral identity, not emitted).
  - `attest_with_vm(bytes)` — attest via MicroVM-bound pipeline.
  - `attest_with_oram(bytes)` — attest via ORAM-bound pipeline.
  - `attest_batch(items)` — batch attest multiple byte slices.
  - `attest_batch_texts(texts)` — batch attest multiple strings.
  - `attest_chain_files(paths)` — chain-attest multiple files via
    streaming (file paths absorbed as domain separators).
  - `attest_directory(dir)` — chain-attest all non-hidden files in a
    directory (sorted lexicographically).
  - `attest_file_merkle(paths)` — Merkle-tree attestation of multiple
    file hashes (supports inclusion proofs).
  - `prove_hash_preimage(seed)` — one-call Lamport hash preimage proof.
  - `prove_pedersen(value, blinding)` — one-call Pedersen commitment
    opening proof.
  - `prove_merkle(leaves, index)` — one-call Merkle inclusion proof.
  - `check_chain(events, root)` — pure-math chain integrity oracle.
  - `check_merkle(leaf, root, index, siblings, leaf_count)` — pure-math
    Merkle inclusion oracle.
  - 20 new unit tests for the interface module.

- **CLI additions** (`src/main.rs`)
  - `veil7 vm-execute <hex_bytecode>` — execute VM bytecode, output
    deterministic 64-byte root.
  - `veil7 batch-sign <text1> <text2>..` — batch attest multiple claims,
    output aggregated Verdict with count.
  - `veil7 prove pedersen <hex_value> <hex_blinding>` — Pedersen
    commitment opening proof.
  - `hex64()` helper for 64-byte (128-char) hex encoding.
  - Updated help text with all new subcommands.

### Changed

- **Test count**: 165 → **222** (+57 tests: 22 VM, 8 Pedersen, 6 ORAM,
  20 interface, 1 doc test).
- **Line count**: ~6 508 → **~8 216** (+1 708 lines of Rust).
- **Release binary**: ~454 KB → **~480 KB**.
- **Relations**: 3 → **4** (added `pedersen`).
- **CLI subcommands**: 8 → **12**.
- **Interface functions**: 6 → **18**.
- **MicroVM opcodes**: 5 (uninterpreted) → **17** (fully interpreted).
- **ORAM operations**: 2 (read/write) → **4** (+ read_modify_write, swap).

### Documented

- `README.md` — updated status (222 tests, ~8200 lines, ~480KB binary),
  added MicroVM opcode table, batch verification section, expanded
  interface table, ORAM extensions, CLI reference (12 commands),
  updated layout and demo pipelines sections.
- `CLAUDE.md` — updated architecture diagram (interface, chain,
  entropy_sources, pedersen, ORAM extensions, 17-opcode VM), updated
  relations list (4 working relations).
- `USE_CASES.md` — added 3 new use cases: Batch Attestation (§8),
  Directory Integrity Anchor (§9), Pedersen Commitment (§10).
  Updated Quick Reference table (10 use cases).
- `CHANGELOG.md` — this entry.

---

### Documented (Phase 1 cache timing)

- **Cache timing / T-table threat model for SHAKE256** (`SPEC-HARDENING.md`,
  `CLAUDE.md`, all 12 SHAKE256 call sites)
  - The `sha3` 0.10 crate (RustCrypto) is a **T-table Keccak** implementation.
    Per-call lookup-table access patterns can leak the absorbed secret on
    shared-cache hardware (Flush+Reload / Prime+Probe against co-resident
    VMs or same-core L3). The same caveat applies to all RustCrypto PQ
    crates (`ml-kem`, `ml-dsa`, `slh-dsa`) which use the same `sha3` crate
    internally.
  - New `SPEC-HARDENING.md` §"Cache timing and T-table side channels"
    documents the threat, lists every veil7-owned SHAKE256 call site
    (12 files, 18 sites) with the secret class that flows in and the
    per-deployment risk (LOW on single-tenant mobile / laptop, MEDIUM–HIGH
    on shared-CPU cloud, HIGH on multi-tenant bare-metal), explains the
    Phase 1 stance (documented accepted gap), and budgets a Phase 2
    `dudect`/`ctverif` validation sprint.
  - Per-site `// SIDE-CHANNEL:` comments added at every `let mut xof = Shake256::default();`
    call site in veil7-owned code, each tagged with risk class:
    - HIGH: `entropy_sources::whiten`, `l1_entropy` (4 sites), `l2_keygen::derive`
      (master seed → PQ KDF), `relations/hash_preimage::h32` (Lamport secret
      leaves), `storage/oram::oram_hash` (slot contents).
    - MEDIUM: `l3_commit::commit` (private claim bytes), `vm::vm_root`
      (execution trace — LOW unless future caller feeds private input).
    - LOW: `chain::{chain_root, ChainState::new}`, `l7_emit` (2 sites),
      `transcript::{new, absorb, challenge}`, `merkle::h32`,
      `relations/hash_preimage::pk_commitment`,
      `l5_verify::kem_roundtrip` and the test-side SHAKE256 site.
  - `CLAUDE.md` adds a "Side-channel threat model" section as a
    documented assumption, paralleling the philosophy section.
  - No source code changes. No test changes. Test count remains 165.

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

- **L2-L7 test coverage expansion (+12 tests, in existing modules)**
  - L2 (keygen): +3 — `different_seeds_produce_different_keys`,
    `kem_and_sig_subseeds_are_domain_separated` (KEM_SEED vs SIG_SEED
    tag independence, verified via the 16-byte prefix collision
    probability of 2^-128), `derive_keys_does_not_leak_master_seed_via_subseeds`
    (no 64-byte window of the master seed appears anywhere in the
    1184-byte KEM ek or 1952-byte ML-DSA vk)
  - L3 (commit): +3 — `commitment_changes_when_kem_ek_changes`,
    `commitment_changes_when_sig_vk_changes`,
    `commitment_binds_all_three_fields` (pairwise distinct 3-tuples
    prove no field is silently dropped from the absorb)
  - L4 (prove): +3 — `proof_changes_when_commitment_changes` (binds
    signature to commitment), `proof_binds_to_sig_ctx_domain_separator`
    (regression guard against future removal of the ML-DSA ctx
    field), `proof_sig_encode_is_stable_byte_layout` (pins
    ML-DSA-65 wire format at 3309 bytes)
  - L5 (verify): +2 — `verify_accumulates_constant_time_even_with_signature_failure`
    (the no-early-exit property of the sig_ok & kem_ok accumulator,
    tested semantically by varying the claim while the signature
    is fixed-tampered), `kem_roundtrip_legitimate_path_produces_matching_secrets`
    (encapsulate_deterministic -> decapsulate -> ct_eq == 1)
  - L6 (zeroise): +1 — `scrub_runs_drop_inline_never` (type-level
    assertion `let _: () = scrub(keys);` pins the no-return unit
    contract; the `#[inline(never)]` attribute is the documented
    barrier contract)
  - All in existing `mod tests` submodules of L2-L6. No new files,
    no architectural changes. Total test count 153 -> 165.

- **Side-channel hardening pass (4 patches from 2025-26 side-channel
  audit against CVE-2026-23519, KyberSlash, ML-DSA rejection sampling,
  Keccak table-lookup cache, and compiler reordering)**
  - **Patch 1: `compiler_fence(SeqCst)` around every `Choice`
    construction.** `subtle::Choice` is documented as "best-effort"
    (CVE-2026-23519 just showed LLVM may still optimize constant-time
    logic into branches on certain archs). We add a SeqCst
    compiler fence before and after every `Choice::from(...)` and
    around the `&` accumulator in:
    * `src/layers/l5_verify.rs` (the `sig_ok & kem_ok` accumulator)
    * `src/layers/l7_emit.rs` (both `Verdict::new` and
      `Verdict::from_statement_digest`)
    * `src/relations/hash_preimage.rs::verify` (early-return and
      accumulator)
    * `src/relations/merkle.rs::verify` (early-return, accumulator,
      final result)
    * `src/relations/ml_dsa.rs::verify` (`Choice::from(ok as u8)`)
    SeqCst fences are global compiler barriers that no optimizer
    is allowed to reorder across, so the Choice construction
    cannot be folded into a branch on the underlying bool.
  - **Patch 2: explicit `core::mem::drop(seed)` after L2 in
    `verify_once_with_seed` and after `R::prove` in
    `prove_and_verify_with_entropy`.** The signature of both
    functions changed from `&Seed` to `Seed` (consume by value).
    After L2 the master seed is no longer needed: the ephemeral
    keypair is the only secret flowing through L3..L7. The
    explicit drop minimizes the seed's live range and gives the
    wipe the earliest possible insertion point. Side-channel
    hardening against any future code change that might extend
    the seed's lifetime past L2 by accident. Affects all callers
    (`verify_once`, `verify_once_with`, `verify_once_with_oram`,
    `verify_once_with_vm`, `prove_and_verify`, plus the
    integration tests in `tests/adversarial.rs` and
    `tests/fuzz_manual.rs`).
  - **Patch 3: SHAKE256 domain separation in `entropy_sources::hw_counter`.**
    The previous `elapsed_nanos ^ wall_nanos` was a raw XOR with
    three problems: (1) XOR is reversible in one direction (an
    attacker who knows one input recovers the other); (2) the
    buffer was 16 bytes of hash + 48 bytes of zero padding (a
    trivially recognizable pattern); (3) a one-way digest gives
    stronger side-channel resistance for the per-method
    whitening downstream. The new code uses
    `SHAKE256("veil7:L1:src:hw-counter-combine:v1" ||
    elapsed || wall)` to fill the full 64-byte buffer with
    one-way-mixed output.
  - **Patch 4: pre-loop `compiler_fence(SeqCst)` in
    `l0_memlock::zeroize_bytes` and `zeroize_u64`.** The previous
    pattern only had a post-loop fence. The pre-loop fence
    ensures that no loads from the secret bytes (or any
    related memory) are reordered to *after* the wipe begins.
    Without it, LLVM could in principle keep an outstanding load
    from a secret byte above the volatile-write loop (volatile
    writes are per-location barriers, not global ones). The
    pre-loop fence makes the wipe an unconditional
    happens-before-deletion point. Combined with the post-loop
    fence (already in place): secret bytes are guaranteed to be
    loaded-then-wiped, and the wipe is guaranteed to
    complete-then-leave-scope. This is the pattern recommended
    by Trail of Bits' "Life of an Optimization Barrier" (2022).
  - All patches are empirical side-channel hardening grounded
    in the 2025-26 academic literature. They do not guarantee
    constant-time (that depends on the underlying hardware and
    the LLVM backend), but they raise the bar by:
    (1) preventing the optimizer from folding our CT logic
        into branches,
    (2) minimizing secret material's live range, and
    (3) preventing secret loads from being hoisted past
        the wipe.
  - 0 new tests added (the existing 165 tests still pass —
    these are hardening fixes, not behavior changes). Mutation
    test from earlier session still passes (or `addr % 256`
    reintroduced would be caught by hardening scan).

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
