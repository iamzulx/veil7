# Use Cases — veil7

This document explains *who* uses veil7 and *how* it is used in real-world
scenarios. Each use case includes: input, API used, and output produced.

---

## 1. Device Boot Attestation (IoT / Embedded)

**Who:** IoT device vendors, secure bootloaders, TEE firmware.

**Problem:** A device must prove to a server/cloud that it booted in a trusted
state — without storing a long-lived key pair in flash.

**veil7 solution:**
- On every boot, the bootloader produces a `Claim` from the stage-2 hash / PCR
  measurement.
- Run `verify_once(&claim)` — the engine builds an ephemeral post-quantum
  identity, signs the measurement, then wipes all key material.
- The server receives the `Verdict` (valid=1 + transcript hash) and correlates
  it with the measurement it holds out-of-band.

**Input:**
```rust
let measurement: &[u8] = /* SHA-256 hash of firmware stage-2 */;
let claim = Claim::new(measurement);
```

**API:**
```rust
let verdict = verify_once(&claim)?;
assert!(verdict.is_valid_bool());
```

**Output:**
- `valid=1` + `transcript=[32 bytes]` that can be correlated to the server's
  measurement.

**Why veil7:** Stateless — no persistent key in flash to extract.
Auto-zeroise — secrets live for only one boot iteration. Post-quantum — ML-KEM +
ML-DSA withstand quantum computers.

---

## 2. Anonymous Document Signing

**Who:** Whistleblowers, transparency agencies, digital notaries.

**Problem:** Sign a document without leaving a permanent identity, timestamp, or
metadata that could trace back to the signer.

**veil7 solution:**
- Convert the document into a `Claim` (raw bytes).
- `verify_once(&claim)` produces a `Verdict` — only a validity bit + transcript.
- No field for name, email, key ID, or timestamp.
- The recipient can correlate the `transcript` with the document hash stored
  separately, without knowing the signer's identity.

**Input:**
```bash
# CLI
cargo run --release -- sign-file ./secret_report.pdf
```

**Or via library:**
```rust
let verdict = veil7::interface::attest_file("./secret_report.pdf")?;
```

**Output:**
```
valid=1 transcript=a3f81c...e7b2
```

**Why veil7:** No metadata — `Verdict` contains no signer ID, time, or any
information other than a validity bit + correlation hash. Stateless — each
document is signed by a fresh identity, so there is no linkability between
signatures.

---

## 3. Universal Proof of Knowledge

**Who:** Cryptography researchers, zero-knowledge auditors, voting systems.

**Problem:** Prove knowledge of a secret without revealing it, using an engine
that can be plugged into *any* relation.

**veil7 solution:**
- Define a relation by implementing the `Relation` trait.
- Built-in examples: `HashPreimage` — proves knowledge of a hash preimage.
- Users can create new relations (e.g. proof of age, set membership) without
  changing the engine.

**Input:**
```rust
use veil7::relations::hash_preimage::{HashPreimage, Witness};

let witness = Witness { seed: [0xABu8; 32] };
```

**API:**
```rust
let verdict = prove_and_verify::<HashPreimage>(&witness, b"")?;
assert!(verdict.is_valid_bool());
```

**Output:**
- `Verdict` with `valid=1` if the prover truly knows the witness.
- Transcript hash identical for the same statement (independent of entropy).

**Why veil7:** Pluggable — swap `HashPreimage` with your own relation, the
verification pipeline does not change. Fiat-Shamir — non-interactive proof, can
be verified offline.

---

## 4. Side-Channel Resistant Key Storage (ORAM)

**Who:** Secure enclaves, software HSMs, crypto wallets.

**Problem:** An attacker with memory bus access can see *which slot* contains a
seed or secret key (timing side-channel).

**veil7 solution:**
- Use `verify_once_with_oram(&claim)`.
- The seed is stored in `ObliviousRAM` before keygen — every slot is touched
  with identical traffic; the attacker cannot distinguish the target slot.
- ORAM uses mask-based updates without branches on every byte.

**Input:**
```rust
let claim = Claim::new(b"wallet-op-42");
```

**API:**
```rust
let verdict = verify_once_with_oram(&claim)?;
```

**Output:**
- `Verdict` as usual, with an extra guarantee: the memory access pattern does
  not reveal where the seed lives.

**Why veil7:** ORAM is pure-Rust, constant-time read/write. No special hardware
required — runs on a general-purpose CPU.

---

## 5. Embedded Secure Enclave (no_std)

**Who:** ARM Cortex-M firmware, bare-metal embedded, aerospace.

**Problem:** No OS, no complex allocator, can't use `std` — but still need
post-quantum attestation.

**veil7 solution:**
- Build with `--no-default-features` (`#![no_std]`).
- Supply seed from a TRNG or hardware entropy source.
- Use `verify_once_with_seed` — does not call the OS CSPRNG.
- Binary ~454 KB stripped, pure Rust, zero C dependency.

**Input:**
```rust
// no_std environment
let raw_entropy: [u8; 64] = trng_harvest(); // from your hardware TRNG
let seed = Seed::from_bytes(&raw_entropy);
let claim = Claim::new(b"sensor-data-packet");
```

**API:**
```rust
let verdict = verify_once_with_seed::<MlDsaProver, MlDsaVerifier>(&seed, &claim)?;
```

**Output:**
- `Verdict` (valid + transcript) sent via UART/SPI to the host.

**Why veil7:** `#![no_std]` compatible — no `std`, `getrandom`, or filesystem.
Pure Rust — no C toolchain to cross-compile. Small footprint — small enough for
limited flash.

---

## 6. CI/CD Artifact Attestation

**Who:** DevOps, supply-chain security, package registries (crate/npm).

**Problem:** The build server needs to sign an artifact (binary, container
image) so downstream users can verify integrity — but a persistent signing key
must not live on the build server (theft risk).

**veil7 solution:**
- After the build finishes, run `veil7 sign-file ./artifact.tar.gz`.
- An ephemeral key is generated from OS entropy, signs the artifact, then is
  zeroised before the build process ends.
- No key file on disk. No secret in environment variables.

**Input:**
```bash
cargo run --release -- sign-file ./artifact.tar.gz
```

**API (via script):**
```rust
let verdict = veil7::interface::attest_file("./artifact.tar.gz")?;
println!("artifact_hash={} transcript={:?}", sha256_file("./artifact.tar.gz"), verdict.transcript());
```

**Output:**
```
valid=1 transcript=9c4b...e2f1
```

**Why veil7:** No key management — no `GITHUB_TOKEN_SIGNING_KEY` or cloud HSM
required. Stateless — each build has a unique identity, so compromising one
build does not affect another. Auto-zeroise — secrets do not linger in RAM/swap
after the process finishes.

---

## 7. Tamper-Evident Log Append

**Who:** Security Operations Centers (SOC), forensic auditors, off-chain
blockchain logging.

**Problem:** Every log entry must be attestable so an attacker who modifies log
history is detected — without storing a private key on the log server.

**veil7 solution:**
- For each log event, create a `Claim` from the hash(event + previous_transcript).
- Run `verify_once(&claim)`, store the output `transcript` alongside the log entry.
- If a log entry is altered, the transcript will not match.

**Input:**
```rust
let event = b"user=admin,action=delete,file=backup";
let claim = Claim::new(event);
```

**API:**
```rust
let verdict = verify_once(&claim)?;
log_store.append(event, verdict.transcript());
```

**Output:**
- `transcript=[32 bytes]` stored as a cryptographic anchor for each entry.

**Why veil7:** No persistent signing key that can be stolen from the log server.
Each entry is implicitly chained through the claim that includes the previous
entry's hash. Transcript contains no sensitive data — it is public and safe to
store in a plaintext log.

---

## 8. Batch Attestation (Multi-Claim)

**Who:** Microservices, API gateways, batch processors.

**Problem:** Multiple independent claims need attestation in a single
operation, producing one aggregated verdict for downstream consumers.

**veil7 solution:**
- Use `attest_batch` or `verify_batch` to process N claims.
- Each claim gets its own ephemeral identity (stateless).
- The batch verdict AND-combines all validity bits and folds transcripts
  into a single SHAKE256 digest.

**Input:**
```rust
let items: &[&[u8]] = &[b"event-A", b"event-B", b"event-C"];
```

**API:**
```rust
let verdict = veil7::interface::attest_batch(items)?;
assert!(verdict.is_valid_bool()); // all valid → batch valid
```

**Output:**
```
valid=1 transcript=5d1685...067c count=3
```

**Why veil7:** Stateless — each claim is independent. No shared key or
session between claims. Aggregated output — one verdict covers all.

---

## 9. Directory Integrity Anchor

**Who:** Configuration management, compliance auditors, deployment verification.

**Problem:** A directory of configuration files needs a single integrity
anchor that detects any modification, addition, or deletion.

**veil7 solution:**
- `attest_directory` reads all non-hidden files, sorts by name, and
  chain-attests them via streaming.
- The single `Verdict` covers the entire directory state.

**Input:**
```bash
veil7 chain-root $(ls /etc/myapp/config/*)
```

**API:**
```rust
let verdict = veil7::interface::attest_directory("/etc/myapp/config")?;
```

**Why veil7:** One-call directory attestation. Sorted file order is
cryptographically bound. Streaming — handles large files without
loading everything into RAM.

---

## 10. Pedersen Commitment (Blinded Value Proof)

**Who:** Voting systems, sealed-bid auctions, privacy-preserving protocols.

**Problem:** Prove knowledge of a committed value without revealing the
value itself — the commitment uses a blinding factor for hiding.

**veil7 solution:**
- `prove_pedersen(value, blinding)` proves knowledge of the opening
  `(value, blinding)` such that `C = SHAKE256(PEDERSEN_OPEN ‖ value ‖ blinding)`.
- The proof is verified within the engine; only the `Verdict` is emitted.

**Input:**
```rust
let value: [u8; 32] = /* secret bid amount */;
let blinding: [u8; 32] = /* random blinding factor */;
```

**API:**
```rust
let verdict = veil7::interface::prove_pedersen(value, blinding)?;
assert!(verdict.is_valid_bool());
```

**Or via CLI:**
```sh
veil7 prove pedersen <hex_value> <hex_blinding>
```

**Why veil7:** The commitment opening never leaves the engine. Stateless
— each proof uses a fresh ephemeral identity. Post-quantum sound — rests
on SHAKE256 preimage resistance.

---

## Quick Reference — API per Use Case

| Use Case | Primary API | Entry Point |
|----------|-------------|-------------|
| Boot Attestation | `verify_once` or `verify_once_with_seed` (no_std) | `Claim::new(measurement)` |
| Document Signing | `interface::attest_file` / `sign-file` CLI | File path or byte slice |
| Proof of Knowledge | `prove_and_verify::<R>` | Witness + relation type |
| ORAM Key Storage | `verify_once_with_oram` | `Claim` + ORAM write/read |
| Embedded (no_std) | `verify_once_with_seed` | `Seed::from_bytes` + `Claim` |
| CI/CD Attestation | `interface::attest_file` / `sign-file` CLI | Artifact file |
| Tamper-Evident Log | `verify_once` + store transcript | Log entry bytes |
| Batch Attestation | `interface::attest_batch` / `batch-sign` CLI | Byte slices |
| Directory Integrity | `interface::attest_directory` | Directory path |
| Pedersen Commitment | `interface::prove_pedersen` / `prove pedersen` CLI | value + blinding |

---

## Note

All of the above use cases produce the **same simple output**:
- `valid=1` (or `valid=0` on failure)
- `transcript=[64-char hex]`

No JSON, no XML, no nested structure. This is intentional — output simplicity
is part of the `NO METADATA` philosophy.
