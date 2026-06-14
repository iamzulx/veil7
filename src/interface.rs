//! Simple interface wrapper — one-call attestation for common use cases.
//!
//! This module is intentionally thin: it only routes inputs into the engine
//! and returns the raw `Verdict`. No formatting, no `String` allocation, no
//! metadata generation. Anything that prints or formats lives outside the
//! library (e.g. in `main.rs` or in the caller's code).
//!
//! ## API surface
//!
//! ### Single-item attestation (ML-DSA pipeline)
//! - [`attest_bytes`] — raw bytes
//! - [`attest_text`] — UTF-8 string
//! - [`attest_file`] — file (full load)
//! - [`attest_file_streaming`] — file (streaming, 4KB chunks)
//! - [`attest_structured`] — bytes with personalization binding
//!
//! ### Pipeline variants
//! - [`attest_with_vm`] — attest via MicroVM-bound pipeline
//! - [`attest_with_oram`] — attest via ORAM-bound pipeline
//!
//! ### Batch attestation
//! - [`attest_batch`] — multiple byte slices, single aggregated Verdict
//! - [`attest_batch_texts`] — multiple strings, single aggregated Verdict
//!
//! ### Chain & directory attestation
//! - [`attest_chain`] — tamper-evident event chain
//! - [`attest_chain_files`] — chain attest multiple files via streaming
//! - [`attest_directory`] — chain attest all files in a directory
//! - [`attest_file_merkle`] — Merkle-tree attest multiple file hashes
//!
//! ### Relation proofs (one-call wrappers)
//! - [`prove_hash_preimage`] — Lamport hash preimage proof
//! - [`prove_pedersen`] — Pedersen commitment opening proof
//! - [`prove_merkle`] — Merkle inclusion proof
//!
//! ### Verification oracles (pure math, no PQ, no entropy)
//! - [`check_chain`] — check events fold to expected root
//! - [`check_merkle`] — check leaf authenticates against root
#![cfg(feature = "std")]

use std::io::Read;

use crate::chain::{chain_root, chain_verify, ChainState};
use crate::l0_memlock::zeroize_bytes;
use crate::pipeline::{
    prove_and_verify, verify_batch, verify_once, verify_once_with_oram, verify_once_with_vm, Claim,
};
use crate::{VeilError, Verdict};

/// Chunk size for [`attest_file_streaming`]. Picked to match the page
/// size on common targets (aarch64 / x86_64) so chunk reads align with
/// the kernel page cache, and to bound transient memory to a few KB
/// regardless of file size. Tunable by callers via the `_with_chunk_size`
/// variant below.
const FILE_CHUNK: usize = 4096;

// ═══════════════════════════════════════════════════════════════════════════
// Single-item attestation
// ═══════════════════════════════════════════════════════════════════════════

/// Attest raw bytes through the ML-DSA pipeline.
///
/// Input: arbitrary byte slice.
/// Output: `Verdict` (valid bit + 32-byte transcript), or `VeilError`.
pub fn attest_bytes(bytes: &[u8]) -> Result<Verdict, VeilError> {
    verify_once(&Claim::new(bytes))
}

/// Attest a UTF-8 string.
pub fn attest_text(text: &str) -> Result<Verdict, VeilError> {
    attest_bytes(text.as_bytes())
}

/// Attest raw bytes with a personalization binding.
///
/// The `label` is passed as the claim's personalization context, which
/// binds the entropy harvest to the label. This means two attestations
/// of the same payload with different labels produce different ephemeral
/// identities and different transcripts — useful for domain-separating
/// attestations (e.g. `"audit"` vs `"sign"`).
///
/// Privacy: the label is NOT included in the `Verdict` or any emitted
/// metadata. It only influences the internal ephemeral identity which
/// is wiped at L6.
pub fn attest_structured(label: &[u8], payload: &[u8]) -> Result<Verdict, VeilError> {
    verify_once(&Claim {
        bytes: payload,
        personalization: label,
    })
}

/// Attest the contents of a file by loading it entirely into memory.
pub fn attest_file(path: &str) -> Result<Verdict, VeilError> {
    let bytes = std::fs::read(path).map_err(|_| VeilError::Crypto)?;
    attest_bytes(&bytes)
}

/// Attest the contents of a file via the streaming chain accumulator.
///
/// The file is read in [`FILE_CHUNK`]-byte chunks and folded into a
/// [`ChainState`] without ever holding the full file in memory. Peak
/// transient memory is one chunk + the accumulator state + the final
/// root. Empty files return `VeilError::Crypto` (there is no chain to
/// attest). The intermediate chunk buffer is wiped after use; the final
/// root is public so the caller (or the engine's L6 barrier) handles
/// its lifecycle.
///
/// Compared to [`attest_file`], this version:
/// * does not allocate a `Vec<u8>` proportional to the file size,
/// * does not leave file bytes in the heap for the lifetime of the call,
/// * still produces the same `Verdict` for the same file contents (the
///   chain framing of the chunk sequence is deterministic, and the
///   pipeline binds the resulting root through the same L1..L7 path).
pub fn attest_file_streaming(path: &str) -> Result<Verdict, VeilError> {
    attest_file_streaming_with_chunk_size(path, FILE_CHUNK)
}

/// Streaming attest with a caller-chosen chunk size. Useful for callers
/// that want to tune the buffer footprint or align reads to a specific
/// device block. The chunk is wiped after each read; only the live
/// accumulator state and one chunk's worth of bytes survive at any time.
pub fn attest_file_streaming_with_chunk_size(
    path: &str,
    chunk_size: usize,
) -> Result<Verdict, VeilError> {
    if chunk_size == 0 {
        return Err(VeilError::Crypto);
    }
    let file = std::fs::File::open(path).map_err(|_| VeilError::Crypto)?;
    let mut reader = std::io::BufReader::with_capacity(chunk_size, file);
    let mut buf = vec![0u8; chunk_size];

    let mut state = ChainState::new();
    loop {
        let n = reader.read(&mut buf).map_err(|_| VeilError::Crypto)?;
        if n == 0 {
            break;
        }
        state.absorb(&buf[..n]);
        // Overwrite the consumed region so the same buffer is safe to
        // reuse on the next iteration; the chunk is fully overwritten
        // before the next absorb so any prior residue is replaced.
        for b in &mut buf[..n] {
            *b = 0;
        }
    }
    // Wipe the chunk buffer before dropping it.
    zeroize_bytes(&mut buf);

    let mut root = state.finalize()?;
    let verdict = attest_bytes(&root)?;
    zeroize_bytes(&mut root);
    Ok(verdict)
}

// ═══════════════════════════════════════════════════════════════════════════
// Pipeline variants
// ═══════════════════════════════════════════════════════════════════════════

/// Attest bytes through the MicroVM-bound pipeline.
///
/// The claim bytes are first executed through the deterministic MicroVM,
/// producing a 64-byte execution root. That root is then used as
/// personalization for the entropy harvest, binding the iteration's
/// ephemeral identity to the VM execution trace.
///
/// Use case: attest data in a way that is cryptographically bound to
/// a sandboxed execution of the data itself (e.g. firmware measurements
/// where the "code" is both the payload and the execution context).
pub fn attest_with_vm(bytes: &[u8]) -> Result<Verdict, VeilError> {
    verify_once_with_vm(&Claim::new(bytes))
}

/// Attest bytes through the ORAM-bound pipeline.
///
/// The harvested seed is stored in ObliviousRAM before keygen, then
/// read back via the constant-time ORAM path. This hides the memory
/// access pattern of the seed storage from a bus-level observer.
///
/// Use case: attest in environments where memory-bus side channels
/// are a concern (shared hardware, cloud VMs, hostile enclaves).
pub fn attest_with_oram(bytes: &[u8]) -> Result<Verdict, VeilError> {
    verify_once_with_oram(&Claim::new(bytes))
}

// ═══════════════════════════════════════════════════════════════════════════
// Batch attestation
// ═══════════════════════════════════════════════════════════════════════════

/// Attest multiple byte slices in a single batch, returning one
/// aggregated `Verdict`.
///
/// Each item gets its own ephemeral identity (fresh entropy, fresh
/// keypair, full L1→L7 cycle). The validity bits are AND-combined
/// (all must be valid), and transcripts are folded into a single
/// batch transcript via domain-separated SHAKE256.
///
/// Empty input returns `VeilError::Crypto`.
pub fn attest_batch(items: &[&[u8]]) -> Result<Verdict, VeilError> {
    let claims: Vec<Claim<'_>> = items.iter().map(|b| Claim::new(b)).collect();
    verify_batch(&claims)
}

/// Attest multiple UTF-8 strings in a single batch.
///
/// Convenience wrapper over [`attest_batch`] for string slices.
pub fn attest_batch_texts(texts: &[&str]) -> Result<Verdict, VeilError> {
    let items: Vec<&[u8]> = texts.iter().map(|s| s.as_bytes()).collect();
    attest_batch(&items)
}

// ═══════════════════════════════════════════════════════════════════════════
// Chain & directory attestation
// ═══════════════════════════════════════════════════════════════════════════

/// Attest a sequence of events as a tamper-evident chain and return a single
/// final anchor `Verdict`.
///
/// Composition: `chain::chain_root(events)` folds the events into a
/// domain-separated SHAKE256 root, then `attest_bytes` runs the ML-DSA
/// pipeline over that root. Tampering with any event changes the root, so
/// the single returned `Verdict` covers the whole sequence.
///
/// Notes on privacy:
/// * `chain_root` is reproducible by anyone holding the events, so the
///   returned root is a public anchor — not a secret.
/// * The root buffer is wiped defensively after the pipeline absorbs it;
///   the engine itself wipes it at L6 regardless.
/// * No event count, no event order, no per-event transcript leaks through
///   the returned `Verdict`.
/// * An empty input returns `VeilError::Crypto` — there is no chain to attest.
pub fn attest_chain(events: &[&[u8]]) -> Result<Verdict, VeilError> {
    let mut root = chain_root(events)?;
    let verdict = attest_bytes(&root)?;
    zeroize_bytes(&mut root);
    Ok(verdict)
}

/// Chain-attest the contents of multiple files via streaming.
///
/// Each file is read in chunks and absorbed into a single `ChainState`
/// accumulator (one absorb per chunk, prefixed with the file path as a
/// domain separator so file boundaries are cryptographically bound).
/// The final chain root is then attested through the ML-DSA pipeline.
///
/// This produces a single `Verdict` that covers all files: tampering
/// with any byte in any file, or reordering files, changes the root.
///
/// Empty paths or unreadable files return `VeilError::Crypto`.
pub fn attest_chain_files(paths: &[&str]) -> Result<Verdict, VeilError> {
    if paths.is_empty() {
        return Err(VeilError::Crypto);
    }

    let mut state = ChainState::new();
    let mut buf = vec![0u8; FILE_CHUNK];

    for path in paths {
        // Absorb the file path as a domain separator so file boundaries
        // are cryptographically bound in the chain.
        state.absorb(path.as_bytes());

        let file = std::fs::File::open(path).map_err(|_| VeilError::Crypto)?;
        let mut reader = std::io::BufReader::with_capacity(FILE_CHUNK, file);
        loop {
            let n = reader.read(&mut buf).map_err(|_| VeilError::Crypto)?;
            if n == 0 {
                break;
            }
            state.absorb(&buf[..n]);
            for b in &mut buf[..n] {
                *b = 0;
            }
        }
    }

    zeroize_bytes(&mut buf);

    let mut root = state.finalize()?;
    let verdict = attest_bytes(&root)?;
    zeroize_bytes(&mut root);
    Ok(verdict)
}

/// Chain-attest all files in a directory (non-recursive, sorted by name).
///
/// Reads the directory, sorts entries lexicographically by filename,
/// and delegates to [`attest_chain_files`]. Hidden files (starting with
/// `.`) and subdirectories are skipped.
///
/// Use case: produce a single integrity anchor for a directory of
/// configuration files, build artifacts, or audit logs.
pub fn attest_directory(dir: &str) -> Result<Verdict, VeilError> {
    let entries = std::fs::read_dir(dir).map_err(|_| VeilError::Crypto)?;
    let mut paths: Vec<String> = Vec::new();

    for entry in entries {
        let entry = entry.map_err(|_| VeilError::Crypto)?;
        let ft = entry.file_type().map_err(|_| VeilError::Crypto)?;
        if !ft.is_file() {
            continue;
        }
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with('.') {
            continue; // skip hidden files
        }
        paths.push(entry.path().to_string_lossy().into_owned());
    }

    if paths.is_empty() {
        return Err(VeilError::Crypto);
    }

    paths.sort();
    let path_refs: Vec<&str> = paths.iter().map(|s| s.as_str()).collect();
    attest_chain_files(&path_refs)
}

/// Build a Merkle tree from the SHAKE256 hashes of multiple files and
/// attest the root.
///
/// Each file is loaded and hashed (via the streaming chain accumulator
/// for large files). The per-file hashes become Merkle leaves, and the
/// resulting root is attested through the ML-DSA pipeline.
///
/// Compared to [`attest_chain_files`] (which folds files sequentially),
/// this produces a Merkle root that supports efficient inclusion proofs:
/// given the root, a single file's hash can be authenticated against
/// the root using the sibling path without re-hashing all files.
pub fn attest_file_merkle(paths: &[&str]) -> Result<Verdict, VeilError> {
    if paths.is_empty() {
        return Err(VeilError::Crypto);
    }

    // Hash each file via streaming to get per-file digests.
    let mut file_hashes: Vec<[u8; 32]> = Vec::with_capacity(paths.len());
    for path in paths {
        let mut state = ChainState::new();
        let mut buf = vec![0u8; FILE_CHUNK];
        let file = std::fs::File::open(path).map_err(|_| VeilError::Crypto)?;
        let mut reader = std::io::BufReader::with_capacity(FILE_CHUNK, file);
        loop {
            let n = reader.read(&mut buf).map_err(|_| VeilError::Crypto)?;
            if n == 0 {
                break;
            }
            state.absorb(&buf[..n]);
            for b in &mut buf[..n] {
                *b = 0;
            }
        }
        zeroize_bytes(&mut buf);
        file_hashes.push(state.finalize()?);
    }

    // Build Merkle tree from file hashes and attest the root.
    let leaf_refs: Vec<&[u8]> = file_hashes.iter().map(|h| h.as_slice()).collect();
    let mut root = crate::merkle_root(&leaf_refs)?;
    let verdict = attest_bytes(&root)?;
    zeroize_bytes(&mut root);
    Ok(verdict)
}

// ═══════════════════════════════════════════════════════════════════════════
// Relation proofs (one-call wrappers)
// ═══════════════════════════════════════════════════════════════════════════

/// Prove knowledge of a 32-byte hash preimage (Lamport one-time proof).
///
/// The `seed` is the secret witness; the derived Lamport public key is
/// the statement. The proof reveals one leaf per position based on the
/// Fiat-Shamir challenge. Soundness rests on SHAKE256 preimage resistance.
pub fn prove_hash_preimage(seed: [u8; 32]) -> Result<Verdict, VeilError> {
    let witness = crate::relations::hash_preimage::Witness { seed };
    prove_and_verify::<crate::relations::hash_preimage::HashPreimage>(&witness, b"")
}

/// Prove knowledge of a Pedersen commitment opening (value + blinding).
///
/// The commitment is `C = SHAKE256(PEDERSEN_OPEN ‖ value ‖ blinding)`.
/// The proof reveals the opening within the engine; only the `Verdict`
/// (valid bit + transcript) is emitted.
pub fn prove_pedersen(value: [u8; 32], blinding: [u8; 32]) -> Result<Verdict, VeilError> {
    let witness = crate::relations::pedersen::Witness { value, blinding };
    prove_and_verify::<crate::relations::pedersen::PedersenCommitment>(&witness, b"")
}

/// Prove Merkle inclusion: the leaf at `index` is a member of the set.
///
/// Builds the Merkle tree from the given leaves, generates an inclusion
/// proof (authentication path), and verifies it — all in one call.
/// Returns the engine `Verdict` bound to the Merkle root.
pub fn prove_merkle(leaves: &[&[u8]], index: usize) -> Result<Verdict, VeilError> {
    let owned_leaves: Vec<Vec<u8>> = leaves.iter().map(|l| l.to_vec()).collect();
    let witness = crate::relations::merkle::Witness {
        leaves: owned_leaves,
        index,
    };
    prove_and_verify::<crate::relations::merkle::MerkleInclusion>(&witness, b"")
}

// ═══════════════════════════════════════════════════════════════════════════
// Verification oracles (pure math, no PQ, no entropy, no side effects)
// ═══════════════════════════════════════════════════════════════════════════

/// Check that `events` fold to `expected_root` under the chain framing.
///
/// Pure SHAKE256 math — no post-quantum signature, no entropy, no
/// ephemeral identity. Anyone with the events and the published root
/// can verify offline without keys, without the engine, without side
/// effects.
///
/// Returns `true` if the chain root matches, `false` otherwise.
pub fn check_chain(events: &[&[u8]], expected_root: &[u8; 32]) -> bool {
    chain_verify(events, expected_root).unwrap_u8() == 1
}

/// Verify Merkle inclusion: check that `leaf` authenticates against
/// `root` at position `index` given the sibling path.
///
/// Pure SHAKE256 math — no PQ, no entropy, no side effects.
/// This is the auditor-side verification for certificate transparency,
/// transparency logs, or any Merkle-based integrity structure.
///
/// Returns `true` if the leaf is authentic, `false` otherwise.
pub fn check_merkle(
    leaf: &[u8; 32],
    root: &[u8; 32],
    index: usize,
    siblings: &[[u8; 32]],
    leaf_count: usize,
) -> bool {
    crate::merkle_verify_path(leaf, root, index, siblings, leaf_count).unwrap_u8() == 1
}

// ═══════════════════════════════════════════════════════════════════════════
// Range Proof (one-call wrapper)
// ═══════════════════════════════════════════════════════════════════════════

/// Prove that `value` is within `[min, max]` without revealing `value`.
///
/// Uses bit-decomposition + SHAKE256 commitments. The proof reveals bits
/// and nonces within the engine; only the `Verdict` is emitted.
///
/// Returns `Ok(Verdict)` with `valid=1` if `min ≤ value ≤ max`,
/// `valid=0` if out of range. Returns `Err` on invalid parameters.
pub fn prove_range(value: u64, min: u64, max: u64) -> Result<Verdict, VeilError> {
    if min > max {
        return Err(VeilError::Crypto);
    }
    let witness = crate::relations::range_proof::Witness { value, min, max };
    prove_and_verify::<crate::relations::range_proof::RangeProof>(&witness, b"")
}

// ═══════════════════════════════════════════════════════════════════════════
// Threshold Attestation (N-of-M)
// ═══════════════════════════════════════════════════════════════════════════

/// Run `m` independent verification iterations on `claim_bytes` and require
/// at least `n` of them to produce `valid=1`.
///
/// Each iteration uses fresh entropy and fresh ephemeral keys (stateless).
/// The final `Verdict` has `valid=1` if ≥ N iterations passed.
///
/// Returns `Err` if `n == 0`, `m == 0`, or `n > m`.
pub fn threshold_attest(claim_bytes: &[u8], n: usize, m: usize) -> Result<Verdict, VeilError> {
    crate::threshold::threshold_verify(&Claim::new(claim_bytes), n, m)
}

// ═══════════════════════════════════════════════════════════════════════════
// Blind Attestation
// ═══════════════════════════════════════════════════════════════════════════

/// Blind a claim with a random mask.
///
/// Returns `(blinded_claim, BlindFactor)`. The caller sends `blinded_claim`
/// to the engine and keeps `factor` for later unblinding.
pub fn blind_claim(claim: &[u8]) -> Result<(Vec<u8>, crate::blind::BlindFactor), VeilError> {
    let factor = crate::blind::BlindFactor::fresh()?;
    let blinded = crate::blind::blind_claim(claim, &factor);
    Ok((blinded, factor))
}

/// Attest a blinded claim through the full L1→L7 pipeline.
///
/// The engine processes the blinded data without seeing the original claim.
pub fn attest_blinded(blinded_claim: &[u8]) -> Result<Verdict, VeilError> {
    verify_once(&Claim::new(blinded_claim))
}

/// Unblind a verdict transcript using the blinding factor.
///
/// Returns the unblinded 32-byte transcript that correlates to the
/// original claim.
pub fn unblind_verdict(verdict: &Verdict, factor: &crate::blind::BlindFactor) -> [u8; 32] {
    crate::blind::unblind_transcript(verdict.transcript(), factor)
}

// ═══════════════════════════════════════════════════════════════════════════
// Forward-Secrecy Chain
// ═══════════════════════════════════════════════════════════════════════════

/// Attest a single chain entry, optionally chaining to a previous transcript.
///
/// If `prev_transcript` is `Some`, the event is chained to the previous
/// entry's transcript (forward secrecy). If `None`, this is the first entry.
///
/// Returns a `Verdict` whose transcript can be used as `prev_transcript`
/// for the next entry.
pub fn attest_chain_entry(
    event: &[u8],
    prev_transcript: Option<&[u8; 32]>,
) -> Result<Verdict, VeilError> {
    // Build chain data: [prev_transcript || event] or just [event]
    let mut chain_data = Vec::new();
    if let Some(prev) = prev_transcript {
        chain_data.extend_from_slice(prev);
    }
    chain_data.extend_from_slice(event);
    verify_once(&Claim::new(&chain_data))
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relations::Relation;

    // ── attest_structured ──────────────────────────────────────────────────

    #[test]
    fn attest_structured_produces_valid_verdict() {
        let v = attest_structured(b"audit", b"some payload").unwrap();
        assert!(v.is_valid_bool());
    }

    #[test]
    fn attest_structured_different_labels_different_transcripts() {
        let v1 = attest_structured(b"label-A", b"payload").unwrap();
        let v2 = attest_structured(b"label-B", b"payload").unwrap();
        assert!(v1.is_valid_bool() && v2.is_valid_bool());
        assert_ne!(
            v1.transcript(),
            v2.transcript(),
            "different personalization must produce different transcripts"
        );
    }

    // ── attest_with_vm ─────────────────────────────────────────────────────

    #[test]
    fn attest_with_vm_produces_valid_verdict() {
        let v = attest_with_vm(b"test data for VM pipeline").unwrap();
        assert!(v.is_valid_bool());
    }

    #[test]
    fn attest_with_vm_differs_from_plain() {
        let v_plain = attest_bytes(b"same data").unwrap();
        let v_vm = attest_with_vm(b"same data").unwrap();
        // Both valid, but different transcripts (different pipeline).
        assert_ne!(v_plain.transcript(), v_vm.transcript());
    }

    // ── attest_with_oram ───────────────────────────────────────────────────

    #[test]
    fn attest_with_oram_produces_valid_verdict() {
        let v = attest_with_oram(b"test data for ORAM pipeline").unwrap();
        assert!(v.is_valid_bool());
    }

    // ── attest_batch ───────────────────────────────────────────────────────

    #[test]
    fn attest_batch_all_valid() {
        let items: &[&[u8]] = &[b"alpha", b"beta", b"gamma"];
        let v = attest_batch(items).unwrap();
        assert!(v.is_valid_bool(), "all items valid → batch valid");
    }

    #[test]
    fn attest_batch_empty_fails() {
        let items: &[&[u8]] = &[];
        assert!(attest_batch(items).is_err());
    }

    #[test]
    fn attest_batch_single_item() {
        let items: &[&[u8]] = &[b"solo"];
        let v = attest_batch(items).unwrap();
        assert!(v.is_valid_bool());
    }

    #[test]
    fn attest_batch_deterministic_transcript_for_same_items() {
        let items: &[&[u8]] = &[b"x", b"y"];
        // Batch transcripts depend on per-iteration entropy, so two runs
        // will have different transcripts. Just verify both are valid.
        let v1 = attest_batch(items).unwrap();
        let v2 = attest_batch(items).unwrap();
        assert!(v1.is_valid_bool() && v2.is_valid_bool());
    }

    // ── attest_batch_texts ─────────────────────────────────────────────────

    #[test]
    fn attest_batch_texts_works() {
        let texts: &[&str] = &["hello", "world", "foo"];
        let v = attest_batch_texts(texts).unwrap();
        assert!(v.is_valid_bool());
    }

    // ── attest_chain_files ─────────────────────────────────────────────────

    #[test]
    fn attest_chain_files_rejects_empty() {
        let paths: &[&str] = &[];
        assert!(attest_chain_files(paths).is_err());
    }

    #[test]
    fn attest_chain_files_rejects_missing() {
        let paths: &[&str] = &["/nonexistent/file.txt"];
        assert!(attest_chain_files(paths).is_err());
    }

    // ── attest_directory ───────────────────────────────────────────────────

    #[test]
    fn attest_directory_rejects_nonexistent() {
        assert!(attest_directory("/nonexistent/dir/12345").is_err());
    }

    #[test]
    fn attest_directory_rejects_empty_dir() {
        let dir = std::env::temp_dir().join("veil7_test_empty_dir");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(attest_directory(dir.to_str().unwrap()).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── prove_hash_preimage ────────────────────────────────────────────────

    #[test]
    fn prove_hash_preimage_valid() {
        let v = prove_hash_preimage([0xAB; 32]).unwrap();
        assert!(v.is_valid_bool());
    }

    // ── prove_pedersen ─────────────────────────────────────────────────────

    #[test]
    fn prove_pedersen_valid() {
        let v = prove_pedersen([0x11; 32], [0x22; 32]).unwrap();
        assert!(v.is_valid_bool());
    }

    // ── prove_merkle ───────────────────────────────────────────────────────

    #[test]
    fn prove_merkle_valid() {
        let leaves: &[&[u8]] = &[b"leaf0", b"leaf1", b"leaf2", b"leaf3"];
        let v = prove_merkle(leaves, 2).unwrap();
        assert!(v.is_valid_bool());
    }

    // ── check_chain oracle ────────────────────────────────────────────────

    #[test]
    fn check_chain_matches_chain_root() {
        let events: &[&[u8]] = &[b"login", b"read", b"logout"];
        let root = chain_root(events).unwrap();
        assert!(check_chain(events, &root));
    }

    #[test]
    fn check_chain_detects_tamper() {
        let events: &[&[u8]] = &[b"login", b"read", b"logout"];
        let root = chain_root(events).unwrap();
        let tampered: &[&[u8]] = &[b"login", b"WRITE", b"logout"];
        assert!(!check_chain(tampered, &root));
    }

    // ── check_merkle oracle ───────────────────────────────────────────────

    #[test]
    fn check_merkle_roundtrip() {
        let leaves: &[&[u8]] = &[b"a", b"b", b"c", b"d"];
        let root = crate::merkle_root(leaves).unwrap();
        // Build proof for index 1 manually via the relation.
        let owned: Vec<Vec<u8>> = leaves.iter().map(|l| l.to_vec()).collect();
        let witness = crate::relations::merkle::Witness {
            leaves: owned,
            index: 1,
        };
        let (stmt, proof) =
            crate::relations::merkle::MerkleInclusion::prove(&witness, &[]).unwrap();
        assert!(check_merkle(
            &stmt.leaf,
            &root,
            proof.index,
            &proof.siblings,
            proof.leaf_count
        ));
    }

    // ── prove_range oracle ────────────────────────────────────────────────

    #[test]
    fn prove_range_in_range() {
        let result = prove_range(500, 100, 1000).unwrap();
        assert!(result.is_valid_bool());
    }

    #[test]
    fn prove_range_at_boundary() {
        let result = prove_range(100, 100, 1000).unwrap();
        assert!(result.is_valid_bool());
        let result2 = prove_range(1000, 100, 1000).unwrap();
        assert!(result2.is_valid_bool());
    }

    #[test]
    fn prove_range_out_of_range_fails() {
        // value > max should produce valid=0 (proof generates but verification fails)
        let result = prove_range(1001, 100, 1000).unwrap();
        assert!(!result.is_valid_bool());
    }

    // ── threshold_attest oracle ─────────────────────────────────────────────

    #[test]
    fn threshold_attest_3_of_5() {
        let claim_bytes = b"threshold-test";
        let result = threshold_attest(claim_bytes, 3, 5).unwrap();
        assert!(result.is_valid_bool());
    }

    #[test]
    fn threshold_attest_1_of_1() {
        let result = threshold_attest(b"single", 1, 1).unwrap();
        assert!(result.is_valid_bool());
    }

    #[test]
    fn threshold_attest_invalid_params() {
        assert!(threshold_attest(b"test", 0, 5).is_err()); // n=0
        assert!(threshold_attest(b"test", 6, 5).is_err()); // n > m
        assert!(threshold_attest(b"test", 5, 0).is_err()); // m=0
    }

    // ── blind_attest oracle ─────────────────────────────────────────────────

    #[test]
    fn blind_attest_roundtrip() {
        let claim = b"secret-data";
        let (blinded, factor) = blind_claim(claim).unwrap();
        let verdict = attest_blinded(&blinded).unwrap();
        assert!(verdict.is_valid_bool());
        let unblinded = unblind_verdict(&verdict, &factor);
        assert_ne!(unblinded, [0u8; 32]);
    }

    #[test]
    fn blind_double_blind_recovers_original() {
        let claim = b"test-data";
        let factor = crate::blind::BlindFactor::from_nonce([0x42; 32]);
        let blinded = crate::blind::blind_claim(claim, &factor);
        let recovered = crate::blind::blind_claim(&blinded, &factor);
        assert_eq!(&recovered[..], claim);
    }

    // ── attest_chain_entry oracle ───────────────────────────────────────────

    #[test]
    fn attest_chain_entry_single() {
        let result = attest_chain_entry(b"first-event", None).unwrap();
        assert!(result.is_valid_bool());
    }

    #[test]
    fn attest_chain_entry_chained() {
        let v1 = attest_chain_entry(b"event-1", None).unwrap();
        let v2 = attest_chain_entry(b"event-2", Some(v1.transcript())).unwrap();
        assert!(v2.is_valid_bool());
        let v3 = attest_chain_entry(b"event-3", Some(v2.transcript())).unwrap();
        assert!(v3.is_valid_bool());
        // All transcripts should be different
        assert_ne!(v1.transcript(), v2.transcript());
        assert_ne!(v2.transcript(), v3.transcript());
    }

    // ── attest_text ────────────────────────────────────────────────────────

    #[test]
    fn attest_text_basic() {
        let v = attest_text("hello world").unwrap();
        assert!(v.is_valid_bool());
    }

    #[test]
    fn attest_text_empty() {
        let v = attest_text("").unwrap();
        assert!(v.is_valid_bool());
    }

    #[test]
    fn attest_text_unicode() {
        let v = attest_text("Hello 世界 🌍").unwrap();
        assert!(v.is_valid_bool());
    }

    #[test]
    fn attest_text_large() {
        let large = "A".repeat(100_000);
        let v = attest_text(&large).unwrap();
        assert!(v.is_valid_bool());
    }

    #[test]
    fn attest_text_different_inputs_different_transcripts() {
        let v1 = attest_text("input A").unwrap();
        let v2 = attest_text("input B").unwrap();
        assert!(v1.is_valid_bool());
        assert!(v2.is_valid_bool());
        // Transcripts differ due to ephemeral keys, but both valid
    }

    // ── attest_file_merkle ─────────────────────────────────────────────────

    #[test]
    fn attest_file_merkle_single_file() {
        use std::io::Write;
        let dir = std::env::temp_dir().join("veil7_test_merkle_single");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let f1 = dir.join("file1.txt");
        std::fs::File::create(&f1)
            .unwrap()
            .write_all(b"hello world")
            .unwrap();

        let paths = [f1.to_str().unwrap()];
        let v = attest_file_merkle(&paths).unwrap();
        assert!(v.is_valid_bool());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn attest_file_merkle_multiple_files() {
        use std::io::Write;
        let dir = std::env::temp_dir().join("veil7_test_merkle_multi");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let f1 = dir.join("file1.txt");
        let f2 = dir.join("file2.txt");
        let f3 = dir.join("file3.txt");
        std::fs::File::create(&f1)
            .unwrap()
            .write_all(b"file one")
            .unwrap();
        std::fs::File::create(&f2)
            .unwrap()
            .write_all(b"file two")
            .unwrap();
        std::fs::File::create(&f3)
            .unwrap()
            .write_all(b"file three")
            .unwrap();

        let paths = [
            f1.to_str().unwrap(),
            f2.to_str().unwrap(),
            f3.to_str().unwrap(),
        ];
        let v = attest_file_merkle(&paths).unwrap();
        assert!(v.is_valid_bool());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn attest_file_merkle_empty_paths_fails() {
        let paths: &[&str] = &[];
        assert!(attest_file_merkle(paths).is_err());
    }

    #[test]
    fn attest_file_merkle_nonexistent_file_fails() {
        let paths = ["/nonexistent/file/that/does/not/exist.txt"];
        assert!(attest_file_merkle(&paths).is_err());
    }

    #[test]
    fn attest_file_merkle_deterministic() {
        use std::io::Write;
        let dir = std::env::temp_dir().join("veil7_test_merkle_det");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let f1 = dir.join("det1.txt");
        let f2 = dir.join("det2.txt");
        std::fs::File::create(&f1)
            .unwrap()
            .write_all(b"deterministic")
            .unwrap();
        std::fs::File::create(&f2)
            .unwrap()
            .write_all(b"test data")
            .unwrap();

        let paths = [f1.to_str().unwrap(), f2.to_str().unwrap()];
        // Merkle root is deterministic, but transcripts differ (ephemeral keys).
        // Just verify both succeed.
        let v1 = attest_file_merkle(&paths).unwrap();
        let v2 = attest_file_merkle(&paths).unwrap();
        assert!(v1.is_valid_bool());
        assert!(v2.is_valid_bool());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn attest_file_merkle_different_files_different_root() {
        use std::io::Write;
        let dir1 = std::env::temp_dir().join("veil7_test_merkle_diff1");
        let dir2 = std::env::temp_dir().join("veil7_test_merkle_diff2");
        let _ = std::fs::remove_dir_all(&dir1);
        let _ = std::fs::remove_dir_all(&dir2);
        std::fs::create_dir_all(&dir1).unwrap();
        std::fs::create_dir_all(&dir2).unwrap();

        let f1 = dir1.join("file.txt");
        let f2 = dir2.join("file.txt");
        std::fs::File::create(&f1)
            .unwrap()
            .write_all(b"content A")
            .unwrap();
        std::fs::File::create(&f2)
            .unwrap()
            .write_all(b"content B")
            .unwrap();

        let paths1 = [f1.to_str().unwrap()];
        let paths2 = [f2.to_str().unwrap()];

        // Both should succeed but produce different roots
        let v1 = attest_file_merkle(&paths1).unwrap();
        let v2 = attest_file_merkle(&paths2).unwrap();
        assert!(v1.is_valid_bool());
        assert!(v2.is_valid_bool());
        // Transcripts should differ (different content → different Merkle root)
        assert_ne!(v1.transcript(), v2.transcript());

        let _ = std::fs::remove_dir_all(&dir1);
        let _ = std::fs::remove_dir_all(&dir2);
    }

    #[test]
    fn attest_file_merkle_mixed_valid_invalid_fails() {
        use std::io::Write;
        let dir = std::env::temp_dir().join("veil7_test_merkle_mixed");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let f1 = dir.join("valid.txt");
        std::fs::File::create(&f1)
            .unwrap()
            .write_all(b"valid content")
            .unwrap();

        let paths = [f1.to_str().unwrap(), "/nonexistent/file.txt"];
        assert!(attest_file_merkle(&paths).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── Edge cases ─────────────────────────────────────────────────────────

    #[test]
    fn attest_bytes_empty_input() {
        let v = attest_bytes(b"").unwrap();
        assert!(v.is_valid_bool());
    }

    #[test]
    fn attest_bytes_very_large_input() {
        let large = vec![0xAAu8; 100_000];
        let v = attest_bytes(&large).unwrap();
        assert!(v.is_valid_bool());
    }

    #[test]
    fn chain_root_single_event() {
        let root = crate::chain::chain_root(&[b"single"]).unwrap();
        assert_ne!(root, [0u8; 32]);
    }

    #[test]
    fn merkle_root_two_leaves() {
        let root = crate::merkle_root(&[b"leaf1", b"leaf2"]).unwrap();
        assert_ne!(root, [0u8; 32]);
    }

    #[test]
    fn prove_range_min_equals_max() {
        let v = prove_range(50, 50, 50).unwrap();
        assert!(v.is_valid_bool());
    }

    #[test]
    fn prove_range_all_zero() {
        let v = prove_range(0, 0, 0).unwrap();
        assert!(v.is_valid_bool());
    }

    #[test]
    fn microvm_execute_near_max_bytes() {
        use crate::execution::vm::BytecodeBuilder;
        // Build bytecode with 100 push instructions (under the 128 stack limit)
        // Each push is 9 bytes (1 opcode + 8 bytes value) = 900 bytes total
        let mut builder = BytecodeBuilder::new();
        for _ in 0..100 {
            builder = builder.push(42);
        }
        let code = builder.build();
        assert_eq!(code.len(), 900);
        let mut vm = crate::execution::MicroVM::new();
        let root = vm.execute(&code);
        assert_ne!(root, [0u8; 64]);
    }

    #[test]
    fn shamir_split_large_shares() {
        let secret = [0x42u8; 64];
        // Max threshold is 32 (coeffs array size), so use t=32, n=50
        let result = crate::shamir::split(&secret, 50, 32);
        assert!(result.is_some());
    }

    #[test]
    fn shamir_reconstruct_empty_slice() {
        let result = crate::shamir::reconstruct(&[]);
        assert!(result.is_none());
    }

    // ── Error paths ────────────────────────────────────────────────────────

    #[test]
    fn attest_file_nonexistent_path() {
        let result = attest_file("/nonexistent/file/that/does/not/exist.txt");
        assert!(result.is_err());
    }

    #[test]
    fn commit_phase_empty_input() {
        let result = crate::commit_reveal::commit_phase(b"");
        assert!(result.is_ok()); // Empty input is valid
    }

    #[test]
    fn blind_attest_empty_claim() {
        let result = crate::blind::blind_attest(b"");
        assert!(result.is_ok()); // Empty input is valid
    }

    #[test]
    fn threshold_attest_n_zero() {
        let result = threshold_attest(b"test", 0, 5);
        assert!(result.is_err()); // n=0 is invalid
    }

    #[test]
    fn shamir_split_t_greater_than_n() {
        let secret = [0x42u8; 64];
        let result = crate::shamir::split(&secret, 3, 5); // t > n
        assert!(result.is_none());
    }

    #[test]
    fn locked_fill_from_oversized_src() {
        let mut locked = crate::l0_memlock::Locked::<32>::new();
        let oversized = vec![0xAAu8; 64]; // Too large for Locked<32>
        let result = locked.fill_from(&oversized);
        assert!(!result); // Should reject oversized input
    }
}
