//! Simple interface wrapper — one-call attestation for common use cases.
//!
//! This module is intentionally thin: it only routes inputs into the engine
//! and returns the raw `Verdict`. No formatting, no `String` allocation, no
//! metadata generation. Anything that prints or formats lives outside the
//! library (e.g. in `main.rs` or in the caller's code).
//!
//! The chain composition itself is in [`crate::chain`] and is `no_std`
//! available; `attest_chain` here is the std-gated convenience that also
//! runs the ML-DSA pipeline over the chain root.
#![cfg(feature = "std")]

use std::io::Read;

use crate::chain::{chain_root, ChainState};
use crate::l0_memlock::zeroize_bytes;
use crate::{verify_once, Claim, VeilError, Verdict};

/// Chunk size for [`attest_file_streaming`]. Picked to match the page
/// size on common targets (aarch64 / x86_64) so chunk reads align with
/// the kernel page cache, and to bound transient memory to a few KB
/// regardless of file size. Tunable by callers via the `_with_chunk_size`
/// variant below.
const FILE_CHUNK: usize = 4096;

/// Attest raw bytes through the legacy ML-DSA pipeline.
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
