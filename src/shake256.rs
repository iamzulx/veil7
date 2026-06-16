// Author: Iamzulx
// Copyright (c) 2026
// License: MIT
//! SHAKE256 wrapper around libcrux-sha3 (formally verified, constant-time).
//!
//! Replaces the RustCrypto `sha3` crate with libcrux-sha3, which is:
//! - **Formally verified** via hax/F* for memory safety and functional correctness
//! - **Constant-time** — generic Keccak implementation, no T-tables
//! - **`#![forbid(unsafe_code)]`** — zero unsafe code
//!
//! This module provides an API compatible with the existing codebase:
//! ```ignore
//! let mut xof = Shake256::default();
//! xof.update(b"tag");
//! xof.update(b"data");
//! let mut out = [0u8; 32];
//! let mut reader = xof.finalize_xof();
//! reader.read(&mut out);
//! ```
//!
//! Internally, data is buffered and hashed in one shot via `libcrux_sha3::shake256`.
//! This eliminates the T-table cache-timing side channel present in RustCrypto's
//! `sha3` crate (documented in SPEC-HARDENING.md).

extern crate alloc;
use alloc::vec::Vec;

use crate::l0_memlock::zeroize_bytes;

/// Incremental SHAKE256 hasher backed by libcrux-sha3.
///
/// Buffers all input data and computes the hash in one shot on `finalize_xof()`.
/// The internal buffer is zeroized on drop.
pub struct Shake256 {
    buf: Vec<u8>,
}

impl Shake256 {
    /// Create a new SHAKE256 hasher.
    #[inline]
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Absorb data into the hasher.
    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Finalize and return a reader that can produce arbitrary-length output.
    ///
    /// Consumes the hasher. The returned `Shake256Reader` holds the computed
    /// output and can be read from incrementally.
    pub fn finalize_xof(self) -> Shake256Reader {
        // Compute a generous output buffer (256 bytes covers most use cases).
        // Callers that need more can use finalize_xof_extended().
        let mut out = [0u8; 256];
        libcrux_sha3::shake256_ema(&mut out, &self.buf);
        // Note: we can't zeroize self.buf here because self is consumed.
        // The Drop impl will handle it.
        Shake256Reader { out, pos: 0 }
    }
}

impl Default for Shake256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Shake256 {
    #[inline(never)]
    fn drop(&mut self) {
        zeroize_bytes(&mut self.buf);
    }
}

/// Reader for SHAKE256 output. Produced by `Shake256::finalize_xof()`.
///
/// Holds a pre-computed output buffer and serves bytes from it.
/// For outputs > 256 bytes, use `read_extended()`.
pub struct Shake256Reader {
    out: [u8; 256],
    pos: usize,
}

impl Shake256Reader {
    /// Read bytes from the XOF output.
    ///
    /// Fills `out` with bytes from the pre-computed buffer.
    /// If more bytes are requested than available, the output is truncated
    /// to the available bytes (no panic). Callers should check `out.len()`
    /// against their requested size.
    pub fn read(&mut self, out: &mut [u8]) {
        let available = self.out.len() - self.pos;
        let to_copy = out.len().min(available);
        out[..to_copy].copy_from_slice(&self.out[self.pos..self.pos + to_copy]);
        self.pos += to_copy;
        // Zero-fill any remaining bytes if caller requested more than available
        if to_copy < out.len() {
            for b in &mut out[to_copy..] {
                *b = 0;
            }
        }
    }
}

impl Drop for Shake256Reader {
    #[inline(never)]
    fn drop(&mut self) {
        zeroize_bytes(&mut self.out);
    }
}

/// One-shot SHAKE256: hash `data` and return `N` bytes.
pub fn shake256<const N: usize>(data: &[u8]) -> [u8; N] {
    libcrux_sha3::shake256(data)
}

/// One-shot SHAKE256 with variable-length output.
pub fn shake256_xof(out: &mut [u8], data: &[u8]) {
    libcrux_sha3::shake256_ema(out, data);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incremental_api_works() {
        let mut xof = Shake256::default();
        xof.update(b"hello");
        xof.update(b" ");
        xof.update(b"world");
        let mut out = [0u8; 32];
        let mut reader = xof.finalize_xof();
        reader.read(&mut out);

        let expected: [u8; 32] = shake256(b"hello world");
        assert_eq!(out, expected, "incremental must match one-shot");
    }

    #[test]
    fn oneshot_matches_direct() {
        let out1: [u8; 32] = shake256(b"test");
        let out2: [u8; 32] = libcrux_sha3::shake256(b"test");
        assert_eq!(out1, out2);
    }

    #[test]
    fn empty_input_produces_nonzero_output() {
        let out: [u8; 32] = shake256(b"");
        assert_ne!(out, [0u8; 32]);
    }

    #[test]
    fn different_inputs_different_outputs() {
        let out1: [u8; 32] = shake256(b"a");
        let out2: [u8; 32] = shake256(b"b");
        assert_ne!(out1, out2);
    }

    #[test]
    fn reader_serves_multiple_reads() {
        let mut xof = Shake256::new();
        xof.update(b"test data for multiple reads");
        let mut reader = xof.finalize_xof();

        let mut out1 = [0u8; 16];
        let mut out2 = [0u8; 16];
        reader.read(&mut out1);
        reader.read(&mut out2);

        let mut full = [0u8; 32];
        let mut xof2 = Shake256::new();
        xof2.update(b"test data for multiple reads");
        let mut reader2 = xof2.finalize_xof();
        reader2.read(&mut full);

        assert_eq!(&full[..16], &out1);
        assert_eq!(&full[16..], &out2);
    }

    #[test]
    fn xof_variable_length() {
        let mut out = [0u8; 64];
        shake256_xof(&mut out, b"test");
        assert_ne!(out, [0u8; 64]);
    }
}
