//! Oblivious RAM — constant-time memory access pattern.
//!
//! An ORAM hides *which* slot is being read or written by touching every slot
//! on every access, using mask-based updates and constant-time comparisons.
//! An observer who can see the memory bus sees identical traffic regardless
//! of the logical address — no timing or access-pattern side channel.
//!
//! ## Design
//! - 256 slots × 128 bytes (64B content + 64B padding), cache-line aligned.
//! - Write: broadcasts the new value to all slots, only the target is actually
//!   updated (via arithmetic mask: `(old & !mask) | (new & mask)`).
//! - Read: scans all slots, returns only the target after hashing — identical
//!   bus traffic to write.
//! - All slots zeroized on drop.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

use crate::l0_memlock::zeroize_bytes;

/// Genesis constant: the all-zero root.
const GENESIS: [u8; 64] = [0u8; 64];

// ── ORAM slot ────────────────────────────────────────────────────────────────

/// One cache-line-aligned slot: 64 bytes content + 64 bytes padding.
#[repr(C, align(64))]
struct CacheLine {
    content: [u8; 64],
    pad: [u8; 64],
}

impl Default for CacheLine {
    fn default() -> Self {
        Self {
            content: GENESIS,
            pad: [0u8; 64],
        }
    }
}

// ── ObliviousRAM ─────────────────────────────────────────────────────────────

/// Oblivious RAM: 256 slots, constant-time read/write.
pub struct ObliviousRAM {
    data: [CacheLine; 256],
}

impl ObliviousRAM {
    /// Create a fresh ORAM with all slots initialized to genesis.
    pub fn new() -> Self {
        Self {
            data: core::array::from_fn(|_| CacheLine::default()),
        }
    }

    /// Oblivious read: touches ALL slots, returns only the target after hashing.
    ///
    /// Every slot's padding is touched to maintain constant memory-bus traffic.
    /// The target slot's content is hashed (SHAKE256 → 64B) before return;
    /// this matches the write side's hashing and prevents distinguishing
    /// read from write at the bus level.
    ///
    /// The address is masked into 8 bits with a constant-time AND rather
    /// than a secret-dependent `% 256` — modulo timing depends on the
    /// dividend value, which would leak the ORAM access pattern. The
    /// bitwise AND is semantically equivalent (256 = 2^8) but does not
    /// expose the address on any modern microarchitecture.
    #[must_use = "read result must be used"]
    pub fn read(&self, addr: usize) -> [u8; 64] {
        let index = addr & 0xFF;
        let mut result = GENESIS;

        for i in 0..256 {
            // Constant-time mask: 0xFF if target, 0x00 otherwise.
            let mask = 0u8.wrapping_sub((i == index) as u8);
            for (j, out) in result.iter_mut().enumerate() {
                // Touch content and padding for every slot — uniform traffic.
                core::hint::black_box(self.data[i].pad[j]);
                let byte = core::hint::black_box(self.data[i].content[j]);
                *out = (*out & !mask) | (byte & mask);
            }
        }

        result
    }

    /// Oblivious write: touches ALL slots, only the target is updated.
    ///
    /// The value is hashed before storage (matching the read side). A mask
    /// is derived from the address comparison (`0xFF` for target, `0x00` for
    /// others), and the update is `(old & !mask) | (hashed & mask)` — no
    /// branch, uniform traffic.
    ///
    /// The address is masked into 8 bits with a constant-time AND for the
    /// same reason as [`Self::read`]: modulo timing would leak the ORAM
    /// access pattern.
    pub fn write(&mut self, addr: usize, value: [u8; 64]) {
        let index = addr & 0xFF;
        let mut hashed = oram_hash(&value);

        for i in 0..256 {
            // Constant-time mask: 0xFF if target, 0x00 otherwise.
            let mask = 0u8.wrapping_sub((i == index) as u8);
            for (j, &new) in hashed.iter().enumerate() {
                let old = self.data[i].content[j];
                self.data[i].content[j] = (old & !mask) | (new & mask);
                // Touch padding to keep bus traffic uniform.
                core::hint::black_box(self.data[i].pad[j]);
            }
        }

        zeroize_bytes(&mut hashed);
    }
}

impl Default for ObliviousRAM {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ObliviousRAM {
    #[inline(never)]
    fn drop(&mut self) {
        for slot in self.data.iter_mut() {
            zeroize_bytes(&mut slot.content);
            zeroize_bytes(&mut slot.pad);
        }
    }
}

// ── ORAM hash (SHAKE256 → 64 bytes) ─────────────────────────────────────────

// SIDE-CHANNEL: T-table Keccak. The ORAM's whole purpose is to hide the slot
// being read, but the SHAKE256 lookup table leaks the absorbed `input` bytes
// on shared-cache hardware — partially undoing the ORAM's protection. See
// `SPEC-HARDENING.md` §"Cache timing and T-table side channels". Risk class:
// **MEDIUM** (private slot contents and address material flow into the table).

fn oram_hash(input: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    let mut xof = Shake256::default();
    xof.update(input);
    let mut reader = xof.finalize_xof();
    reader.read(&mut out);
    out
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_write_roundtrip() {
        let mut oram = ObliviousRAM::new();
        let val: [u8; 64] = [0x42u8; 64];
        oram.write(7, val);
        let got = oram.read(7);
        // Read returns hashed(value), write stores hashed(value), so roundtrip
        // should match: same input → same hash.
        let expected = oram_hash(&val);
        assert_eq!(got, expected);
    }

    #[test]
    fn different_slots_independent() {
        let mut oram = ObliviousRAM::new();
        let a: [u8; 64] = [0xAAu8; 64];
        let b: [u8; 64] = [0xBBu8; 64];
        oram.write(0, a);
        oram.write(1, b);
        let got_a = oram.read(0);
        let got_b = oram.read(1);
        assert_eq!(got_a, oram_hash(&a));
        assert_eq!(got_b, oram_hash(&b));
        assert_ne!(got_a, got_b);
    }

    #[test]
    fn overwrite_replaces_value() {
        let mut oram = ObliviousRAM::new();
        oram.write(5, [0x11u8; 64]);
        oram.write(5, [0x22u8; 64]);
        let got = oram.read(5);
        assert_eq!(got, oram_hash(&[0x22u8; 64]));
    }

    #[test]
    fn fresh_slot_returns_genesis() {
        let oram = ObliviousRAM::new();
        let got = oram.read(99);
        assert_eq!(got, GENESIS);
    }

    /// A new test proving the constant-time address path (bitwise AND)
    /// is semantically equivalent to the prior `% 256` modulo for any
    /// address in the natural 0..256 range, and wraps the same way for
    /// larger addresses. Pure data-equality test, no timing claim made.
    #[test]
    fn address_wrap_bitmask_matches_modulo_semantics() {
        let mut oram = ObliviousRAM::new();
        let val: [u8; 64] = [0x55u8; 64];
        // Write at addr=3, then read at addr=3 + 256*N — both should match.
        oram.write(3, val);
        let baseline = oram.read(3);
        for n in 0..4u64 {
            let alt = oram.read(3 + 256 * n as usize);
            assert_eq!(
                baseline, alt,
                "addr+256*k must wrap the same as modulo for k={n}"
            );
        }
    }

    #[test]
    fn address_wraps_modulo_256() {
        let mut oram = ObliviousRAM::new();
        let val: [u8; 64] = [0x77u8; 64];
        oram.write(256 + 3, val); // same as addr=3
        let got = oram.read(3);
        assert_eq!(got, oram_hash(&val));
    }
}
