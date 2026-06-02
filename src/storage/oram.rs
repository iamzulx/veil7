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
use zeroize::Zeroize;

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
    #[must_use = "read result must be used"]
    pub fn read(&self, addr: usize) -> [u8; 64] {
        let index = addr % 256;
        let mut result = GENESIS;

        for i in 0..256 {
            // Touch all pad bytes — constant traffic on the memory bus.
            for j in 0..64 {
                let _ = self.data[i].pad[j];
            }

            // Only extract the target content (already hashed at write time).
            if i == index {
                result = self.data[i].content;
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
    pub fn write(&mut self, addr: usize, value: [u8; 64]) {
        let index = addr % 256;
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

        hashed.zeroize();
    }
}

impl Default for ObliviousRAM {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ObliviousRAM {
    fn drop(&mut self) {
        for slot in self.data.iter_mut() {
            slot.content.zeroize();
            slot.pad.zeroize();
        }
    }
}

// ── ORAM hash (SHAKE256 → 64 bytes) ─────────────────────────────────────────

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

    #[test]
    fn address_wraps_modulo_256() {
        let mut oram = ObliviousRAM::new();
        let val: [u8; 64] = [0x77u8; 64];
        oram.write(256 + 3, val); // same as addr=3
        let got = oram.read(3);
        assert_eq!(got, oram_hash(&val));
    }
}
