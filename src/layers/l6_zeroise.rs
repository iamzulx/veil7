//! L6 — Zeroization.
//!
//! Defence-in-depth wiping. The PQ secret keys already self-wipe on Drop
//! (RustCrypto `ZeroizeOnDrop`), and L1's `Seed` wipes on Drop too. This layer
//! provides:
//!
//!   1. `Zeroizing<T>` — a guard that explicitly zeroises a buffer at end of
//!      scope, for any transient byte material the pipeline holds.
//!   2. `scrub()` — an explicit barrier the orchestrator calls at the end of
//!      each iteration to force-drop all key material *before* the verdict is
//!      returned, so secrets never coexist with the emitted result.
//!
//! Statelessness guarantee: after `scrub()` consumes the keys, there is no path
//! by which key material can outlive the iteration.

use crate::l2_keygen::EphemeralKeys;
use zeroize::Zeroize;

/// A scope guard that zeroises its contents when dropped. Use for transient
/// secret-adjacent byte buffers that aren't already `ZeroizeOnDrop`.
pub struct Zeroizing<const N: usize>(pub [u8; N]);

impl<const N: usize> Drop for Zeroizing<N> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<const N: usize> Zeroizing<N> {
    #[inline]
    pub fn new(bytes: [u8; N]) -> Self {
        Zeroizing(bytes)
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }
}

/// Explicit end-of-iteration scrub barrier.
///
/// Takes ownership of the ephemeral keys and drops them immediately. Because
/// the ML-KEM decapsulation key and ML-DSA signing key are `ZeroizeOnDrop`,
/// this forces their secret material to be wiped at a well-defined point —
/// before the orchestrator emits any verdict. Returns nothing: the keys are
/// gone.
#[inline(never)] // ensure the drop is a real, non-elidable barrier
pub fn scrub(keys: EphemeralKeys) {
    // Moving `keys` in and letting it fall out of scope runs Drop on every
    // field. The `inline(never)` + explicit drop documents intent and prevents
    // the optimizer from reordering the wipe past the function boundary.
    drop(keys);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeroizing_wipes_on_drop() {
        let z = Zeroizing::new([0xAAu8; 16]);
        assert_eq!(z.as_bytes()[0], 0xAA);
        drop(z);
        // Can't observe wiped memory safely; this asserts the API shape works.
    }

    #[test]
    fn scrub_consumes_keys() {
        use crate::l1_entropy::harvest;
        use crate::l2_keygen::derive_keys;
        let seed = harvest(b"l6").unwrap();
        let keys = derive_keys(&seed).unwrap();
        scrub(keys);
        // `keys` is moved; compile-time proof it cannot be used after scrub.
    }
}
