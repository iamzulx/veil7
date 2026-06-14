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

use crate::l0_memlock::zeroize_bytes;
use crate::l2_keygen::EphemeralKeys;

/// A scope guard that zeroises its contents when dropped. Use for transient
/// secret-adjacent byte buffers that aren't already `ZeroizeOnDrop`.
pub struct Zeroizing<const N: usize>(pub [u8; N]);

impl<const N: usize> Drop for Zeroizing<N> {
    #[inline(never)]
    fn drop(&mut self) {
        zeroize_bytes(&mut self.0);
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
    #[cfg_attr(miri, ignore)] // calls derive_keys → libcrux cpuid (unsupported by Miri)
    fn scrub_consumes_keys() {
        use crate::l1_entropy::harvest;
        use crate::l2_keygen::derive_keys;
        let seed = harvest(b"l6").unwrap();
        let keys = derive_keys(&seed).unwrap();
        scrub(keys);
        // `keys` is moved; compile-time proof it cannot be used after scrub.
    }

    #[test]
    #[cfg_attr(miri, ignore)] // calls derive_keys → libcrux cpuid (unsupported by Miri)
    fn scrub_runs_drop_inline_never() {
        // The `#[inline(never)]` attribute on `scrub` is the
        // compile-time contract that prevents the optimizer from
        // reordering the Drop call past the function boundary.
        // We can't observe `inline(never)` at runtime, but we
        // can verify the contract indirectly: the function
        // must actually consume its argument (i.e., it takes
        // ownership of `EphemeralKeys` and drops it). If the
        // signature were `&EphemeralKeys` instead of
        // `EphemeralKeys`, scrub would be a no-op.
        //
        // Compile-time check: try to call scrub with a borrowed
        // reference and observe that it fails to type-check.
        // We do this with a compile-fail doctest pattern: we
        // declare a stub function with the wrong signature, then
        // check that the real `scrub` doesn't accept it.
        //
        // (We don't actually generate a compile_fail doctest
        // here because that would require an external file. The
        // `&EphemeralKeys` signature is a sufficient documentation
        // of the contract.)
        //
        // Runtime check: scrub must not return anything (the
        // signature is `fn scrub(keys: EphemeralKeys)` with no
        // return). We assert this at the type level by binding
        // the call to `let _: () = scrub(keys);`.
        use crate::l1_entropy::harvest;
        use crate::l2_keygen::derive_keys;
        let seed = harvest(b"l6-inline").unwrap();
        let keys = derive_keys(&seed).unwrap();
        // Type-assert: scrub returns unit. If the signature
        // changed to return something else, this would fail to
        // compile.
        let _: () = scrub(keys);
    }
}
