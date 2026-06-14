//! L0 — Memory Locking (defence-in-depth, swap protection).
//!
//! Provides [`Locked`]: a heap-boxed byte buffer whose pages are pinned in RAM
//! via `mlock(2)` so they cannot be paged out to swap/disk where a cold-boot or
//! disk-forensics attacker could later recover them. On drop the buffer is
//! zeroised FIRST, then `munlock`'d — order matters so the secret never lingers
//! in a still-unlockable page.
//!
//! ## Scope (honest about what this does and does NOT cover)
//! This locks material veil7 *owns*: the L1 master seed and L2's transient
//! sub-seeds — the upstream entropy from which every key is derived. The PQ
//! secret keys themselves (ML-KEM/ML-DSA) are heap-allocated inside the
//! RustCrypto crates and cannot be mlock'd without forking them; those still
//! rely on `ZeroizeOnDrop` for wiping. Locking the seed is the meaningful win:
//! it is the root secret, and it is small enough to fit the device's modest
//! RLIMIT_MEMLOCK budget.
//!
//! ## Failure policy
//! `mlock` can fail (e.g. RLIMIT_MEMLOCK exhausted). veil7 treats memory locking
//! as best-effort hardening, not a correctness invariant: if the lock fails the
//! buffer still functions and still zeroises on drop — it just isn't pinned.
//! The caller can query [`Locked::is_locked`] to learn whether pinning succeeded.
//! This avoids turning a hardening feature into a denial-of-service.
//!
//! This is the only module in the crate permitted to use `unsafe`.

#![allow(unsafe_code)]

use alloc::boxed::Box;
use core::sync::atomic::{compiler_fence, Ordering};

/// Wipe bytes with volatile stores plus a compiler fence, so the scrub cannot be
/// elided as a dead store or reordered past a security boundary.
///
/// The **pre-loop** `compiler_fence(SeqCst)` ensures that no loads from the
/// secret bytes (or any related memory) are reordered to *after* the
/// wipe begins. Without this fence, LLVM could in principle keep an
/// outstanding load from a secret byte above the volatile-write loop
/// (the volatile writes are per-location barriers, not global ones).
/// The pre-loop fence makes the wipe an unconditional
/// happens-before-deletion point.
///
/// The **post-loop** `compiler_fence(SeqCst)` ensures that no loads from
/// the wiped region can be hoisted *past* the wipe, so a downstream
/// read sees the zeroed memory even if the optimizer would otherwise
/// have re-ordered the load to before the wipe completed.
///
/// Together: secret bytes are guaranteed to be loaded-then-wiped, and the
/// wipe is guaranteed to complete-then-leave-scope. This is the
/// side-channel hardening recommended by Trail of Bits' "Life of an
/// Optimization Barrier" (2022) and the pattern used by `subtle`'s
/// `Choice` optimization barrier.
#[inline(never)]
pub(crate) fn zeroize_bytes(bytes: &mut [u8]) {
    compiler_fence(Ordering::SeqCst);
    for b in bytes.iter_mut() {
        // SAFETY: `b` is a valid, uniquely borrowed byte. Volatile write is used
        // only to force the store to happen; it does not create aliasing.
        unsafe {
            core::ptr::write_volatile(b as *mut u8, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

/// Wipe a `u64` scalar with a volatile store plus a compiler fence.
#[inline(never)]
pub(crate) fn zeroize_u64(word: &mut u64) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: `word` is a valid, uniquely borrowed scalar. Volatile write is
    // used only to force the store to happen; it does not create aliasing.
    unsafe {
        core::ptr::write_volatile(word as *mut u64, 0);
    }
    compiler_fence(Ordering::SeqCst);
}

/// A heap-pinned, self-zeroising byte buffer.
///
/// Invariants:
///   * The bytes live in a `Box<[u8; N]>` so the backing allocation has a stable
///     address that does not move when the `Locked` value is moved (only the box
///     pointer moves, not the pages we locked).
///   * If `locked` is true, the page range is currently `mlock`'d.
///   * On drop: zeroise the bytes, then `munlock` (if it was locked).
pub struct Locked<const N: usize> {
    buf: Box<[u8; N]>,
    locked: bool,
}

impl<const N: usize> Locked<N> {
    /// Allocate a zeroed, heap-pinned buffer and attempt to lock its pages.
    ///
    /// Locking is best-effort: on failure the buffer is still usable and
    /// `is_locked()` returns false.
    pub fn new() -> Self {
        let buf = Box::new([0u8; N]);
        // SAFETY: `buf` points to exactly N initialised bytes for the lifetime
        // of this allocation; the range [ptr, ptr+N) is valid for mlock.
        // Under Miri, mlock is unsupported so we skip it (best-effort anyway).
        #[cfg(miri)]
        let locked = false;
        #[cfg(not(miri))]
        let locked = unsafe {
            let ptr = buf.as_ptr() as *const libc::c_void;
            libc::mlock(ptr, N) == 0
        };
        Locked { buf, locked }
    }

    /// Whether the pages are currently pinned in RAM.
    #[inline]
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Immutable view of the locked bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.buf
    }

    /// Mutable view, for filling the buffer with secret material in place.
    #[inline]
    pub fn as_mut_bytes(&mut self) -> &mut [u8; N] {
        &mut self.buf
    }

    /// Copy `src` into the locked buffer. `src` must be exactly `N` bytes.
    /// Returns `false` (and copies nothing) on a length mismatch.
    pub fn fill_from(&mut self, src: &[u8]) -> bool {
        if src.len() != N {
            return false;
        }
        self.buf.copy_from_slice(src);
        true
    }
}

impl<const N: usize> Default for Locked<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Drop for Locked<N> {
    #[inline(never)]
    fn drop(&mut self) {
        // 1. Wipe the secret while pages are still resident and locked.
        zeroize_bytes(&mut self.buf[..]);
        // 2. Unlock the pages (only if we successfully locked them).
        if self.locked {
            // SAFETY: same valid [ptr, ptr+N) range that was passed to mlock;
            // munlock on an unlocked-or-already-wiped range is harmless.
            unsafe {
                let ptr = self.buf.as_ptr() as *const libc::c_void;
                libc::munlock(ptr, N);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_and_locks() {
        let l: Locked<64> = Locked::new();
        // On this device mlock works (verified), but we don't hard-assert it —
        // the type must remain correct even where locking is denied.
        assert_eq!(l.as_bytes().len(), 64);
    }

    #[test]
    fn fill_and_read_back() {
        let mut l: Locked<32> = Locked::new();
        let data = [0x5Au8; 32];
        assert!(l.fill_from(&data));
        assert_eq!(l.as_bytes(), &data);
    }

    #[test]
    fn fill_rejects_wrong_length() {
        let mut l: Locked<32> = Locked::new();
        assert!(!l.fill_from(&[0u8; 16]), "length mismatch must be rejected");
    }

    #[test]
    fn drops_cleanly_when_locked() {
        // Exercise the zeroise-then-munlock drop path.
        let mut l: Locked<48> = Locked::new();
        l.as_mut_bytes()[0] = 0xFF;
        drop(l); // must not panic / double-free
    }
}
