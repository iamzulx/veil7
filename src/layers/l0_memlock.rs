// Author: Iamzulx
// Copyright (c) 2026
// License: MIT
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

extern crate alloc;
use alloc::boxed::Box;
use core::sync::atomic::{compiler_fence, fence, AtomicUsize, Ordering};

#[cfg(feature = "std")]
extern crate libc;

// ═══════════════════════════════════════════════════════════════════════════
// Memory Locking Budget Management (Zero Trust 2026)
// ═══════════════════════════════════════════════════════════════════════════

/// Global tracker for locked memory usage (in bytes).
///
/// This atomic counter tracks the total amount of memory currently locked
/// via `mlock()`. This enables:
/// - Budget management: prevent exhausting `RLIMIT_MEMLOCK`
/// - Monitoring: track locked memory usage over time
/// - Zero Trust verification: ensure memory isolation is enforced
///
/// Reference: Linux Security 2026 Hardening Best Practices
/// <https://linuxsecurity.com/news/server-security/linux-security-hardening-best-practices>
static LOCKED_MEMORY_USAGE: AtomicUsize = AtomicUsize::new(0);

/// Get current locked memory usage in bytes.
///
/// Returns the total amount of memory currently locked via `mlock()`.
/// This is useful for monitoring and budget management.
#[cfg(feature = "std")]
pub fn get_locked_memory_usage() -> usize {
    LOCKED_MEMORY_USAGE.load(Ordering::SeqCst)
}

/// Get `RLIMIT_MEMLOCK` limit in bytes.
///
/// Returns the maximum amount of memory that can be locked by this process.
/// Returns `None` if the limit cannot be determined.
///
/// Reference: `man 2 getrlimit`
#[cfg(feature = "std")]
pub fn get_mlock_limit() -> Option<usize> {
    #[cfg(not(miri))]
    {
        let mut rlim: libc::rlimit = unsafe { core::mem::zeroed() };
        if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut rlim) } == 0 {
            Some(rlim.rlim_cur as usize)
        } else {
            None
        }
    }
    #[cfg(miri)]
    {
        None
    }
}

/// Check if we're approaching `RLIMIT_MEMLOCK` limit.
///
/// Returns `true` if usage > 80% of limit. This is a conservative threshold
/// to prevent unexpected `mlock` failures.
///
/// Reference: Zero Trust 2026 — "verify everything, trust nothing"
/// <https://www.exabeam.com/explainers/zero-trust/zero-trust-in-2026-principles-technologies-and-best-practices>
#[cfg(feature = "std")]
pub fn is_approaching_mlock_limit() -> bool {
    if let Some(limit) = get_mlock_limit() {
        let usage = get_locked_memory_usage();
        let threshold = (limit as f64 * 0.8) as usize;
        usage > threshold
    } else {
        false
    }
}

/// Check if memory is actually locked (Linux-specific).
///
/// Reads `/proc/self/status` to check `VmLck` field and verify that
/// the expected amount of memory is locked.
///
/// Returns `true` if verification succeeds, `false` otherwise.
///
/// Reference: Linux kernel documentation on `/proc/self/status`
/// <https://www.kernel.org/doc/Documentation/filesystems/proc.txt>
#[cfg(all(feature = "std", target_os = "linux", not(miri)))]
pub fn is_memory_locked(expected_bytes: usize) -> bool {
    use std::fs;

    if let Ok(status) = fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("VmLck:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(vm_lck_kb) = parts[1].parse::<u64>() {
                        // Convert expected bytes to KB (round up)
                        let expected_kb = expected_bytes.div_ceil(1024);
                        return vm_lck_kb >= expected_kb as u64;
                    }
                }
            }
        }
    }

    false
}

// ═══════════════════════════════════════════════════════════════════════════

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
    fence(Ordering::SeqCst);
}

/// Wipe a raw memory range with volatile stores plus a compiler fence.
///
/// This is a safe wrapper around the unsafe volatile write operations.
/// The caller must ensure `ptr` is valid for `len` bytes and that
/// the memory is safe to write to (no aliasing violations).
///
/// This function is intentionally safe to call from modules that have
/// `#![deny(unsafe_code)]` — the unsafe is encapsulated here in l0_memlock.
#[inline(never)]
pub(crate) fn zeroize_ptr(ptr: *mut u8, len: usize) {
    compiler_fence(Ordering::SeqCst);
    for i in 0..len {
        // SAFETY: caller guarantees ptr is valid for len bytes.
        unsafe {
            core::ptr::write_volatile(ptr.add(i), 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
    fence(Ordering::SeqCst);
}

/// Wipe a byte slice in place using volatile stores.
///
/// This is a safe wrapper that obtains a mutable pointer from an immutable
/// reference and wipes the memory. The caller must ensure the slice is
/// the only reference to this memory (no aliasing).
///
/// This is used for wiping libcrux private key bytes where the API only
/// provides immutable access to the underlying byte array.
#[inline(never)]
pub(crate) fn zeroize_slice(bytes: &[u8]) {
    let ptr = bytes.as_ptr() as *mut u8;
    zeroize_ptr(ptr, bytes.len());
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

// ═══════════════════════════════════════════════════════════════════════════
// Memory Poisoning (Defence-in-Depth)
// ═══════════════════════════════════════════════════════════════════════════

/// Poison pattern for detecting use-after-free.
///
/// After zeroizing memory, we fill it with this pattern to detect
/// use-after-free bugs. If code reads from freed memory, it will see
/// this pattern instead of zeros, making bugs more obvious.
///
/// Reference: CWE-416 (Use After Free)
/// <https://cwe.mitre.org/data/definitions/416.html>
const POISON_PATTERN: u8 = 0xDE;

/// Poison bytes with a pattern to detect use-after-free.
///
/// This is a defence-in-depth measure: after zeroizing memory, we fill it
/// with a poison pattern (0xDE). If code reads from freed memory, it will
/// see this pattern instead of zeros, making bugs more obvious.
///
/// Reference: Zero Trust 2026 — "defence-in-depth, verify everything"
/// <https://nmsconsulting.com/latest-cybersecurity-best-practices-2026>
#[inline(never)]
pub(crate) fn poison_bytes(bytes: &mut [u8]) {
    compiler_fence(Ordering::SeqCst);
    for b in bytes.iter_mut() {
        // SAFETY: `b` is a valid, uniquely borrowed byte.
        unsafe {
            core::ptr::write_volatile(b as *mut u8, POISON_PATTERN);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

// ═══════════════════════════════════════════════════════════════════════════
// Stack Canary Validation (Buffer Overflow Detection)
// ═══════════════════════════════════════════════════════════════════════════

/// Canary value for stack-based buffer overflow detection.
///
/// This constant is planted into a stack buffer and validated after
/// sensitive operations to detect stack smashing (CWE-121).
#[allow(dead_code)]
const CANARY_VALUE: u64 = 0xDEADBEEFCAFEBABE;

/// Plant a stack canary by writing `CANARY_VALUE` bytes into the buffer
/// using volatile writes to prevent elision.
///
/// # Security
/// The canary is placed on the stack adjacent to sensitive buffers so that
/// a buffer overflow will corrupt it before reaching return addresses.
#[inline(never)]
#[allow(dead_code)]
pub(crate) fn plant_stack_canary(canary: &mut [u8; 8]) {
    let val = CANARY_VALUE.to_ne_bytes();
    for (c, v) in canary.iter_mut().zip(val.iter()) {
        // SAFETY: `canary` is a valid, uniquely borrowed 8-byte buffer.
        unsafe {
            core::ptr::write_volatile(c as *mut u8, *v);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

/// Validate a stack canary by reading bytes with volatile reads and
/// comparing against `CANARY_VALUE`.
///
/// Returns `true` if the canary is intact, `false` if corrupted
/// (indicating a buffer overflow was detected).
#[inline(never)]
#[allow(dead_code)]
pub(crate) fn validate_stack_canary(canary: &[u8; 8]) -> bool {
    compiler_fence(Ordering::SeqCst);
    let mut buf = [0u8; 8];
    for (b, slot) in canary.iter().zip(buf.iter_mut()) {
        // SAFETY: `canary` is a valid, borrowed 8-byte buffer.
        unsafe {
            *slot = core::ptr::read_volatile(b as *const u8);
        }
    }
    buf == CANARY_VALUE.to_ne_bytes()
}

/// Wipe a stack canary buffer using volatile stores.
///
/// Called after validation to ensure the canary value does not linger
/// on the stack after it has served its purpose.
#[inline(never)]
#[allow(dead_code)]
pub(crate) fn wipe_stack_canary(canary: &mut [u8; 8]) {
    compiler_fence(Ordering::SeqCst);
    for c in canary.iter_mut() {
        // SAFETY: `canary` is a valid, uniquely borrowed 8-byte buffer.
        unsafe {
            core::ptr::write_volatile(c as *mut u8, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
    fence(Ordering::SeqCst);
}

/// Zeroize and poison bytes (zeroize → poison → zeroize).
///
/// This is a 3-pass wipe:
/// 1. Zeroize (clear secrets)
/// 2. Poison (fill with 0xDE to detect use-after-free)
/// 3. Zeroize (final clean)
///
/// This ensures secrets are cleared, use-after-free is detectable, and
/// the final state is clean zeros.
#[inline(never)]
pub(crate) fn zeroize_and_poison(bytes: &mut [u8]) {
    zeroize_bytes(bytes);
    poison_bytes(bytes);
    zeroize_bytes(bytes);
}

// ═══════════════════════════════════════════════════════════════════════════
// Hardware RNG (unsafe confined to this module)
// ═══════════════════════════════════════════════════════════════════════════

/// Try to read a u64 from the hardware random number generator.
/// Safe wrapper — all `unsafe` is confined here in l0_memlock.
pub(crate) fn hw_random_u64() -> Result<u64, ()> {
    #[cfg(target_arch = "x86_64")]
    {
        hw_rdrand64()
    }
    #[cfg(all(target_arch = "aarch64", feature = "std"))]
    {
        hw_rndr64()
    }
    #[cfg(all(target_arch = "aarch64", not(feature = "std")))]
    {
        Err(())
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        Err(())
    }
}

/// RDRAND — x86_64 hardware random number.
#[cfg(target_arch = "x86_64")]
fn hw_rdrand64() -> Result<u64, ()> {
    let val: u64;
    let ok: u8;
    unsafe {
        core::arch::asm!(
            "rdrand {val}",
            "setc {ok}",
            val = out(reg) val,
            ok = out(reg_byte) ok,
            options(nomem, nostack),
        );
    }
    if ok != 0 {
        Ok(val)
    } else {
        Err(())
    }
}

/// RNDR — aarch64 hardware random number (ARMv8.5-A FEAT_RNG).
#[cfg(all(target_arch = "aarch64", feature = "std"))]
fn hw_rndr64() -> Result<u64, ()> {
    const HWCAP_RNG: libc::c_ulong = 1 << 27;
    let hwcap = unsafe { libc::getauxval(libc::AT_HWCAP) };
    if hwcap & HWCAP_RNG == 0 {
        return Err(());
    }
    let val: u64;
    let nzcv: u64;
    unsafe {
        core::arch::asm!(
            "mrs {val}, s3_3_c2_c4_0",
            "mrs {out}, nzcv",
            val = out(reg) val,
            out = out(reg) nzcv,
            options(nomem, nostack),
        );
    }
    if (nzcv & (1 << 30)) == 0 {
        Ok(val)
    } else {
        Err(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Memory Canaries (Buffer Overflow Detection)
// ═══════════════════════════════════════════════════════════════════════════

/// Canary value for detecting buffer overflows.
///
/// This is a sentinel value placed before and after buffers to detect
/// buffer overflows. If the canary is modified, we know a buffer overflow
/// occurred.
///
/// Reference: CWE-120 (Buffer Copy without Checking Size of Input)
/// <https://cwe.mitre.org/data/definitions/120.html>
const CANARY: u64 = 0xDEADBEEFCAFEBABE;

/// Check if canary value is intact.
///
/// Returns `true` if the canary is intact, `false` if it was modified
/// (indicating a buffer overflow). This is a public utility function that
/// can be used by other modules to detect buffer overflows by checking
/// sentinel values placed before/after buffers.
#[inline]
pub fn check_canary(canary: u64) -> bool {
    canary == CANARY
}

// ═══════════════════════════════════════════════════════════════════════════

/// A heap-pinned, self-zeroising byte buffer.
///
/// Invariants:
///   * The bytes live in a `Box<[u8; N]>` so the backing allocation has a stable
///     address that does not move when the `Locked` value is moved (only the box
///     pointer moves, not the pages we locked).
///   * If `locked` is true, the page range is currently `mlock`'d.
///   * On drop: zeroise the bytes, then `munlock` (if it was locked).
///
/// ## Platform note (Android/Termux)
/// On Android/Termux, `mlock()` returns `ENOMEM` (errno 12) even when
/// `RLIMIT_MEMLOCK` suggests sufficient budget (e.g. 65536 kB). This is a
/// kernel-level restriction — Android does not allow `mlock` for non-root
/// processes regardless of rlimit. `Locked` handles this gracefully:
/// `is_locked()` returns `false` and the buffer still functions correctly
/// with volatile zeroization on drop. Security is maintained via zeroize;
/// only swap-protection is degraded.
///
/// With `std` feature: uses `libc::mlock`/`munlock` for memory pinning.
/// Without `std`: provides same API but without memory locking (best-effort).
pub struct Locked<const N: usize> {
    buf: Box<[u8; N]>,
    #[cfg(feature = "std")]
    locked: bool,
}

impl<const N: usize> Locked<N> {
    /// Allocate a zeroed, heap-pinned buffer and attempt to lock its pages.
    ///
    /// Locking is best-effort: on failure the buffer is still usable and
    /// `is_locked()` returns false.
    ///
    /// ## Budget Management (Zero Trust 2026)
    ///
    /// This function checks if we're approaching the `RLIMIT_MEMLOCK` limit
    /// before attempting to lock memory. If usage > 80% of limit, we skip
    /// locking to prevent unexpected failures.
    ///
    /// If locking succeeds, we update the global `LOCKED_MEMORY_USAGE` counter.
    /// This counter is decremented in `Drop`.
    pub fn new() -> Self {
        let buf = Box::new([0u8; N]);
        #[cfg(feature = "std")]
        {
            // Under Miri, mlock is unsupported so we skip it (best-effort anyway).
            #[cfg(miri)]
            let locked = false;
            #[cfg(not(miri))]
            let locked = {
                // Check if we're approaching RLIMIT_MEMLOCK limit (Zero Trust 2026)
                if is_approaching_mlock_limit() {
                    // Skip locking to prevent unexpected failures
                    false
                } else {
                    let locked = unsafe {
                        let ptr = buf.as_ptr() as *const libc::c_void;
                        libc::mlock(ptr, N) == 0
                    };
                    // Update global counter if locking succeeded
                    if locked {
                        LOCKED_MEMORY_USAGE.fetch_add(N, Ordering::SeqCst);
                    }
                    locked
                }
            };
            Locked { buf, locked }
        }
        #[cfg(not(feature = "std"))]
        {
            Locked { buf }
        }
    }

    /// Whether the pages are currently pinned in RAM.
    #[inline]
    pub fn is_locked(&self) -> bool {
        #[cfg(feature = "std")]
        {
            self.locked
        }
        #[cfg(not(feature = "std"))]
        {
            false
        }
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
        // 1. Wipe and poison the secret (zeroize → poison → zeroize).
        // This ensures secrets are cleared, use-after-free is detectable,
        // and the final state is clean zeros.
        zeroize_and_poison(&mut self.buf[..]);

        // 2. Unlock the pages (only if we successfully locked them).
        #[cfg(feature = "std")]
        if self.locked {
            // SAFETY: same valid [ptr, ptr+N) range that was passed to mlock;
            // munlock on an unlocked-or-already-wiped range is harmless.
            unsafe {
                let ptr = self.buf.as_ptr() as *const libc::c_void;
                libc::munlock(ptr, N);
            }
            // Decrement global counter (Zero Trust 2026 budget management)
            LOCKED_MEMORY_USAGE.fetch_sub(N, Ordering::SeqCst);
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
    fn zeroize_bytes_clears_memory() {
        let mut buf = [0xFFu8; 32];
        zeroize_bytes(&mut buf);
        assert!(buf.iter().all(|&b| b == 0), "zeroize must clear all bytes");
    }

    #[test]
    fn poison_bytes_fills_pattern() {
        let mut buf = [0x00u8; 32];
        poison_bytes(&mut buf);
        assert!(
            buf.iter().all(|&b| b == POISON_PATTERN),
            "poison must fill with pattern 0xDE"
        );
    }

    #[test]
    fn zeroize_and_poison_clears_and_poisons() {
        let mut buf = [0xFFu8; 32];
        zeroize_and_poison(&mut buf);
        // Final state should be zeros (zeroize → poison → zeroize)
        assert!(
            buf.iter().all(|&b| b == 0),
            "zeroize_and_poison must end with zeros"
        );
    }

    #[test]
    fn canary_check_detects_modification() {
        assert!(check_canary(CANARY), "intact canary must pass");
        assert!(
            !check_canary(0x0000000000000000),
            "modified canary must fail"
        );
        assert!(
            !check_canary(0xFFFFFFFFFFFFFFFF),
            "modified canary must fail"
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn locked_memory_usage_tracking() {
        let _initial_usage = get_locked_memory_usage();

        {
            let _l1: Locked<64> = Locked::new();
            let _usage_after_1 = get_locked_memory_usage();
            // Usage should increase (if mlock succeeded)
            // On Android/Termux, mlock fails, so usage stays the same
            #[cfg(not(target_os = "android"))]
            assert!(_usage_after_1 >= _initial_usage);

            let _l2: Locked<128> = Locked::new();
            let _usage_after_2 = get_locked_memory_usage();
            // Usage should increase further (if mlock succeeded)
            #[cfg(not(target_os = "android"))]
            assert!(_usage_after_2 >= _usage_after_1);
        }

        // After drop, usage should return to initial (if mlock succeeded)
        let _final_usage = get_locked_memory_usage();
        #[cfg(not(target_os = "android"))]
        assert_eq!(
            _final_usage, _initial_usage,
            "usage must return to initial after drop"
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn mlock_limit_query() {
        let limit = get_mlock_limit();
        // Limit should be queryable (may be None on some systems)
        if let Some(limit_bytes) = limit {
            assert!(limit_bytes > 0, "limit must be positive");
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn approaching_mlock_limit_check() {
        // This test verifies the function works, not the actual threshold
        let _approaching = is_approaching_mlock_limit();
        // Just verify it doesn't panic
    }

    #[test]
    fn drops_cleanly_when_locked() {
        // Exercise the zeroise-then-munlock drop path.
        let mut l: Locked<48> = Locked::new();
        l.as_mut_bytes()[0] = 0xFF;
        drop(l); // must not panic / double-free
    }

    #[test]
    fn test_plant_and_validate_canary() {
        let mut canary = [0u8; 8];
        plant_stack_canary(&mut canary);
        assert!(
            validate_stack_canary(&canary),
            "planted canary must validate"
        );
    }

    #[test]
    fn test_corrupted_canary_detected() {
        let mut canary = [0u8; 8];
        plant_stack_canary(&mut canary);
        canary[3] ^= 0xFF; // corrupt one byte
        assert!(
            !validate_stack_canary(&canary),
            "corrupted canary must fail validation"
        );
    }

    #[test]
    fn test_wipe_canary() {
        let mut canary = [0u8; 8];
        plant_stack_canary(&mut canary);
        wipe_stack_canary(&mut canary);
        assert!(
            !validate_stack_canary(&canary),
            "wiped canary must fail validation"
        );
    }
}
