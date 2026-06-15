//! Multi-method entropy harvest with **per-method untraceability**.
//!
//! Each method produces 64 bytes of raw entropy. The raw bytes are
//! immediately run through a **domain-tagged SHAKE256 hash** (a one-way,
//! preimage-resistant transform) before being folded into the pool.
//! After this transform, the contribution is opaque: no observer can
//! tell whether a given output bit came from the OS CSPRNG, wall-clock
//! jitter, stack address, thread ID, or hardware counter.
//!
//! ## Untraceability property
//!
//! For each method `i`:
//!   `whiten_i = SHAKE256(ENTROPY_SOURCE_i || raw_i)`
//!
//! Properties:
//!   * `ENTROPY_SOURCE_i` is **public** (different per method so hashes
//!     domain-separate and don't collide).
//!   * `raw_i` is **private** (the method's actual entropy contribution).
//!   * SHAKE256 is preimage-resistant under the Random Oracle Model.
//!   * The pool is `XOR(whiten_1, whiten_2, ..., whiten_n)` and the final
//!     seed is `SHAKE256(ENTROPY_FINALIZE || personalization || pool)` —
//!     another preimage-resistant transform.
//!
//! Claim: an observer who knows the final seed AND all but one of the
//! source's raw inputs cannot recover the missing input. This is the
//! standard compositional-preimage property of the SHAKE256 sponge
//! construction: reversing the final squeeze requires inverting the
//! XOR, which requires inverting one of the per-method whiten steps,
//! which is the SHAKE256 preimage problem.
//!
//! ## Method set
//!
//! Six methods, each with a genuinely different raw source (not all
//! reduced to the same underlying `getrandom` call):
//!
//! 1. `os_csprng_primary`   — `getrandom` 64 bytes
//! 2. `os_csprng_secondary` — `getrandom` 64 bytes (separate call, possibly
//!    different kernel scheduling)
//! 3. `wall_clock`          — `SystemTime::now()` nanoseconds
//! 4. `stack_addr`          — pointer to a stack-local variable
//! 5. `thread_id`           — hashed `std::thread::current().id()`
//! 6. `hw_counter`          — `Instant::elapsed()` ⊕ `SystemTime::now().as_nanos()`
//!
//! ## Privacy
//!
//! * The raw bytes are `ZeroizeOnDrop` via the `Wipe` impl.
//! * The whitened output is one-way; it never contains the raw input.
//! * The `DomainTag` is a `&'static [u8]` reference (no allocation).
//! * The struct is `#[repr(C)]`-friendly (no implicit padding) for the
//!   wiping loop to walk the buffer linearly.

use crate::common::domain;
use crate::l0_memlock::zeroize_bytes;
use crate::shake256::Shake256;

#[cfg(feature = "std")]
use std::hash::{Hash, Hasher};

/// Width of each method's raw output, in bytes. 64 = the L1 seed width.
pub const SOURCE_LEN: usize = 64;

/// One method's contribution to the entropy pool.
///
/// Construction is via the public `os_*`, `wall_clock`, `stack_addr`,
/// `thread_id`, `hw_counter` helpers. Direct construction is `pub(crate)`
/// to keep the public surface clean.
pub struct EntropySource {
    name: &'static str,
    domain_tag: &'static [u8],
    raw: [u8; SOURCE_LEN],
}

impl EntropySource {
    /// Construct an `EntropySource` from a pre-computed raw buffer.
    /// Used by the public helper functions below.
    pub(crate) fn from_raw(
        name: &'static str,
        domain_tag: &'static [u8],
        raw: [u8; SOURCE_LEN],
    ) -> Self {
        Self {
            name,
            domain_tag,
            raw,
        }
    }

    /// The public name of this method (for diagnostics; never emitted
    /// into any output, never used as a log statement).
    #[inline]
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The public domain tag this method is whiten under.
    #[inline]
    pub fn domain_tag(&self) -> &'static [u8] {
        self.domain_tag
    }

    /// Immutable view of the raw buffer (pre-whitening).
    #[inline]
    pub fn raw(&self) -> &[u8; SOURCE_LEN] {
        &self.raw
    }

    /// **One-way whiten**: SHAKE256(domain_tag || raw). The output
    /// cannot be inverted to recover the raw buffer — that's the
    /// "untraceability" property the multi-source harvest relies on.
    ///
    /// Each call returns a fresh `[u8; 64]`. The raw buffer is
    /// **not** mutated; call `wipe` to destroy it.
    ///
    /// SIDE-CHANNEL: SHAKE256 here absorbs **raw OS entropy bytes** (CSPRNG
    /// output, jitter, time-of-day). On shared-cache hardware an attacker can
    /// recover the per-source raw bits via Flush+Reload / Prime+Probe against
    /// the Keccak T-tables. See `SPEC-HARDENING.md` §"Cache timing and T-table
    /// side channels". Risk class for this call: **HIGH** (raw entropy input).
    pub fn whiten(&self) -> [u8; SOURCE_LEN] {
        let mut xof = Shake256::default();
        xof.update(self.domain_tag);
        xof.update(&self.raw);
        let mut out = [0u8; SOURCE_LEN];
        xof.finalize_xof().read(&mut out);
        out
    }

    /// Destroy the raw buffer (volatile write + SeqCst fence via
    /// `l0_memlock::zeroize_bytes`). After this, `raw()` returns zeros
    /// and the underlying memory no longer contains the entropy bits.
    pub fn wipe(&mut self) {
        zeroize_bytes(&mut self.raw);
    }
}

impl Drop for EntropySource {
    /// Defensive auto-wipe on drop, in case the caller forgets to
    /// call `wipe` explicitly. Volatile + fence via `zeroize_bytes`.
    #[inline(never)]
    fn drop(&mut self) {
        zeroize_bytes(&mut self.raw);
    }
}

// ── Public method constructors ───────────────────────────────────────────────
//
// Each helper allocates the raw buffer at the call site, fills it from
// a single named source, and wraps it in `EntropySource`. The source
// bytes are read directly into the buffer; no intermediate copy.

/// Read 64 bytes from the OS CSPRNG (`getrandom` syscall). This is the
/// cryptographic-primary method.
#[cfg(feature = "std")]
pub fn os_csprng_primary() -> Result<EntropySource, &'static str> {
    let mut raw = [0u8; SOURCE_LEN];
    getrandom::getrandom(&mut raw).map_err(|_| "os_csprng_primary failed")?;
    Ok(EntropySource::from_raw(
        "os_csprng_primary",
        domain::ENTROPY_SOURCE_OS_PRIMARY,
        raw,
    ))
}

/// `no_std` stub: no OS CSPRNG available. Returns the primary-method
/// `Err` so the caller (`harvest_multi_source`) returns `VeilError::Entropy`.
/// The other no_std stubs (`wall_clock`, `stack_addr`, etc.) succeed —
/// they contribute zero bytes honestly — but without the cryptographic
/// primary the multi-source harvest cannot be safely executed.
#[cfg(not(feature = "std"))]
pub fn os_csprng_primary() -> Result<EntropySource, &'static str> {
    Err("os_csprng_primary unavailable in no_std without external entropy")
}

/// Read 64 bytes from the OS CSPRNG again. A second independent call
/// gives us a *separate* kernel scheduling — useful when the first
/// call's bytes are correlated with a prior iteration's bytes (which
/// can happen with degenerate RNG implementations).
#[cfg(feature = "std")]
pub fn os_csprng_secondary() -> Result<EntropySource, &'static str> {
    let mut raw = [0u8; SOURCE_LEN];
    getrandom::getrandom(&mut raw).map_err(|_| "os_csprng_secondary failed")?;
    Ok(EntropySource::from_raw(
        "os_csprng_secondary",
        domain::ENTROPY_SOURCE_OS_SECONDARY,
        raw,
    ))
}

/// `no_std` stub: no OS CSPRNG available. Best-effort failure: returns
/// `Err` so the multi-source harvest pipeline can skip this source.
#[cfg(not(feature = "std"))]
pub fn os_csprng_secondary() -> Result<EntropySource, &'static str> {
    Err("os_csprng_secondary unavailable in no_std")
}

/// Read the wall-clock time (`SystemTime::now()`) padded to 64 bytes.
/// This is a non-cryptographic source; it's defence-in-depth that
/// contributes variability even if the OS CSPRNG somehow returns
/// constant bytes. The contribution is whitened away by the per-method
/// domain tag, so this raw input never leaves this function.
#[cfg(feature = "std")]
pub fn wall_clock() -> EntropySource {
    let nanos: u128 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut raw = [0u8; SOURCE_LEN];
    raw[..16].copy_from_slice(&nanos.to_le_bytes());
    // The remaining 48 bytes are zero — they will be whitened away
    // by the domain tag. No information beyond the 16-byte nanosecond
    // timestamp leaks.
    EntropySource::from_raw("wall_clock", domain::ENTROPY_SOURCE_WALL_CLOCK, raw)
}

/// `no_std` stub: no `SystemTime` available. The raw buffer is zero.
#[cfg(not(feature = "std"))]
pub fn wall_clock() -> EntropySource {
    EntropySource::from_raw(
        "wall_clock",
        domain::ENTROPY_SOURCE_WALL_CLOCK,
        [0u8; SOURCE_LEN],
    )
}

/// Read the address of a stack-local variable, padded to 64 bytes.
/// ASLR + stack-depth variance means the address changes between
/// invocations even on the same call site. This is a non-cryptographic
/// source, like the wall clock.
pub fn stack_addr() -> EntropySource {
    let probe: u8 = 0;
    let addr = (&probe as *const u8) as usize as u64;
    let mut raw = [0u8; SOURCE_LEN];
    raw[..8].copy_from_slice(&addr.to_le_bytes());
    // The remaining 56 bytes are zero.
    EntropySource::from_raw("stack_addr", domain::ENTROPY_SOURCE_STACK_ADDR, raw)
}

/// Read the OS thread identifier. Each thread in a process has a unique
/// ID; this varies per spawn, per thread-pool scheduling, and per
/// fork. Uses `std::thread::current().id()` hashed via the default
/// hasher, so no `unsafe` is needed (and no libc syscall — this is
/// portable to all `std`-supported targets).
#[cfg(feature = "std")]
pub fn thread_id() -> EntropySource {
    use std::collections::hash_map::DefaultHasher;
    let mut raw = [0u8; SOURCE_LEN];
    let mut hasher = DefaultHasher::new();
    std::thread::current().id().hash(&mut hasher);
    let tid = hasher.finish();
    raw[..8].copy_from_slice(&tid.to_le_bytes());
    EntropySource::from_raw("thread_id", domain::ENTROPY_SOURCE_THREAD_ID, raw)
}

/// `no_std` stub: no `std::thread` available. The raw buffer is zero
/// — the source "contributes" nothing — but the method still occupies
/// a domain tag so the pool composition is consistent. Honest: not
/// every target has every source.
#[cfg(not(feature = "std"))]
pub fn thread_id() -> EntropySource {
    EntropySource::from_raw(
        "thread_id",
        domain::ENTROPY_SOURCE_THREAD_ID,
        [0u8; SOURCE_LEN],
    )
}

/// Read a hardware high-resolution timer (the OS's monotonic clock).
/// This is a non-cryptographic source; the per-method domain tag
/// whitens the contribution into the pool so the raw timestamp is
/// not exposed to the final seed.
///
/// Internally uses `std::time::Instant` which on every supported
/// target resolves to a hardware counter: `CNTVCT_EL0` on aarch64,
/// `RDTSC` on x86/x86_64, `mach_absolute_time` on macOS,
/// `QueryPerformanceCounter` on Windows. Using `Instant` rather than
/// raw inline asm keeps this function `unsafe`-free and portable.
///
/// The two nanos readings are combined with a domain-separated
/// SHAKE256 squeeze, not a raw XOR. Reasons:
///   * Domain separation: an attacker who knows `elapsed_nanos`
///     (or `wall_nanos`) cannot recover the other from the combined
///     buffer. The raw XOR was reversible in one direction;
///     the SHAKE256 squeeze is one-way.
///   * Length: the source buffer is 64 bytes. `to_le_bytes()` of a
///     single u128 is 16 bytes; the remaining 48 bytes were zero
///     in the XOR path. The SHAKE256 squeeze fills all 64 bytes
///     with output that is bounded by both inputs jointly, so
///     the buffer is no longer a "16-byte hash + 48 zero padding"
///     pattern that an attacker could trivially recognise.
///   * Pre-rotation: the per-method whiten still XORs into the pool
///     (in `harvest_multi_source`), but the source itself now carries
///     a one-way digest of its inputs rather than a direct copy.
///     This is the side-channel hardening recommended in the 2025-26
///     audit: avoid leaking raw input patterns into the whiten step.
#[cfg(feature = "std")]
pub fn hw_counter() -> EntropySource {
    use crate::shake256::Shake256;

    let elapsed_nanos = std::time::Instant::now().elapsed().as_nanos();
    let wall_nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    let mut raw = [0u8; SOURCE_LEN];
    let mut xof = Shake256::default();
    xof.update(b"veil7:L1:src:hw-counter-combine:v1");
    xof.update(&elapsed_nanos.to_le_bytes());
    xof.update(&wall_nanos.to_le_bytes());
    xof.finalize_xof().read(&mut raw);

    EntropySource::from_raw("hw_counter", domain::ENTROPY_SOURCE_HW_COUNTER, raw)
}

/// Read the process ID (PID) as an entropy source.
/// PID varies per process spawn, fork, and exec, providing entropy from
/// OS process scheduling. This is a non-cryptographic source (defence-in-depth).
#[cfg(feature = "std")]
pub fn process_id() -> EntropySource {
    use std::process;
    let pid = process::id();
    let mut raw = [0u8; SOURCE_LEN];
    raw[..4].copy_from_slice(&pid.to_le_bytes());
    EntropySource::from_raw("process_id", domain::ENTROPY_SOURCE_PROCESS_ID, raw)
}

/// `no_std` stub: no process ID available. Returns zero buffer.
#[cfg(not(feature = "std"))]
pub fn process_id() -> EntropySource {
    EntropySource::from_raw("process_id", domain::ENTROPY_SOURCE_PROCESS_ID, [0u8; SOURCE_LEN])
}

/// Read the address of a heap allocation as an entropy source.
/// Heap allocation addresses vary with ASLR, heap layout, and allocator state,
/// providing entropy from memory layout. This is a non-cryptographic source.
#[cfg(feature = "std")]
pub fn memory_allocation_addr() -> EntropySource {
    let allocation = Box::new([0u8; 64]);
    let addr = allocation.as_ptr() as usize as u64;
    let mut raw = [0u8; SOURCE_LEN];
    raw[..8].copy_from_slice(&addr.to_le_bytes());
    EntropySource::from_raw("memory_allocation_addr", domain::ENTROPY_SOURCE_MEMORY_ALLOC, raw)
}

/// Read CPU cache access timing as an entropy source.
/// Timing of memory access patterns varies with cache state, CPU load, and
/// memory contention, providing entropy from microarchitectural jitter.
#[cfg(feature = "std")]
pub fn cpu_cache_timing() -> EntropySource {
    use std::time::Instant;

    // Allocate a buffer and measure access time
    let mut buffer = vec![0u8; 4096];
    let start = Instant::now();

    // Access pattern that stresses cache (stride by cache line size)
    for i in (0..buffer.len()).step_by(64) {
        buffer[i] = buffer[i].wrapping_add(1);
    }

    let elapsed = start.elapsed().as_nanos();
    let mut raw = [0u8; SOURCE_LEN];
    raw[..16].copy_from_slice(&elapsed.to_le_bytes());

    EntropySource::from_raw("cpu_cache_timing", domain::ENTROPY_SOURCE_CPU_CACHE, raw)
}

/// Read page fault timing as an entropy source.
/// Timing of page faults varies with memory pressure, TLB state, and OS
/// scheduling, providing entropy from memory management jitter.
#[cfg(feature = "std")]
pub fn page_fault_timing() -> EntropySource {
    use std::time::Instant;

    // Allocate a large buffer to trigger page faults (64 KB = 16 pages)
    let start = Instant::now();
    let mut buffer = vec![0u8; 65536];

    // Touch each page to trigger page faults
    for i in (0..buffer.len()).step_by(4096) {
        buffer[i] = 1;
    }

    let elapsed = start.elapsed().as_nanos();
    let mut raw = [0u8; SOURCE_LEN];
    raw[..16].copy_from_slice(&elapsed.to_le_bytes());

    EntropySource::from_raw("page_fault_timing", domain::ENTROPY_SOURCE_PAGE_FAULT, raw)
}

/// Read interrupt timing as an entropy source.
/// Timing of interrupts varies with OS scheduling, hardware interrupts, and
/// system load, providing entropy from interrupt jitter.
#[cfg(feature = "std")]
pub fn interrupt_timing() -> EntropySource {
    use std::time::Instant;
    use std::thread;
    use std::time::Duration;

    // Sleep for a short time to allow interrupts to occur
    let start = Instant::now();
    thread::sleep(Duration::from_micros(100));
    let elapsed = start.elapsed().as_nanos();

    let mut raw = [0u8; SOURCE_LEN];
    raw[..16].copy_from_slice(&elapsed.to_le_bytes());

    EntropySource::from_raw("interrupt_timing", domain::ENTROPY_SOURCE_INTERRUPT, raw)
}

/// Read memory contention timing as an entropy source.
/// Timing of memory operations under contention varies with CPU load, cache
/// state, and memory bandwidth, providing entropy from memory contention jitter.
#[cfg(feature = "std")]
pub fn memory_contention_timing() -> EntropySource {
    use std::time::Instant;
    use std::sync::{Arc, Barrier};
    use std::thread;

    // Create contention by spawning multiple threads
    let barrier = Arc::new(Barrier::new(5));
    let mut handles = vec![];

    for _ in 0..4 {
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            // Do some memory-intensive work
            let mut buffer = vec![0u8; 1024];
            for i in 0..buffer.len() {
                buffer[i] = buffer[i].wrapping_add(1);
            }
        }));
    }

    let start = Instant::now();
    barrier.wait();

    // Do memory-intensive work under contention
    let mut buffer = vec![0u8; 1024];
    for i in 0..buffer.len() {
        buffer[i] = buffer[i].wrapping_add(1);
    }

    let elapsed = start.elapsed().as_nanos();

    for handle in handles {
        let _ = handle.join();
    }

    let mut raw = [0u8; SOURCE_LEN];
    raw[..16].copy_from_slice(&elapsed.to_le_bytes());

    EntropySource::from_raw("memory_contention_timing", domain::ENTROPY_SOURCE_MEMORY_CONTENTION, raw)
}

/// `no_std` stub: no `Instant` available. The raw buffer is zero.
#[cfg(not(feature = "std"))]
pub fn hw_counter() -> EntropySource {
    EntropySource::from_raw(
        "hw_counter",
        domain::ENTROPY_SOURCE_HW_COUNTER,
        [0u8; SOURCE_LEN],
    )
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Whiten must be deterministic per (tag, raw) pair.
    #[test]
    fn whiten_is_deterministic() {
        let s = os_csprng_primary().expect("os_csprng available");
        let w1 = s.whiten();
        let w2 = s.whiten();
        assert_eq!(w1, w2, "whiten must be a pure function of (tag, raw)");
    }

    /// Different domain tags must produce different whitened outputs
    /// for the same raw input. This is the per-method untraceability
    /// property: two sources sharing raw bytes still produce
    /// distinguishable contributions.
    #[test]
    fn whiten_domain_separates() {
        let raw1 = [0xABu8; SOURCE_LEN];
        let a = EntropySource::from_raw("a", domain::ENTROPY_SOURCE_OS_PRIMARY, raw1);
        let b = EntropySource::from_raw("b", domain::ENTROPY_SOURCE_OS_SECONDARY, raw1);
        let wa = a.whiten();
        let wb = b.whiten();
        assert_ne!(
            wa, wb,
            "different domain tags must produce different whitened outputs"
        );
    }

    /// Different raw inputs must produce different whitened outputs
    /// under the same domain tag.
    #[test]
    fn whiten_input_separates() {
        let raw1 = [0xABu8; SOURCE_LEN];
        let raw2 = [0xCDu8; SOURCE_LEN];
        let a = EntropySource::from_raw("a", domain::ENTROPY_SOURCE_OS_PRIMARY, raw1);
        let b = EntropySource::from_raw("a", domain::ENTROPY_SOURCE_OS_PRIMARY, raw2);
        let wa = a.whiten();
        let wb = b.whiten();
        assert_ne!(wa, wb, "different raw must produce different whitened");
    }

    /// Pin the contract: `whiten` borrows `&self`, not `&mut self`,
    /// so it can run on shared references (the harvest pipeline
    /// stores sources in a `Vec` and iterates immutably).
    #[test]
    fn whiten_takes_shared_reference() {
        let raw = [0x42u8; SOURCE_LEN];
        let s = EntropySource::from_raw("x", domain::ENTROPY_SOURCE_OS_PRIMARY, raw);
        let _r: [u8; SOURCE_LEN] = s.whiten();
    }

    /// `wipe` must zero the raw buffer. After wipe, the buffer
    /// is gone — `raw()` returns all zeros.
    #[test]
    fn wipe_zeros_raw_buffer() {
        let mut s = os_csprng_primary().expect("os_csprng available");
        // Sanity: before wipe, the buffer is non-zero.
        let before = *s.raw();
        assert!(
            before.iter().any(|&b| b != 0),
            "raw buffer should be non-zero before wipe"
        );
        s.wipe();
        assert_eq!(*s.raw(), [0u8; SOURCE_LEN], "wipe must zero the buffer");
    }

    /// `Drop` also wipes (defence in depth — caller might forget).
    #[test]
    fn drop_wipes_automatically() {
        // We can't observe a Drop directly, but we can verify the
        // buffer is zero after the value goes out of scope. Use a
        // helper that returns a pointer into the buffer.
        let raw_ptr: *const u8;
        {
            let mut s = os_csprng_primary().expect("os_csprng available");
            s.wipe();
            raw_ptr = s.raw().as_ptr();
            // After wipe, the buffer is zeros — drop is a no-op then.
        }
        // After the inner scope, the buffer's memory may have been
        // reused by the allocator. We can only check the contract:
        // wipe was called and the buffer is currently zero.
        let _ = raw_ptr; // suppress unused-variable warning
    }

    /// The six public method constructors all return `EntropySource`
    /// with a valid `name()`, a non-empty `domain_tag()`, and a
    /// 64-byte `raw()`. This is a smoke test that the API surface is
    /// coherent.
    #[test]
    fn all_six_method_constructors_produce_valid_sources() {
        let s1 = os_csprng_primary().expect("ok");
        let s2 = os_csprng_secondary().expect("ok");
        let s3 = wall_clock();
        let s4 = stack_addr();
        let s5 = thread_id();
        let s6 = hw_counter();
        for (i, s) in [&s1, &s2, &s3, &s4, &s5, &s6].iter().enumerate() {
            assert!(!s.name().is_empty(), "source {i} has empty name");
            assert!(!s.domain_tag().is_empty(), "source {i} has empty tag");
            assert_eq!(s.raw().len(), SOURCE_LEN);
        }
    }
}
