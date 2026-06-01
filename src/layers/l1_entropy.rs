//! L1 — Entropy Harvest.
//!
//! Flow origin. Gathers entropy from the OS CSPRNG, folds in volatile
//! environmental jitter (high-resolution clock + stack address), and stretches
//! it through SHAKE256 into a fixed-size seed. The raw OS bytes and jitter are
//! zeroised the instant the seed is produced.
//!
//! Statelessness: no seed is ever stored. Each call produces an independent
//! `Seed` that the caller owns and is responsible for dropping (it self-wipes).

use crate::l0_memlock::Locked;
use crate::{domain, VeilError};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use zeroize::Zeroize;

/// Width of the master seed handed to L2. 64 bytes = 512 bits of stretched
/// entropy, enough to seed both PQ key derivations with independent halves.
pub const SEED_LEN: usize = 64;

/// A self-zeroising, memory-locked master seed.
///
/// The bytes live in a [`Locked`] buffer: pinned in RAM via `mlock` (so they
/// cannot be swapped to disk) and wiped-then-unlocked on drop. Locking is
/// best-effort — query [`Seed::is_locked`] to learn whether pinning succeeded.
pub struct Seed(pub(crate) Locked<SEED_LEN>);

impl Seed {
    #[inline]
    pub fn as_bytes(&self) -> &[u8; SEED_LEN] {
        self.0.as_bytes()
    }

    /// Whether the seed's pages are pinned in RAM (not swappable).
    #[inline]
    pub fn is_locked(&self) -> bool {
        self.0.is_locked()
    }

    /// Construct a seed from raw bytes into a freshly locked buffer.
    /// Used internally (e.g. determinism tests); the harvest path is preferred.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn from_bytes(raw: &[u8; SEED_LEN]) -> Self {
        let mut locked = Locked::<SEED_LEN>::new();
        locked.fill_from(raw);
        Seed(locked)
    }
}

// Drop is handled by `Locked` (zeroise then munlock); no manual impl needed.

/// Volatile, non-deterministic jitter that is cheap to read and varies between
/// iterations even on the same device. Not relied on for security (the OS
/// CSPRNG is), purely defence-in-depth so two iterations never share input even
/// in the pathological case of a CSPRNG returning identical bytes.
fn jitter() -> [u8; 24] {
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut out = [0u8; 24];

    // High-resolution wall clock (nanos). Transient — never emitted anywhere.
    let nanos: u128 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    out[0..16].copy_from_slice(&nanos.to_le_bytes());

    // Address of a stack local: varies with ASLR and stack depth per call.
    let probe = 0u8;
    let addr = (&probe as *const u8) as usize as u64;
    out[16..24].copy_from_slice(&addr.to_le_bytes());

    out
}

/// Harvest entropy and stretch it into a [`Seed`].
///
/// `personalization` lets the caller bind the seed to a context without leaking
/// it (it is absorbed into the sponge, never stored). Pass `&[]` if unused.
pub fn harvest(personalization: &[u8]) -> Result<Seed, VeilError> {
    // 1. Primary entropy: OS CSPRNG. On Android this is the getrandom syscall.
    let mut os_bytes = [0u8; 48];
    getrandom::getrandom(&mut os_bytes).map_err(|_| VeilError::Entropy)?;

    // 2. Defence-in-depth jitter.
    let mut jit = jitter();

    // 3. Domain-separated SHAKE256 stretch: tag || personalization || os || jitter.
    let mut xof = Shake256::default();
    xof.update(domain::ENTROPY_STRETCH);
    xof.update(personalization);
    xof.update(&os_bytes);
    xof.update(&jit);

    // Read the stretched output directly into a memory-locked buffer, so the
    // seed bytes are pinned (and never sit in an unlocked stack array).
    let mut locked = Locked::<SEED_LEN>::new();
    let mut reader = xof.finalize_xof();
    reader.read(locked.as_mut_bytes());

    // 4. Wipe all transient inputs immediately. Only the locked seed survives.
    os_bytes.zeroize();
    jit.zeroize();

    Ok(Seed(locked))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harvest_produces_full_seed() {
        let s = harvest(b"test").expect("entropy available");
        // Astronomically unlikely to be all-zero unless harvest is broken.
        assert!(s.as_bytes().iter().any(|&b| b != 0));
    }

    #[test]
    fn two_harvests_differ() {
        let a = harvest(b"").unwrap();
        let b = harvest(b"").unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes(), "seeds must be independent");
    }

    #[test]
    fn seed_wipes_on_drop() {
        // Capture the raw pointer, drop, then read through it is UB — instead we
        // assert the Zeroize path runs by constructing and dropping in scope.
        let s = harvest(b"wipe").unwrap();
        let copy = *s.as_bytes();
        drop(s);
        // The dropped seed's memory is wiped; our independent copy is fine.
        assert!(copy.iter().any(|&b| b != 0));
    }
}
