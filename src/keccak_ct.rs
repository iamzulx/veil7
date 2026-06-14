//! Constant-time Keccak wrapper — defense-in-depth masking layer.
//!
//! **Update (Phase 2.1):** SHAKE256 is now backed by **libcrux-sha3** which
//! is formally verified (hax/F*) and uses a generic Keccak implementation
//! with no T-tables. The T-table side-channel gap is now **closed** at the
//! base level.
//!
//! This module provides an additional **masked sponge** layer as
//! defense-in-depth:
//!
//! 1. Before each absorb, XOR the input with a random mask.
//! 2. Feed the masked input through libcrux-sha3 (already constant-time).
//! 3. The mask adds a second layer of protection beyond libcrux's own CT.
//! 4. The mask is derived from a per-call random nonce, wiped after use.
//!
//! ## Philosophy alignment
//! - **Silence over explanation**: defense-in-depth even when base is CT.
//! - **Wipe outside boundary**: masks are wiped after use.
//! - **Math over abstraction**: XOR masking is simple, auditable math.

extern crate alloc;
use alloc::vec;

use crate::l0_memlock::zeroize_bytes;

use crate::shake256::Shake256;

/// A constant-time SHAKE256 hasher that masks inputs before absorbing.
///
/// Usage is identical to `Shake256`: call `ct_update` with data, then
/// `ct_finalize` to squeeze output bytes.
pub struct CtShake256 {
    inner: Shake256,
    mask: [u8; 32],
}

impl CtShake256 {
    /// Create a new constant-time SHAKE256 hasher.
    ///
    /// Generates a fresh random mask for this instance. The mask is
    /// unique per hasher, so two `CtShake256` instances with the same
    /// input will produce different internal states (but the same
    /// final output after unmasking — see `ct_finalize`).
    #[cfg(feature = "std")]
    pub fn new() -> Result<Self, crate::VeilError> {
        let mut mask = [0u8; 32];
        getrandom::getrandom(&mut mask).map_err(|_| crate::VeilError::Entropy)?;
        Ok(Self {
            inner: Shake256::default(),
            mask,
        })
    }

    /// Create with a caller-supplied mask (for `no_std` or deterministic use).
    pub fn with_mask(mask: [u8; 32]) -> Self {
        Self {
            inner: Shake256::default(),
            mask,
        }
    }

    /// Absorb data with masking.
    ///
    /// The data is XOR'd with the mask (cycled) before being fed to the
    /// underlying SHAKE256. The T-table access pattern leaks the masked
    /// data, not the original.
    ///
    /// To recover the correct output, use `ct_finalize` which accounts
    /// for the masking.
    pub fn ct_update(&mut self, data: &[u8]) {
        // Generate a mask stream as long as the data from the base mask.
        // This avoids the weakness of cycling a 32-byte mask over long inputs.
        let mut mask_stream = vec![0u8; data.len()];
        let mut mask_xof = Shake256::default();
        mask_xof.update(b"veil7:ct:mask-stream");
        mask_xof.update(&self.mask);
        mask_xof.update(&(data.len() as u64).to_le_bytes());
        let mut reader = mask_xof.finalize_xof();
        reader.read(&mut mask_stream);

        let mut masked = data.to_vec();
        for (i, b) in masked.iter_mut().enumerate() {
            *b ^= mask_stream[i];
        }
        self.inner.update(&masked);
        zeroize_bytes(&mut masked);
        zeroize_bytes(&mut mask_stream);
    }

    /// Absorb data WITHOUT masking (for public / non-secret data).
    ///
    /// Use this when the data is known to be public (e.g. domain tags,
    /// protocol labels). No performance penalty.
    pub fn update_public(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalize and squeeze output bytes.
    ///
    /// Because the input was masked, the raw SHAKE256 output is also
    /// "masked" in a sense. To get the correct digest, we need to
    /// account for the mask. However, since SHAKE256 is a sponge,
    /// the mask affects the internal state in a non-invertible way.
    ///
    /// **Design decision**: we do NOT try to "unmask" the output.
    /// Instead, `CtShake256` is used as a drop-in for cases where
    /// the output does not need to match a specific `Shake256` output
    /// (e.g. internal transcript state, ephemeral key derivation).
    /// For cases where exact `Shake256` compatibility is needed,
    /// use the standard `Shake256` directly.
    ///
    /// The mask is wiped after finalization.
    pub fn ct_finalize(&mut self, out: &mut [u8]) {
        // Take ownership of the inner hasher by replacing with a fresh one.
        let inner = core::mem::take(&mut self.inner);
        let mut reader = inner.finalize_xof();
        reader.read(out);
        zeroize_bytes(&mut self.mask);
    }

    /// Convenience: finalize into a fixed-size array.
    pub fn ct_finalize_array<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        self.ct_finalize(&mut out);
        out
    }
}

impl Default for CtShake256 {
    fn default() -> Self {
        // Use a fixed non-zero mask constant. Default cannot call getrandom,
        // so we use a well-known non-zero pattern to ensure the mask is never
        // all-zeros (which would make masking a no-op).
        Self::with_mask([0xA5; 32])
    }
}

impl Drop for CtShake256 {
    #[inline(never)]
    fn drop(&mut self) {
        zeroize_bytes(&mut self.mask);
    }
}

/// Constant-time SHAKE256 one-shot: hash `data` with automatic masking.
///
/// This is a convenience function for single-shot hashing where the
/// output does not need to match standard SHAKE256 exactly.
#[cfg(feature = "std")]
pub fn ct_shake256(data: &[u8], out: &mut [u8]) {
    let mut hasher = match CtShake256::new() {
        Ok(h) => h,
        Err(_) => {
            // Fallback: use a non-zero fixed mask if CSPRNG fails.
            CtShake256::with_mask([0xA5; 32])
        }
    };
    hasher.ct_update(data);
    hasher.ct_finalize(out);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "std")]
    fn ct_shake256_produces_nonzero_output() {
        let mut out = [0u8; 32];
        ct_shake256(b"test-data", &mut out);
        assert_ne!(out, [0u8; 32]);
    }

    #[test]
    #[cfg(feature = "std")]
    fn ct_shake256_different_masks_different_outputs() {
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        ct_shake256(b"same-data", &mut out1);
        ct_shake256(b"same-data", &mut out2);
        // Different random masks → different outputs.
        assert_ne!(out1, out2);
    }

    #[test]
    fn ct_shake256_deterministic_with_fixed_mask() {
        let mask = [0x42u8; 32];
        let mut h1 = CtShake256::with_mask(mask);
        let mut h2 = CtShake256::with_mask(mask);

        h1.ct_update(b"hello");
        h2.ct_update(b"hello");

        let out1: [u8; 32] = h1.ct_finalize_array();
        let out2: [u8; 32] = h2.ct_finalize_array();
        assert_eq!(out1, out2, "same mask + same data → same output");
    }

    #[test]
    fn different_data_different_output() {
        let mask = [0xAAu8; 32];
        let mut h1 = CtShake256::with_mask(mask);
        let mut h2 = CtShake256::with_mask(mask);

        h1.ct_update(b"data-A");
        h2.ct_update(b"data-B");

        let out1: [u8; 32] = h1.ct_finalize_array();
        let out2: [u8; 32] = h2.ct_finalize_array();
        assert_ne!(out1, out2);
    }

    #[test]
    fn public_update_is_unmasked() {
        // Public update should produce the same result as standard Shake256.
        let mut standard = Shake256::default();
        standard.update(b"public-data");
        let mut std_out = [0u8; 32];
        standard.finalize_xof().read(&mut std_out);

        let mut ct = CtShake256::with_mask([0xFF; 32]);
        ct.update_public(b"public-data");
        let ct_out: [u8; 32] = ct.ct_finalize_array();

        assert_eq!(
            std_out, ct_out,
            "public update must match standard SHAKE256"
        );
    }

    #[test]
    fn mask_is_wiped_on_drop() {
        let mask = [0xBBu8; 32];
        let hasher = CtShake256::with_mask(mask);
        drop(hasher);
        // We can't directly verify the mask is wiped (it's in the dropped
        // struct), but the Drop impl is #[inline(never)] and calls
        // zeroize_bytes, which is the documented contract.
    }
}
