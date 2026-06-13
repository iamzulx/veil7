//! L7 — Traceless Emission.
//!
//! The only thing that leaves the engine. A `Verdict` carries:
//!   * `valid: Choice` — one bit, constant-time (1 = verified, 0 = not).
//!   * `transcript: [u8; 32]` — a SHAKE256 hash binding the verdict to the
//!     commitment, so a caller can correlate a verdict to the claim THEY hold
//!     without the engine storing or emitting the claim, keys, or any ID.
//!
//! Explicitly absent (by construction — there is no field to hold them):
//!   * No timestamp, no sequence number, no session/request ID.
//!   * No key material, no signature, no claim plaintext.
//!   * No error detail beyond the opaque `VeilError` (which never reaches L7 on
//!     the success path).
//!
//! `Debug` is implemented by hand to print only the bit and a fixed-width hash,
//! never anything that could vary as a fingerprint.

use crate::domain;
use crate::l3_commit::Commitment;

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use subtle::Choice;

use core::fmt::Write;
use core::sync::atomic::{compiler_fence, Ordering};

/// The metadata-free result of one verification iteration.
pub struct Verdict {
    /// Constant-time validity bit.
    valid: Choice,
    /// 32-byte transcript hash bound to the commitment.
    transcript: [u8; 32],
}

impl Verdict {
    /// Construct a verdict from the validity choice and the commitment.
    pub(crate) fn new(valid: Choice, commitment: &Commitment) -> Self {
        // Side-channel hardening: `Choice` is supposed to be CT but
        // dalek-cryptography/subtle documents it as "best-effort"
        // (CVE-2026-23519 showed LLVM may optimize cmov into bne
        // on ARM Cortex-M0 — different arch than ours but the
        // principle applies). We add a compiler fence before the
        // constructor so the `Choice` is observable across the
        // function boundary as the optimizer's barrier put it
        // there, and not as some compiler-internal value that
        // got folded.
        compiler_fence(Ordering::SeqCst);
        // SIDE-CHANNEL: T-table Keccak. Absorbs only public commitment bytes.
        // See SPEC-HARDENING.md §"Cache timing and T-table side channels".
        // Risk class: LOW (public input).
        let mut xof = Shake256::default();
        xof.update(domain::TRANSCRIPT);
        xof.update(commitment.as_bytes());
        let mut transcript = [0u8; 32];
        let mut reader = xof.finalize_xof();
        reader.read(&mut transcript);
        Verdict { valid, transcript }
    }

    /// Construct a verdict bound to an arbitrary 32-byte statement digest.
    ///
    /// Used by the generic relation pipeline: the digest is a public commitment
    /// to the statement (carries no secret), so the verdict can be correlated to
    /// the claim the caller holds without the engine emitting any metadata.
    pub(crate) fn from_statement_digest(valid: Choice, statement_digest: &[u8; 32]) -> Self {
        // Same hardening as `new`: a fence before the Choice field is
        // written into the struct, to keep `valid` observable across
        // the constructor boundary.
        compiler_fence(Ordering::SeqCst);
        // SIDE-CHANNEL: T-table Keccak. Absorbs only public statement_digest
        // bytes. See SPEC-HARDENING.md §"Cache timing and T-table side
        // channels". Risk class: LOW (public input).
        let mut xof = Shake256::default();
        xof.update(domain::TRANSCRIPT);
        xof.update(statement_digest);
        let mut transcript = [0u8; 32];
        let mut reader = xof.finalize_xof();
        reader.read(&mut transcript);
        Verdict { valid, transcript }
    }

    /// Construct a batch verdict from an aggregated validity choice and
    /// a pre-computed 32-byte batch transcript.
    ///
    /// Used by `verify_batch`: the batch transcript is a SHAKE256 fold of
    /// individual verdict transcripts, so it uniquely identifies the claim
    /// set without per-claim metadata.
    #[cfg(feature = "std")]
    pub(crate) fn from_batch(valid: Choice, batch_transcript: &[u8; 32]) -> Self {
        compiler_fence(Ordering::SeqCst);
        Verdict {
            valid,
            transcript: *batch_transcript,
        }
    }

    /// Was the claim verified? Returns a constant-time `Choice`.
    #[inline]
    pub fn is_valid(&self) -> Choice {
        self.valid
    }

    /// Convenience boolean. Note: collapsing to `bool` is a deliberate caller
    /// choice — the engine itself never branches on this internally.
    #[inline]
    pub fn is_valid_bool(&self) -> bool {
        self.valid.unwrap_u8() == 1
    }

    /// The transcript hash. Public, carries no secret and no metadata.
    #[inline]
    pub fn transcript(&self) -> &[u8; 32] {
        &self.transcript
    }
}

impl core::fmt::Debug for Verdict {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Only the bit and the hash. Nothing time-varying or identifying.
        write!(
            f,
            "Verdict {{ valid: {}, transcript: ",
            self.valid.unwrap_u8()
        )?;
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for &byte in self.transcript.iter() {
            f.write_char(HEX[(byte >> 4) as usize] as char)?;
            f.write_char(HEX[(byte & 0x0f) as usize] as char)?;
        }
        write!(f, " }}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l1_entropy::Seed;
    use crate::l2_keygen::derive_keys;
    use crate::l3_commit::commit;

    fn fake_seed() -> Seed {
        Seed::from_bytes(&[0xA5u8; 64])
    }

    #[test]
    fn verdict_carries_bit_and_hash() {
        let seed = fake_seed();
        let keys = derive_keys(&seed).unwrap();
        let c = commit(&keys, b"claim");
        let v = Verdict::new(Choice::from(1u8), &c);
        assert!(v.is_valid_bool());
        assert_eq!(v.transcript().len(), 32);
    }

    #[test]
    fn debug_is_metadata_free() {
        let seed = fake_seed();
        let keys = derive_keys(&seed).unwrap();
        let c = commit(&keys, b"claim");
        let v = Verdict::new(Choice::from(0u8), &c);
        let s = alloc::format!("{:?}", v);
        assert!(s.contains("valid: 0"));
        assert!(s.contains("transcript:"));
    }
}
