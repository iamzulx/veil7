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
        let mut xof = Shake256::default();
        xof.update(domain::TRANSCRIPT);
        xof.update(statement_digest);
        let mut transcript = [0u8; 32];
        let mut reader = xof.finalize_xof();
        reader.read(&mut transcript);
        Verdict { valid, transcript }
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
            "Verdict {{ valid: {}, transcript: {} }}",
            self.valid.unwrap_u8(),
            hex32(&self.transcript)
        )
    }
}

/// Lowercase hex of a 32-byte array, no allocation beyond the fixed buffer.
fn hex32(b: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for &byte in b.iter() {
        s.push(HEX[(byte >> 4) as usize] as char);
        s.push(HEX[(byte & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l1_entropy::harvest;
    use crate::l2_keygen::derive_keys;
    use crate::l3_commit::commit;

    #[test]
    fn verdict_carries_bit_and_hash() {
        let seed = harvest(b"l7").unwrap();
        let keys = derive_keys(&seed).unwrap();
        let c = commit(&keys, b"claim");
        let v = Verdict::new(Choice::from(1u8), &c);
        assert!(v.is_valid_bool());
        assert_eq!(v.transcript().len(), 32);
    }

    #[test]
    fn debug_is_metadata_free() {
        let seed = harvest(b"l7d").unwrap();
        let keys = derive_keys(&seed).unwrap();
        let c = commit(&keys, b"claim");
        let v = Verdict::new(Choice::from(0u8), &c);
        let s = format!("{:?}", v);
        assert!(s.contains("valid: 0"));
        assert!(s.contains("transcript:"));
    }
}
