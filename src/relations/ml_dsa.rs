//! ML-DSA relation — knowledge of an ML-DSA-65 signing key (libcrux backend).
//!
//! This wraps the lattice signature scheme (FIPS 204) as a [`Relation`], proving
//! the engine's verification core is genuinely *universal*: a completely
//! different cryptographic family (module-lattice signatures) flows through the
//! exact same trait and the same `prove_and_verify` pipeline as the pure-hash
//! [`super::hash_preimage`] relation.
//!
//! ## What is proven
//! Knowledge of a 32-byte seed `w` whose derived ML-DSA-65 verifying key is the
//! statement `x`. The proof is an ML-DSA signature over a Fiat-Shamir challenge
//! that is itself bound to the verifying key via the [`Transcript`]:
//!
//!   kp = MLDSA.KeyGen(w)              (libcrux, formally verified)
//!   x  = kp.verification_key
//!   c  = Transcript(PROTO).absorb("vk", x_bytes).challenge()
//!   π  = MLDSA.Sign(kp.signing_key, c, ctx, randomness)
//!
//! Verification recomputes `c` from `x` and checks the signature. Because the
//! signed message is the transcript challenge (bound to `x`), a valid signature
//! demonstrates possession of the signing key for that exact verifying key.
//!
//! ## Backend
//! Uses **libcrux** (hax/F* formally verified) for all ML-DSA operations:
//! key generation, signing, and verification. No RustCrypto dependencies.
//!
//! ## Status
//! Research/educational composition over formally verified libcrux primitives.

use crate::common::{Transcript, VeilError};
use crate::l0_memlock::zeroize_bytes;
use crate::pq_backends::libcrux_backend;
use crate::relations::Relation;

use libcrux_ml_dsa::ml_dsa_65::{MLDSA65Signature, MLDSA65VerificationKey};

use crate::shake256::Shake256;
use core::sync::atomic::{compiler_fence, Ordering};
use subtle::Choice;

/// Protocol label binding the transcript to this relation.
const PROTO: &[u8] = b"veil7:relation:ml-dsa-65-knowledge:v1";
/// ML-DSA signing context (FIPS 204 ctx field) — extra domain separation.
const CTX: &[u8] = b"veil7:rel:mldsa:ctx:v1";

/// Public statement: the ML-DSA-65 verifying key (raw bytes).
pub struct Statement {
    pub vk: MLDSA65VerificationKey,
}

/// Secret witness: the 32-byte seed from which the signing key is derived.
pub struct Witness {
    pub seed: [u8; 32],
}

impl Drop for Witness {
    #[inline(never)]
    fn drop(&mut self) {
        zeroize_bytes(&mut self.seed);
    }
}

/// The proof: an ML-DSA signature over the transcript challenge.
pub struct Proof {
    pub sig: MLDSA65Signature,
}

impl Drop for Proof {
    #[inline(never)]
    fn drop(&mut self) {
        zeroize_bytes(self.sig.as_mut_slice());
    }
}

/// Derive deterministic signing randomness from the seed and challenge.
///
/// libcrux's `ml_dsa_65::sign` requires a 32-byte randomness parameter
/// (unlike RustCrypto's `sign_deterministic`). We derive it deterministically
/// from the seed + challenge via SHAKE256 to maintain the deterministic
/// proof property (same seed → same proof).
fn derive_signing_randomness(seed: &[u8; 32], challenge: &[u8; 32]) -> [u8; 32] {
    let mut xof = Shake256::default();
    xof.update(b"veil7:rel:mldsa:sig-randomness:v1");
    xof.update(seed);
    xof.update(challenge);
    let mut out = [0u8; 32];
    let mut reader = xof.finalize_xof();
    let _ = reader.read(&mut out);
    out
}

/// Derive the Fiat-Shamir challenge message bound to the verifying key.
fn challenge_for(stmt: &Statement) -> [u8; 32] {
    let mut t = Transcript::new(PROTO);
    HashChallenge::bind(stmt, &mut t);
    t.challenge_array(b"mldsa:challenge")
}

/// Internal helper so `bind_statement` and `challenge_for` stay in sync.
struct HashChallenge;
impl HashChallenge {
    fn bind(stmt: &Statement, t: &mut Transcript) {
        t.absorb(b"mldsa:vk", stmt.vk.as_slice());
    }
}

/// The relation marker type.
pub struct MlDsaKnowledge;

impl Relation for MlDsaKnowledge {
    type Statement = Statement;
    type Witness = Witness;
    type Proof = Proof;

    fn protocol_label() -> &'static [u8] {
        PROTO
    }

    fn statement_from_witness(witness: &Witness) -> Statement {
        let kp = libcrux_backend::dsa_keygen(witness.seed);
        Statement {
            vk: kp.verification_key,
        }
    }

    fn bind_statement(stmt: &Statement, t: &mut Transcript) {
        HashChallenge::bind(stmt, t);
    }

    fn prove(
        witness: &Witness,
        _entropy: &[u8], // deterministic: randomness derived from seed + challenge
    ) -> Result<(Statement, Proof), VeilError> {
        let kp = libcrux_backend::dsa_keygen(witness.seed);
        let stmt = Statement {
            vk: kp.verification_key,
        };
        let msg = challenge_for(&stmt);
        let sig_randomness = derive_signing_randomness(&witness.seed, &msg);

        let sig = libcrux_backend::dsa_sign(&kp.signing_key, &msg, CTX, sig_randomness)?;

        Ok((stmt, Proof { sig }))
    }

    fn verify(stmt: &Statement, proof: &Proof) -> Result<Choice, VeilError> {
        let msg = challenge_for(stmt);
        let result = libcrux_backend::dsa_verify(&stmt.vk, &msg, CTX, &proof.sig);

        // Side-channel hardening: fence around the Choice conversion.
        compiler_fence(Ordering::SeqCst);
        let c = Choice::from(result.is_ok() as u8);
        compiler_fence(Ordering::SeqCst);
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn honest_proof_verifies() {
        let w = Witness { seed: [0x21u8; 32] };
        let (stmt, proof) = MlDsaKnowledge::prove(&w, &[]).unwrap();
        let ok = MlDsaKnowledge::verify(&stmt, &proof).unwrap();
        assert_eq!(ok.unwrap_u8(), 1, "honest ML-DSA proof must verify");
    }

    #[test]
    fn wrong_statement_fails() {
        let (_, proof) = MlDsaKnowledge::prove(&Witness { seed: [0x21u8; 32] }, &[]).unwrap();
        let other = MlDsaKnowledge::statement_from_witness(&Witness { seed: [0x99u8; 32] });
        let ok = MlDsaKnowledge::verify(&other, &proof).unwrap();
        assert_eq!(
            ok.unwrap_u8(),
            0,
            "proof must not validate under another vk"
        );
    }

    #[test]
    fn deterministic_statement() {
        let s1 = MlDsaKnowledge::statement_from_witness(&Witness { seed: [5u8; 32] });
        let s2 = MlDsaKnowledge::statement_from_witness(&Witness { seed: [5u8; 32] });
        assert_eq!(
            s1.vk.as_slice(),
            s2.vk.as_slice(),
            "keygen is deterministic"
        );
    }

    #[test]
    fn deterministic_proof() {
        let w = Witness { seed: [0x42u8; 32] };
        let (_, p1) = MlDsaKnowledge::prove(&w, &[]).unwrap();
        let (_, p2) = MlDsaKnowledge::prove(&w, &[]).unwrap();
        assert_eq!(
            p1.sig.as_slice(),
            p2.sig.as_slice(),
            "same seed must produce identical signatures"
        );
    }
}
