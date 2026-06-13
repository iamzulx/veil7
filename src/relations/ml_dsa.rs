//! ML-DSA relation — knowledge of an ML-DSA-65 signing key.
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
//!   sk = MLDSA.KeyGen(w)
//!   x  = sk.verifying_key()
//!   c  = Transcript(PROTO).absorb("vk", encode(x)).challenge()
//!   π  = MLDSA.Sign_deterministic(sk, c, ctx)
//!
//! Verification recomputes `c` from `x` and checks the signature. Because the
//! signed message is the transcript challenge (bound to `x`), a valid signature
//! demonstrates possession of the signing key for that exact verifying key.
//!
//! ## Status
//! Research/educational composition over audited RustCrypto primitives. The
//! ML-DSA primitive itself is the upstream implementation; the proof-of-knowledge
//! framing around it is unaudited.

use crate::common::{Transcript, VeilError};
use crate::l0_memlock::zeroize_bytes;
use crate::relations::Relation;

use ml_dsa::{KeyInit as _, Keypair as _, MlDsa65, Signature, SigningKey, VerifyingKey};
use ml_kem::array::Array; // shared hybrid-array type used to build the 32-byte seed

use core::sync::atomic::{compiler_fence, Ordering};
use subtle::Choice;

/// Protocol label binding the transcript to this relation.
const PROTO: &[u8] = b"veil7:relation:ml-dsa-65-knowledge:v1";
/// ML-DSA signing context (FIPS 204 ctx field) — extra domain separation.
const CTX: &[u8] = b"veil7:rel:mldsa:ctx:v1";

/// Public statement: the ML-DSA-65 verifying key.
pub struct Statement {
    pub vk: VerifyingKey<MlDsa65>,
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
    pub sig: Signature<MlDsa65>,
}

/// Build an ML-DSA-65 signing key from a 32-byte seed.
fn signing_key_from_seed(seed: &[u8; 32]) -> Result<SigningKey<MlDsa65>, VeilError> {
    let seed_arr: ml_dsa::B32 = Array::try_from(&seed[..]).map_err(|_| VeilError::Crypto)?;
    Ok(SigningKey::<MlDsa65>::new(&seed_arr))
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
        let enc = stmt.vk.encode();
        t.absorb(b"mldsa:vk", enc.as_slice());
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
        // If the seed is malformed we cannot build a key; fall back to a key from
        // a zeroed seed. This path is unreachable for the fixed 32-byte witness,
        // but we avoid panicking to keep the engine oracle-free.
        let sk = signing_key_from_seed(&witness.seed)
            .unwrap_or_else(|_| SigningKey::<MlDsa65>::new(&Array::default()));
        Statement {
            vk: sk.verifying_key(),
        }
    }

    fn bind_statement(stmt: &Statement, t: &mut Transcript) {
        HashChallenge::bind(stmt, t);
    }

    fn prove(
        witness: &Witness,
        _entropy: &[u8], // ML-DSA deterministic signing: entropy not required
    ) -> Result<(Statement, Proof), VeilError> {
        let sk = signing_key_from_seed(&witness.seed)?;
        let stmt = Statement {
            vk: sk.verifying_key(),
        };
        let msg = challenge_for(&stmt);
        let sig = sk
            .expanded_key()
            .sign_deterministic(&msg, CTX)
            .map_err(|_| VeilError::Crypto)?;
        Ok((stmt, Proof { sig }))
    }

    fn verify(stmt: &Statement, proof: &Proof) -> Result<Choice, VeilError> {
        let msg = challenge_for(stmt);
        let ok = stmt.vk.verify_with_context(&msg, CTX, &proof.sig);
        // Side-channel hardening: a fence around the Choice::from so
        // the boolean -> Choice conversion is observable across the
        // function boundary. The upstream `verify_with_context`
        // returns `bool` internally (which we accept as documented
        // best-effort), but the *transformation* into our accumulator
        // type is now fence-protected.
        compiler_fence(Ordering::SeqCst);
        let c = Choice::from(ok as u8);
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
        // Prove with one witness; verify the proof against a different vk.
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
        assert_eq!(s1.vk.encode(), s2.vk.encode(), "keygen is deterministic");
    }
}
