//! L5 — Universal Verification.
//!
//! The "universal" core: a scheme-agnostic `Verifier` trait that re-derives the
//! commitment independently and checks the proof against it. Pairing it with the
//! `Prover` trait from L4 means any PQ signature scheme can be slotted in without
//! changing the pipeline — verification is dispatched through the trait, not
//! hard-wired to one algorithm.
//!
//! Two independent checks must BOTH pass:
//!   1. PQ signature verifies over the re-derived commitment (ML-DSA-65).
//!   2. PQ KEM round-trip succeeds: encapsulate to the ephemeral public key,
//!      decapsulate with the secret key, shared secrets match in constant time.
//!      This proves the KEM keypair is internally consistent and exercises the
//!      second PQ primitive, so the verdict attests to a live PQ identity, not
//!      just a signature.
//!
//! The boolean result is combined with `subtle::Choice` to avoid early-exit
//! timing leaks between the two checks.

use crate::l2_keygen::EphemeralKeys;
use crate::l3_commit::{commit, Commitment};
use crate::l4_prove::{sig_ctx, Proof};
use crate::VeilError;

use ml_dsa::Keypair as _;
use ml_kem::array::Array;

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use subtle::{Choice, ConstantTimeEq};

/// Pluggable verification scheme. Mirror of `Prover`.
pub trait Verifier {
    /// Verify `proof` attests to `claim` under `keys`. Returns a constant-time
    /// `Choice` (1 = valid, 0 = invalid) — never a short-circuiting bool.
    fn verify(keys: &EphemeralKeys, claim: &[u8], proof: &Proof) -> Result<Choice, VeilError>;
}

/// Default verifier: ML-DSA-65 signature + ML-KEM-768 round-trip consistency.
pub struct MlDsaVerifier;

impl Verifier for MlDsaVerifier {
    fn verify(keys: &EphemeralKeys, claim: &[u8], proof: &Proof) -> Result<Choice, VeilError> {
        // (1) Re-derive the commitment from scratch — verifier trusts nothing
        //     it was handed except the claim and the keys.
        let recommitment: Commitment = commit(keys, claim);

        // (2) PQ signature check over the re-derived commitment.
        let vk = keys.sig_sk.verifying_key();
        let sig_ok: bool = vk.verify_with_context(recommitment.as_bytes(), sig_ctx(), &proof.sig);

        // (3) PQ KEM round-trip: derive deterministic encapsulation coins from
        //     the commitment so this step is reproducible and bound to the
        //     transcript, then check decapsulation matches.
        let kem_ok = kem_roundtrip(keys, &recommitment)?;

        // Combine in constant time — no early exit between the two checks.
        Ok(Choice::from(sig_ok as u8) & kem_ok)
    }
}

/// Encapsulate to the ephemeral KEM public key using deterministic coins
/// derived from the commitment, then decapsulate with the secret key and check
/// the two shared secrets are equal in constant time.
fn kem_roundtrip(keys: &EphemeralKeys, commitment: &Commitment) -> Result<Choice, VeilError> {
    // Derive 32-byte encapsulation message `m` from the commitment.
    let mut xof = Shake256::default();
    xof.update(crate::domain::KEM_ENCAP_COINS);
    xof.update(commitment.as_bytes());
    let mut m = [0u8; 32];
    let mut reader = xof.finalize_xof();
    reader.read(&mut m);

    let m_arr: Array<u8, ml_kem::array::typenum::U32> =
        Array::try_from(&m[..]).map_err(|_| VeilError::Crypto)?;

    // Encapsulate (deterministic) -> (ciphertext, shared secret sender side).
    let (ct, ss_send) = keys.kem_ek.encapsulate_deterministic(&m_arr);

    // Decapsulate with the secret key -> shared secret receiver side.
    let ss_recv = {
        use ml_kem::Decapsulate as _;
        keys.kem_dk.decapsulate(&ct)
    };

    // Constant-time comparison of the two 32-byte shared secrets.
    Ok(ss_send.as_slice().ct_eq(ss_recv.as_slice()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l1_entropy::harvest;
    use crate::l2_keygen::derive_keys;
    use crate::l4_prove::{MlDsaProver, Prover};

    fn valid_setup(claim: &[u8]) -> (EphemeralKeys, Proof) {
        let seed = harvest(b"l5").unwrap();
        let keys = derive_keys(&seed).unwrap();
        let c = crate::l3_commit::commit(&keys, claim);
        let proof = MlDsaProver::prove(&keys, &c).unwrap();
        (keys, proof)
    }

    #[test]
    fn valid_proof_verifies() {
        let (keys, proof) = valid_setup(b"hello");
        let ok = MlDsaVerifier::verify(&keys, b"hello", &proof).unwrap();
        assert_eq!(ok.unwrap_u8(), 1);
    }

    #[test]
    fn wrong_claim_fails() {
        let (keys, proof) = valid_setup(b"hello");
        // Verify against a different claim than was proven.
        let ok = MlDsaVerifier::verify(&keys, b"goodbye", &proof).unwrap();
        assert_eq!(ok.unwrap_u8(), 0, "tampered claim must fail");
    }

    #[test]
    fn tampered_signature_fails() {
        let (keys, mut proof) = valid_setup(b"hello");
        // Corrupt the signature bytes.
        let mut enc = proof.sig.encode();
        enc[0] ^= 0xFF;
        if let Some(bad) = ml_dsa::Signature::<ml_dsa::MlDsa65>::decode(&enc) {
            proof.sig = bad;
            let ok = MlDsaVerifier::verify(&keys, b"hello", &proof).unwrap();
            assert_eq!(ok.unwrap_u8(), 0, "tampered signature must fail");
        }
    }
}
