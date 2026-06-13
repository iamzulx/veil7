//! L5 — Universal Verification (libcrux backend).
//!
//! The "universal" core: a scheme-agnostic `Verifier` trait that re-derives the
//! commitment independently and checks the proof against it. Pairing it with
//! the `Prover` trait from L4 means any PQ signature scheme can be slotted in
//! without changing the pipeline.
//!
//! Two independent checks must BOTH pass:
//!   1. PQ signature verifies over the re-derived commitment (ML-DSA-65, libcrux).
//!   2. PQ KEM round-trip succeeds: encapsulate to the ephemeral public key,
//!      decapsulate with the secret key, shared secrets match in constant time.
//!
//! The boolean result is combined with `subtle::Choice` to avoid early-exit
//! timing leaks between the two checks.

use crate::l2_keygen::EphemeralKeys;
use crate::l3_commit::{commit, Commitment};
use crate::l4_prove::{sig_ctx, Proof};
use crate::pq_backends::libcrux_backend;
use crate::VeilError;

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
/// Both via libcrux (hax/F* formally verified).
pub struct MlDsaVerifier;

impl Verifier for MlDsaVerifier {
    fn verify(keys: &EphemeralKeys, claim: &[u8], proof: &Proof) -> Result<Choice, VeilError> {
        // (1) Re-derive the commitment from scratch — verifier trusts nothing
        //     it was handed except the claim and the keys.
        let recommitment: Commitment = commit(keys, claim);

        // (2) PQ signature check over the re-derived commitment (libcrux).
        let sig_ok: bool = libcrux_backend::dsa_verify(
            &keys.dsa_kp.verification_key,
            recommitment.as_bytes(),
            sig_ctx(),
            &proof.sig,
        )
        .is_ok();

        // (3) PQ KEM round-trip: derive deterministic encapsulation coins from
        //     the commitment so this step is reproducible and bound to the
        //     transcript, then check decapsulation matches (libcrux).
        let kem_ok = kem_roundtrip(keys, &recommitment)?;

        // Combine in constant time — no early exit between the two checks.
        let result = {
            use core::sync::atomic::{compiler_fence, Ordering};
            compiler_fence(Ordering::SeqCst);
            let sig_choice = Choice::from(sig_ok as u8);
            compiler_fence(Ordering::SeqCst);
            let combined = sig_choice & kem_ok;
            compiler_fence(Ordering::SeqCst);
            combined
        };
        Ok(result)
    }
}

/// Encapsulate to the ephemeral KEM public key using deterministic coins
/// derived from the commitment, then decapsulate with the secret key and check
/// the two shared secrets are equal in constant time.
///
/// Uses libcrux (hax/F* verified) for both encapsulate and decapsulate.
fn kem_roundtrip(keys: &EphemeralKeys, commitment: &Commitment) -> Result<Choice, VeilError> {
    // Derive 32-byte encapsulation coins from the commitment.
    // SIDE-CHANNEL: T-table Keccak. `commitment` is a public value, `m` is a
    // derived encapsulation coin. Both are public by construction. See
    // SPEC-HARDENING.md §"Cache timing and T-table side channels".
    // Risk class: LOW (public values).
    let mut xof = Shake256::default();
    xof.update(crate::domain::KEM_ENCAP_COINS);
    xof.update(commitment.as_bytes());
    let mut m = [0u8; 32];
    let mut reader = xof.finalize_xof();
    reader.read(&mut m);

    // Encapsulate (deterministic) -> (ciphertext, shared secret sender side).
    let (ct, ss_send) = libcrux_backend::kem_encapsulate(keys.kem_kp.public_key(), m);

    // Decapsulate with the secret key -> shared secret receiver side.
    let ss_recv = libcrux_backend::kem_decapsulate(keys.kem_kp.private_key(), &ct);

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
        let ok = MlDsaVerifier::verify(&keys, b"goodbye", &proof).unwrap();
        assert_eq!(ok.unwrap_u8(), 0, "tampered claim must fail");
    }

    #[test]
    fn tampered_signature_fails() {
        let (keys, mut proof) = valid_setup(b"hello");
        // Corrupt one byte of the signature.
        let sig_bytes = proof.sig.as_slice();
        let mut corrupted = [0u8; libcrux_backend::DSA_SIG_SIZE];
        corrupted.copy_from_slice(sig_bytes);
        corrupted[0] ^= 0xFF;
        proof.sig = libcrux_ml_dsa::ml_dsa_65::MLDSA65Signature::new(corrupted);
        let ok = MlDsaVerifier::verify(&keys, b"hello", &proof).unwrap();
        assert_eq!(ok.unwrap_u8(), 0, "tampered signature must fail");
    }

    #[test]
    fn verify_accumulates_constant_time_even_with_signature_failure() {
        let (keys, mut proof) = valid_setup(b"hello");
        let sig_bytes = proof.sig.as_slice();
        let mut corrupted = [0u8; libcrux_backend::DSA_SIG_SIZE];
        corrupted.copy_from_slice(sig_bytes);
        corrupted[0] ^= 0xFF;
        proof.sig = libcrux_ml_dsa::ml_dsa_65::MLDSA65Signature::new(corrupted);

        for claim in &[
            b"hello" as &[u8],
            b"",
            b"\x00\xff\x80",
            b"a-longer-claim-for-variety",
        ] {
            let ok = MlDsaVerifier::verify(&keys, claim, &proof).unwrap();
            assert_eq!(
                ok.unwrap_u8(),
                0,
                "tampered signature must yield 0 for any claim"
            );
        }
    }

    #[test]
    fn kem_roundtrip_legitimate_path_produces_matching_secrets() {
        let seed = harvest(b"l5legit").unwrap();
        let keys = derive_keys(&seed).unwrap();
        let c = crate::l3_commit::commit(&keys, b"hello");

        // Reproduce the KEM round-trip from the verifier.
        let mut xof = sha3::Shake256::default();
        xof.update(crate::domain::KEM_ENCAP_COINS);
        xof.update(c.as_bytes());
        let mut m = [0u8; 32];
        xof.finalize_xof().read(&mut m);

        let (ct, ss_send) = libcrux_backend::kem_encapsulate(keys.kem_kp.public_key(), m);
        let ss_recv = libcrux_backend::kem_decapsulate(keys.kem_kp.private_key(), &ct);

        assert_eq!(
            ss_send.as_slice().ct_eq(ss_recv.as_slice()).unwrap_u8(),
            1,
            "legitimate KEM round-trip must produce matching shared secrets"
        );
    }
}
