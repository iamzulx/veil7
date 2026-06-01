//! Relations — the universal verification core.
//!
//! A [`Relation`] defines *what is being proven*: knowledge of a witness `w`
//! satisfying a public statement `x`, i.e. an NP relation `R(x, w)`. The engine
//! verifies "the prover knows `w` such that `R(x, w)` holds" without the scheme
//! being hard-wired into the pipeline. Swap the `Relation`, and the same
//! machinery verifies something entirely different — that is what "universal
//! verification" means here.
//!
//! Each relation supplies a non-interactive proof via the Fiat-Shamir transform
//! over a shared [`Transcript`]: the prover and verifier build the *same*
//! transcript from public values and derive the *same* challenge, so no
//! interaction is needed and nothing persists between calls.
//!
//! ## Honesty / scope
//! Soundness of every relation here holds in the Random Oracle Model (SHAKE256
//! modelled as a random oracle). These are research/educational constructions —
//! correct and tested, but unaudited. Do not use for production secrets.

use crate::common::{Transcript, VeilError};

/// An NP relation with a non-interactive (Fiat-Shamir) proof of knowledge.
pub trait Relation {
    /// Public input the verifier sees.
    type Statement;
    /// Secret input only the prover holds.
    type Witness;
    /// The proof object sent from prover to verifier.
    type Proof;

    /// A unique protocol label binding the transcript to THIS relation, so a
    /// proof for one relation can never be replayed under another.
    fn protocol_label() -> &'static [u8];

    /// Derive the public statement from a witness (the honest setup direction).
    /// e.g. for a hash preimage relation: `statement = H(witness)`.
    fn statement_from_witness(witness: &Self::Witness) -> Self::Statement;

    /// Absorb the public statement into the transcript. Prover and verifier MUST
    /// implement this identically — it is the binding that makes the derived
    /// challenge depend on the statement (the core Frozen-Heart guard).
    fn bind_statement(stmt: &Self::Statement, t: &mut Transcript);

    /// Prove knowledge of `witness` for the derived statement.
    /// `entropy` supplies the prover's commitment randomness (from L1).
    fn prove(
        witness: &Self::Witness,
        entropy: &[u8],
    ) -> Result<(Self::Statement, Self::Proof), VeilError>;

    /// Verify `proof` against `stmt`. Returns a constant-time `subtle::Choice`
    /// (1 = valid, 0 = invalid) rather than a short-circuiting bool.
    fn verify(stmt: &Self::Statement, proof: &Self::Proof) -> Result<subtle::Choice, VeilError>;
}

pub mod hash_preimage;
pub mod merkle;
pub mod ml_dsa;
