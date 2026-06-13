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
//!
//! ## Determinism of the built-in relations
//! `hash_preimage`, `merkle`, and `ml_dsa` are pure-deterministic: their
//! `prove` implementations do not use the `entropy` parameter. Two calls
//! with the same witness produce byte-identical `(Statement, Proof)`
//! pairs and therefore byte-identical verdict transcripts. This is a
//! feature — it lets auditors re-derive proofs offline without re-running
//! the engine — but it means the engine's 12-round entropy mix
//! (`harvest()`) in `prove_and_verify` is wasted for these relations. The
//! `entropy` parameter is kept in the trait signature for forward
//! compatibility with future probabilistic relations (e.g. discrete-log
//! knowledge proofs with honest-verifier ZK simulation).

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
    ///
    /// Note for relation implementors: the current built-in relations
    /// (`hash_preimage`, `merkle`, `ml_dsa`) are pure-deterministic —
    /// their `prove` function ignores `entropy` and produces the same
    /// `(Statement, Proof)` for the same witness every time. The
    /// parameter is part of the trait signature so future relations
    /// (e.g. probabilistic zero-knowledge schemes) can opt into the
    /// entropy stream without a trait break. Documented in
    /// `relations/mod.rs` honesty section.
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
