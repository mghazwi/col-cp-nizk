//! The `messages` module contains the API for the messages passed between the parties and the dealer
//! in an aggregated multiparty computation protocol.
//!
//! For more explanation of how the `dealer`, `party`, and `messages` modules orchestrate the protocol execution, see
//! [the API for the aggregated multiparty computation protocol](../aggregation/index.html#api-for-the-aggregated-multiparty-computation-protocol).

extern crate alloc;

use alloc::vec::Vec;
use core::iter;
use crate::bp::generators::{BulletproofGens, PedersenGens};

use ark_ec::{AffineRepr, Group, CurveConfig, CurveGroup, ScalarMul, VariableBaseMSM};
use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField, batch_inversion, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// A commitment to the bits of a party's value.
#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub struct BitCommitment<G: Group> {
    pub(super) V_j: G,
    pub(super) A_j: G,
    pub(super) S_j: G,
}

/// Challenge values derived from all parties' [`BitCommitment`]s.
#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub struct BitChallenge<G: Group> {
    pub(super) y: G::ScalarField,
    pub(super) z: G::ScalarField,
}

/// A commitment to a party's polynomial coefficents.
#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub struct PolyCommitment<G: Group> {
    pub(super) T_1_j: G,
    pub(super) T_2_j: G,
}

/// Challenge values derived from all parties' [`PolyCommitment`]s.
#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
pub struct PolyChallenge<G: Group> {
    pub(super) x: G::ScalarField,
}

/// A party's proof share, ready for aggregation into the final
/// [`RangeProof`](::RangeProof).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProofShare<G:Group> {
    pub(super) t_x: G::ScalarField,
    pub(super) t_x_blinding: G::ScalarField,
    pub(super) e_blinding: G::ScalarField,
    pub(super) l_vec: Vec<G::ScalarField>,
    pub(super) r_vec: Vec<G::ScalarField>,
}
//TODO: audi shares not implemented

