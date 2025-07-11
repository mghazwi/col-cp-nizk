#![allow(non_snake_case)]
//! Definition of the proof struct.

use crate::bp::errors::R1CSError;
use crate::bp::inner_product_proof_381::InnerProductProof;
use crate::bp::util;
use ark_bls12_381::Fr;
use ark_bls12_381::G1Affine as G;

const ONE_PHASE_COMMITMENTS: u8 = 0;
const TWO_PHASE_COMMITMENTS: u8 = 1;

/// A proof of some statement specified by a
/// [`ConstraintSystem`](::r1cs::ConstraintSystem).
///
/// Statements are specified by writing gadget functions which add
/// constraints to a [`ConstraintSystem`](::r1cs::ConstraintSystem)
/// implementation.  To construct an [`R1CSProof`], a prover constructs
/// a [`ProverCS`](::r1cs::ProverCS), then passes it to gadget
/// functions to build the constraint system, then consumes the
/// constraint system using
/// [`ProverCS::prove`](::r1cs::ProverCS::prove) to produce an
/// [`R1CSProof`].  To verify an [`R1CSProof`], a verifier constructs a
/// [`VerifierCS`](::r1cs::VerifierCS), then passes it to the same
/// gadget functions to (re)build the constraint system, then consumes
/// the constraint system using
/// [`VerifierCS::verify`](::r1cs::VerifierCS::verify) to verify the
/// proof.
#[derive(Clone, Debug)]
#[allow(non_snake_case)]
pub struct R1CSProof {
    /// Commitment to the values of input wires in the first phase.
    pub A_I1: G,
    /// Commitment to the values of output wires in the first phase.
    pub A_O1: G,
    /// Commitment to the blinding factors in the first phase.
    pub S1: G,
    /// Commitment to the values of input wires in the second phase.
    pub A_I2: G,
    /// Commitment to the values of output wires in the second phase.
    pub A_O2: G,
    /// Commitment to the blinding factors in the second phase.
    pub S2: G,
    /// Commitment to the \\(t_1\\) coefficient of \\( t(x) \\)
    pub T_1: G,
    /// Commitment to the \\(t_3\\) coefficient of \\( t(x) \\)
    pub T_3: G,
    /// Commitment to the \\(t_4\\) coefficient of \\( t(x) \\)
    pub T_4: G,
    /// Commitment to the \\(t_5\\) coefficient of \\( t(x) \\)
    pub T_5: G,
    /// Commitment to the \\(t_6\\) coefficient of \\( t(x) \\)
    pub T_6: G,
    /// Evaluation of the polynomial \\(t(x)\\) at the challenge point \\(x\\)
    pub t_x: Fr,
    /// Blinding factor for the synthetic commitment to \\( t(x) \\)
    pub t_x_blinding: Fr,
    /// Blinding factor for the synthetic commitment to the
    /// inner-product arguments
    pub e_blinding: Fr,
    /// Proof data for the inner-product argument.
    pub ipp_proof: InnerProductProof,
}

//TODO: implement serialize
