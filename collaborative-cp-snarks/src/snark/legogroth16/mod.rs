//! An implementation of the [`Groth16`] zkSNARK.
//!
//! [`Groth16`]: https://eprint.iacr.org/2016/260.pdf
#![cfg_attr(not(feature = "std"), no_std)]
#![warn(unused, future_incompatible, nonstandard_style, rust_2018_idioms)]
#![allow(clippy::many_single_char_names, clippy::op_ref)]
#![forbid(unsafe_code)]

#[cfg(feature = "r1cs")]
#[macro_use]
extern crate derivative;

/// Reduce an R1CS instance to a *Quadratic Arithmetic Program* instance.
pub mod r1cs_to_qap;

/// Data structures used by the prover, verifier, and generator.
pub mod data_structures;

/// Generate public parameters for the Groth16 zkSNARK construction.
pub mod generator;

/// Create proofs for the Groth16 zkSNARK construction.
pub mod prover;

/// Verify proofs for the Groth16 zkSNARK construction.
pub mod verifier;

/// CP Link module
pub mod link;

/// Constraints for the Groth16 verifier.
#[cfg(feature = "r1cs")]
pub mod constraints;

pub mod tests;

use crate::mpc::spdz_pairing::MpcPairingTrait;

use self::data_structures::{PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use self::verifier::prepare_verifying_key;
use ark_ec::pairing::Pairing;
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use ark_std::rand::RngCore;
use ark_std::{marker::PhantomData, vec::Vec};
use r1cs_to_qap::{LibsnarkReduction, R1CSToQAP};

/// The SNARK of [[Groth16]](https://eprint.iacr.org/2016/260.pdf).
pub struct LegoGroth16<B, P, QAP: R1CSToQAP = LibsnarkReduction>
where
    B: Pairing,
    P: MpcPairingTrait<B>,
{
    _p: PhantomData<(B, P, QAP)>,
}

impl<B, P, QAP> LegoGroth16<B, P, QAP>
where
    B: Pairing,
    P: MpcPairingTrait<B>,
    QAP: R1CSToQAP,
{
    /// LegoGroth16 setup
    pub fn setup<C: ConstraintSynthesizer<<P as MpcPairingTrait<B>>::ScalarField>, R: RngCore>(
        circuit: C,
        pedersen_bases: &[<P as MpcPairingTrait<B>>::G1Affine],
        rng: &mut R,
    ) -> Result<(ProvingKey<B, P>, VerifyingKey<B, P>), SynthesisError> {
        let pk = Self::generate_random_parameters_with_reduction(circuit, pedersen_bases, rng)?;
        let vk = pk.vk.clone();

        Ok((pk, vk))
    }
}
