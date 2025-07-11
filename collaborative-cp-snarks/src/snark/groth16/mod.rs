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

pub mod tests;

/// Constraints for the Groth16 verifier.
#[cfg(feature = "r1cs")]
pub mod constraints;

use crate::mpc::spdz_pairing::MpcPairingTrait;

use self::data_structures::{PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use self::verifier::prepare_verifying_key;
use ark_crypto_primitives::snark::*;
use ark_ec::pairing::Pairing;
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::RngCore;
use ark_std::{marker::PhantomData, vec::Vec};
use r1cs_to_qap::{LibsnarkReduction, R1CSToQAP};

/// The SNARK of [[Groth16]](https://eprint.iacr.org/2016/260.pdf).
pub struct Groth16<B, P, QAP: R1CSToQAP = LibsnarkReduction>
where
    B: Pairing,
    P: MpcPairingTrait<B>,
{
    _p: PhantomData<(B, P, QAP)>,
}

impl<B, P, QAP> SNARK<<P as MpcPairingTrait<B>>::ScalarField> for Groth16<B, P, QAP>
where
    B: Pairing,
    P: MpcPairingTrait<B>,
    QAP: R1CSToQAP,
{
    type ProvingKey = ProvingKey<B, P>;
    type VerifyingKey = VerifyingKey<B, P>;
    type Proof = Proof<B, P>;
    type ProcessedVerifyingKey = PreparedVerifyingKey<B, P>;
    type Error = SynthesisError;

    fn circuit_specific_setup<
        C: ConstraintSynthesizer<<P as MpcPairingTrait<B>>::ScalarField>,
        R: RngCore,
    >(
        circuit: C,
        rng: &mut R,
    ) -> Result<(Self::ProvingKey, Self::VerifyingKey), Self::Error> {
        let pk = Self::generate_random_parameters_with_reduction(circuit, rng)?;
        let vk = pk.vk.clone();

        Ok((pk, vk))
    }

    fn prove<C: ConstraintSynthesizer<<P as MpcPairingTrait<B>>::ScalarField>, R: RngCore>(
        pk: &Self::ProvingKey,
        circuit: C,
        rng: &mut R,
    ) -> Result<Self::Proof, Self::Error> {
        Self::create_random_proof_with_reduction(circuit, pk, rng)
    }

    fn process_vk(
        circuit_vk: &Self::VerifyingKey,
    ) -> Result<Self::ProcessedVerifyingKey, Self::Error> {
        Ok(prepare_verifying_key(circuit_vk))
    }

    fn verify_with_processed_vk(
        circuit_pvk: &Self::ProcessedVerifyingKey,
        x: &[<P as MpcPairingTrait<B>>::ScalarField],
        proof: &Self::Proof,
    ) -> Result<bool, Self::Error> {
        Ok(Self::verify_proof(&circuit_pvk, proof, &x)?)
    }
}

impl<B, P, QAP: R1CSToQAP> CircuitSpecificSetupSNARK<<P as MpcPairingTrait<B>>::ScalarField>
    for Groth16<B, P, QAP>
where
    B: Pairing,
    P: MpcPairingTrait<B>,
{
}
