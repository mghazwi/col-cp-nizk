use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField};

use crate::mpc::spdz_pairing::MpcPairingTrait;

use super::{r1cs_to_qap::R1CSToQAP, Groth16};

use super::{PreparedVerifyingKey, Proof, VerifyingKey};

use ark_relations::r1cs::{Result as R1CSResult, SynthesisError};

use core::ops::{AddAssign, Neg};

/// Prepare the verifying key `vk` for use in proof verification.
pub fn prepare_verifying_key<B, E>(vk: &VerifyingKey<B, E>) -> PreparedVerifyingKey<B, E>
where
    B: Pairing,
    E: MpcPairingTrait<B>,
{
    let alpha_g1_beta_g2: <E as MpcPairingTrait<B>>::TargetField =
        <E as MpcPairingTrait<B>>::my_pairing(vk.alpha_g1, vk.beta_g2);

    PreparedVerifyingKey {
        vk: vk.clone(),
        alpha_g1_beta_g2: alpha_g1_beta_g2,
        gamma_g2_neg_pc: vk.gamma_g2.into_group().neg().into_affine().into(),
        delta_g2_neg_pc: vk.delta_g2.into_group().neg().into_affine().into(),
    }
}

impl<B, E, QAP: R1CSToQAP> Groth16<B, E, QAP>
where
    B: Pairing,
    E: MpcPairingTrait<B>,
{
    /// Prepare proof inputs for use with [`verify_proof_with_prepared_inputs`], wrt the prepared
    /// verification key `pvk` and instance public inputs.
    pub fn prepare_inputs(
        pvk: &PreparedVerifyingKey<B, E>,
        public_inputs: &[<E as MpcPairingTrait<B>>::ScalarField],
    ) -> R1CSResult<<E as MpcPairingTrait<B>>::G1> {
        if (public_inputs.len() + 1) != pvk.vk.gamma_abc_g1.len() {
            return Err(SynthesisError::MalformedVerifyingKey);
        }

        let mut g_ic = pvk.vk.gamma_abc_g1[0].into_group();
        for (i, b) in public_inputs.iter().zip(pvk.vk.gamma_abc_g1.iter().skip(1)) {
            g_ic.add_assign(&b.mul_bigint(i.into_bigint()));
        }

        Ok(g_ic)
    }

    /// Verify a Groth16 proof `proof` against the prepared verification key `pvk` and prepared public
    /// inputs. This should be preferred over [`verify_proof`] if the instance's public inputs are
    /// known in advance.
    pub fn verify_proof_with_prepared_inputs(
        pvk: &PreparedVerifyingKey<B, E>,
        proof: &Proof<B, E>,
        prepared_inputs: &<E as MpcPairingTrait<B>>::G1,
    ) -> R1CSResult<bool> {
        let qap = <E as MpcPairingTrait<B>>::multi_miller_loop(
            [
                <<E as MpcPairingTrait<B>>::G1Affine as Into<
                    <E as MpcPairingTrait<B>>::G1Prepared,
                >>::into(proof.a),
                prepared_inputs.into_affine().into(),
                proof.c.into(),
            ],
            [
                proof.b.into(),
                pvk.gamma_g2_neg_pc.clone(),
                pvk.delta_g2_neg_pc.clone(),
            ],
        );

        let test = <E as MpcPairingTrait<B>>::my_final_exponentiation(qap)
            .ok_or(SynthesisError::UnexpectedIdentity)?;

        Ok(test == pvk.alpha_g1_beta_g2)
    }

    /// Verify a Groth16 proof `proof` against the prepared verification key `pvk`,
    /// with respect to the instance `public_inputs`.
    pub fn verify_proof(
        pvk: &PreparedVerifyingKey<B, E>,
        proof: &Proof<B, E>,
        public_inputs: &[<E as MpcPairingTrait<B>>::ScalarField],
    ) -> R1CSResult<bool> {
        let prepared_inputs = Self::prepare_inputs(pvk, public_inputs)?;
        Self::verify_proof_with_prepared_inputs(pvk, proof, &prepared_inputs)
    }
}
