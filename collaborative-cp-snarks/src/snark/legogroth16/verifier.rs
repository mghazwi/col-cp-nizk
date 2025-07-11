use super::link::{PESubspaceSnark, SubspaceSnark};
use super::{r1cs_to_qap::R1CSToQAP, LegoGroth16, PreparedVerifyingKey, Proof, VerifyingKey};
use crate::mpc::spdz_pairing::MpcPairingTrait;
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_relations::r1cs::{Result as R1CSResult, SynthesisError};
use core::ops::{AddAssign, Neg};
use std::ops::Mul;

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

impl<B, E, QAP: R1CSToQAP> LegoGroth16<B, E, QAP>
where
    B: Pairing,
    E: MpcPairingTrait<B>,
{
    /// Prepare proof inputs for use with [`verify_proof_with_prepared_inputs`], wrt the prepared
    /// verification key `pvk` and instance public inputs.
    /// Prepare the verifying key `vk` for use in proof verification.
    pub fn prepare_verifying_key(vk: &VerifyingKey<B, E>) -> PreparedVerifyingKey<B, E> {
        PreparedVerifyingKey {
            vk: vk.clone(),
            alpha_g1_beta_g2: <E as MpcPairingTrait<B>>::my_pairing(vk.alpha_g1, vk.beta_g2),
            gamma_g2_neg_pc: vk.gamma_g2.into_group().neg().into().into(),
            delta_g2_neg_pc: vk.delta_g2.into_group().neg().into().into(),
        }
    }

    /// Verify a Groth16 proof `proof` against the prepared verification key `pvk`,
    /// with respect to the instance `public_inputs`.
    pub fn verify_proof(
        pvk: &PreparedVerifyingKey<B, E>,
        proof: &Proof<B, E>,
        _public_inputs: &[<E as MpcPairingTrait<B>>::ScalarField],
    ) -> R1CSResult<bool> {
        let commitments = vec![proof.link_d.into_group(), proof.d.into_group()];

        let link_verified = PESubspaceSnark::<B, E>::verify(
            &pvk.vk.link_pp,
            &pvk.vk.link_vk,
            &commitments
                .iter()
                .map(|p| p.into_affine())
                .collect::<Vec<_>>(),
            &proof.link_pi,
        );

        let qap = <E as MpcPairingTrait<B>>::multi_miller_loop(
            [proof.a, proof.c, proof.d],
            [
                proof.b.into(),
                pvk.delta_g2_neg_pc.clone(),
                pvk.gamma_g2_neg_pc.clone(),
            ],
        );

        let test = <E as MpcPairingTrait<B>>::my_final_exponentiation(qap)
            .ok_or(SynthesisError::UnexpectedIdentity)?;

        Ok(link_verified && test == pvk.alpha_g1_beta_g2)
    }

    /// Verify the commitment of a Groth16 proof
    pub fn verify_commitment(
        pvk: &PreparedVerifyingKey<B, E>,
        proof: &Proof<B, E>,
        public_inputs: &[<E as MpcPairingTrait<B>>::ScalarField],
        v: &<E as MpcPairingTrait<B>>::ScalarField,
        link_v: &<E as MpcPairingTrait<B>>::ScalarField,
    ) -> Result<bool, SynthesisError> {
        if (public_inputs.len() + 1) != pvk.vk.gamma_abc_g1.len() {
            return Err(SynthesisError::MalformedVerifyingKey);
        }
        if (public_inputs.len() + 2) != pvk.vk.link_bases.len() {
            return Err(SynthesisError::MalformedVerifyingKey);
        }

        let mut g_ic = pvk.vk.gamma_abc_g1[0].into_group();
        for (i, b) in public_inputs.iter().zip(pvk.vk.gamma_abc_g1.iter().skip(1)) {
            g_ic.add_assign(&b.mul(i));
        }
        g_ic.add_assign(&pvk.vk.eta_gamma_inv_g1.mul(v));

        let mut g_link = pvk.vk.link_bases[0].into_group();
        for (i, b) in public_inputs.iter().zip(pvk.vk.link_bases.iter().skip(1)) {
            g_link.add_assign(&b.mul(i));
        }
        g_link.add_assign(&pvk.vk.link_bases.last().unwrap().mul(link_v));

        Ok(proof.d == g_ic.into() && proof.link_d == g_link.into())
    }
}
