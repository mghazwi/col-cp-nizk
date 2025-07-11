use super::{r1cs_to_qap::R1CSToQAP, LegoGroth16, Proof, ProvingKey};
use crate::mpc::spdz_pairing::MpcPairingTrait;
use crate::snark::legogroth16::link::{PESubspaceSnark, SubspaceSnark};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{UniformRand, Zero};
use ark_poly::GeneralEvaluationDomain;
use ark_relations::r1cs::{
    ConstraintMatrices, ConstraintSynthesizer, ConstraintSystem, OptimizationGoal,
    Result as R1CSResult, SynthesisError,
};
use ark_std::One;
use ark_std::{
    cfg_into_iter, end_timer,
    ops::{AddAssign, Mul},
    start_timer,
    vec::Vec,
};

use rand::RngCore;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

type D<F> = GeneralEvaluationDomain<F>;

impl<B, E, QAP: R1CSToQAP> LegoGroth16<B, E, QAP>
where
    B: Pairing,
    E: MpcPairingTrait<B>,
{
    /// Create a Groth16 proof using randomness `r` and `s` and
    /// the provided R1CS-to-QAP reduction, using the provided
    /// R1CS constraint matrices.
    #[inline]
    pub fn create_proof_with_reduction_and_matrices(
        pk: &ProvingKey<B, E>,
        r: <E as MpcPairingTrait<B>>::ScalarField,
        s: <E as MpcPairingTrait<B>>::ScalarField,
        v: <E as MpcPairingTrait<B>>::ScalarField,
        link_v: <E as MpcPairingTrait<B>>::ScalarField,
        matrices: &ConstraintMatrices<<E as MpcPairingTrait<B>>::ScalarField>,
        num_inputs: usize,
        num_constraints: usize,
        full_assignment: &[<E as MpcPairingTrait<B>>::ScalarField],
    ) -> R1CSResult<Proof<B, E>> {
        let prover_time = start_timer!(|| "Groth16::Prover");
        let witness_map_time = start_timer!(|| "R1CS to QAP witness map");
        let h = QAP::witness_map_from_matrices::<
            <E as MpcPairingTrait<B>>::ScalarField,
            D<<E as MpcPairingTrait<B>>::ScalarField>,
        >(matrices, num_inputs, num_constraints, full_assignment)?;
        end_timer!(witness_map_time);
        let input_assignment = &full_assignment[1..num_inputs];
        let aux_assignment = &full_assignment[num_inputs..];
        let proof = Self::create_proof_with_assignment(
            pk,
            r,
            s,
            v,
            link_v,
            &h,
            input_assignment,
            aux_assignment,
        )?;
        end_timer!(prover_time);

        Ok(proof)
    }

    #[inline]
    fn create_proof_with_assignment(
        pk: &ProvingKey<B, E>,
        r: <E as MpcPairingTrait<B>>::ScalarField,
        s: <E as MpcPairingTrait<B>>::ScalarField,
        v: <E as MpcPairingTrait<B>>::ScalarField,
        link_v: <E as MpcPairingTrait<B>>::ScalarField,
        h: &[<E as MpcPairingTrait<B>>::ScalarField],
        input_assignment: &[<E as MpcPairingTrait<B>>::ScalarField],
        aux_assignment: &[<E as MpcPairingTrait<B>>::ScalarField],
    ) -> R1CSResult<Proof<B, E>> {
        let c_acc_time = start_timer!(|| "Compute C");

        let h_assignment = cfg_into_iter!(h).map(|s| *s).collect::<Vec<_>>();

        // let h_acc = E::G1::msm(&pk.h_query, &h_assignment[..h_assignment.len() - 1]);

        let h_acc: <E as MpcPairingTrait<B>>::G1 =
            custom_msm(&pk.h_query, &h_assignment[..h_assignment.len() - 1]);

        drop(h_assignment);

        let l_aux_acc: <E as MpcPairingTrait<B>>::G1 = custom_msm(&pk.l_query, aux_assignment);

        let r_s_delta_g1 = pk.delta_g1 * (r * s);
        let v_eta_delta_inv = pk.eta_delta_inv_g1.into_group().mul(v);

        end_timer!(c_acc_time);

        let input_assignment_with_one = [
            &[<E as MpcPairingTrait<B>>::ScalarField::one()],
            input_assignment,
        ]
        .concat();

        let input_assignment = input_assignment_with_one[1..].to_vec();

        let assignment = [&input_assignment[..], &aux_assignment[..]].concat();

        // Compute A
        let a_acc_time = start_timer!(|| "Compute A");
        let r_g1 = pk.delta_g1.mul(r);

        let g_a = Self::calculate_coeff(r_g1, &pk.a_query, pk.vk.alpha_g1, &assignment);

        let s_g_a = g_a * &s;
        end_timer!(a_acc_time);

        // Compute B in G1 if needed
        let g1_b = if !r.is_zero() {
            let b_g1_acc_time = start_timer!(|| "Compute B in G1");
            let s_g1 = pk.delta_g1.mul(s);
            let g1_b = Self::calculate_coeff(s_g1, &pk.b_g1_query, pk.beta_g1, &assignment);

            end_timer!(b_g1_acc_time);

            g1_b
        } else {
            <E as MpcPairingTrait<B>>::G1::zero()
        };

        // Compute B in G2
        let b_g2_acc_time = start_timer!(|| "Compute B in G2");

        let s_g2 = pk.vk.delta_g2.mul(s);

        // Here party 1 takes another path than p0
        let g2_b = Self::calculate_coeff(s_g2, &pk.b_g2_query, pk.vk.beta_g2, &assignment);

        let r_g1_b = g1_b * &r;
        drop(assignment);

        end_timer!(b_g2_acc_time);

        let c_time = start_timer!(|| "Finish C");
        let mut g_c = s_g_a;
        g_c += &r_g1_b;
        g_c -= &r_s_delta_g1;
        g_c += &l_aux_acc;
        g_c += &h_acc;
        // LegoGroth16 addition
        g_c -= &v_eta_delta_inv;

        end_timer!(c_time);

        // LegoGroth16 addition

        // Compute D
        let d_acc_time = start_timer!(|| "Compute D");

        let gamma_abc_inputs_source = &pk.vk.gamma_abc_g1;
        let gamma_abc_inputs_acc: <E as MpcPairingTrait<B>>::G1 =
            custom_msm(gamma_abc_inputs_source, &input_assignment_with_one);

        let v_eta_gamma_inv = pk.vk.eta_gamma_inv_g1.into_group().mul(v);

        let mut g_d = gamma_abc_inputs_acc;
        g_d += &v_eta_gamma_inv;
        end_timer!(d_acc_time);

        let input_assignment_with_one_with_link_hider =
            [&input_assignment_with_one, &[link_v][..]].concat();
        let input_assignment_with_one_with_hiders =
            [&input_assignment_with_one_with_link_hider, &[v][..]].concat();
        let link_time = start_timer!(|| "Compute CP_{link}");

        // Link_pi is the proof that links the commitment to the input
        let link_pi = PESubspaceSnark::<B, E>::prove(
            &pk.vk.link_pp,
            &pk.link_ek,
            &input_assignment_with_one_with_hiders,
        );
        let pedersen_bases_affine = &pk.vk.link_bases;
        let pedersen_values = input_assignment_with_one_with_link_hider
            .into_iter()
            .collect::<Vec<_>>();

        let g_d_link: <E as MpcPairingTrait<B>>::G1 =
            custom_msm(pedersen_bases_affine, &pedersen_values);

        end_timer!(link_time);

        Ok(Proof {
            a: g_a.into_affine(),
            b: g2_b.into_affine(),
            c: g_c.into_affine(),
            d: g_d.into_affine(),
            link_d: g_d_link.into_affine(),
            link_pi,
        })
    }

    /// Create a Groth16 proof that is zero-knowledge using the provided
    /// R1CS-to-QAP reduction.
    /// This method samples randomness for zero knowledges via `rng`.
    pub fn prove<C: ConstraintSynthesizer<<E as MpcPairingTrait<B>>::ScalarField>, R: RngCore>(
        pk: &ProvingKey<B, E>,
        circuit: C,
        v: <E as MpcPairingTrait<B>>::ScalarField,
        link_v: <E as MpcPairingTrait<B>>::ScalarField,
        rng: &mut R,
    ) -> Result<Proof<B, E>, SynthesisError> {
        let r = <E as MpcPairingTrait<B>>::ScalarField::rand(rng);
        let s = <E as MpcPairingTrait<B>>::ScalarField::rand(rng);

        Self::create_proof_with_reduction(circuit, pk, r, s, v, link_v)
    }

    /// Create a Groth16 proof that is *not* zero-knowledge with the provided
    /// R1CS-to-QAP reduction.
    #[inline]
    pub fn create_proof_with_reduction_no_zk<C>(
        circuit: C,
        pk: &ProvingKey<B, E>,
    ) -> R1CSResult<Proof<B, E>>
    where
        C: ConstraintSynthesizer<<E as MpcPairingTrait<B>>::ScalarField>,
    {
        Self::create_proof_with_reduction(
            circuit,
            pk,
            <E as MpcPairingTrait<B>>::ScalarField::zero(),
            <E as MpcPairingTrait<B>>::ScalarField::zero(),
            <E as MpcPairingTrait<B>>::ScalarField::zero(),
            <E as MpcPairingTrait<B>>::ScalarField::zero(),
        )
    }

    /// Create a Groth16 proof using randomness `r` and `s` and the provided
    /// R1CS-to-QAP reduction.
    #[inline]
    pub fn create_proof_with_reduction<C>(
        circuit: C,
        pk: &ProvingKey<B, E>,
        r: <E as MpcPairingTrait<B>>::ScalarField,
        s: <E as MpcPairingTrait<B>>::ScalarField,
        v: <E as MpcPairingTrait<B>>::ScalarField,
        link_v: <E as MpcPairingTrait<B>>::ScalarField,
    ) -> R1CSResult<Proof<B, E>>
    where
        E: Pairing,
        C: ConstraintSynthesizer<<E as MpcPairingTrait<B>>::ScalarField>,
        QAP: R1CSToQAP,
    {
        let prover_time = start_timer!(|| "Groth16::Prover");
        let cs = ConstraintSystem::new_ref();

        // Set the optimization goal
        cs.set_optimization_goal(OptimizationGoal::Constraints);

        // Synthesize the circuit.
        let synthesis_time = start_timer!(|| "Constraint synthesis");
        circuit.generate_constraints(cs.clone())?;
        // debug_assert!(cs.is_satisfied().unwrap());
        end_timer!(synthesis_time);

        let lc_time = start_timer!(|| "Inlining LCs");
        cs.finalize();
        end_timer!(lc_time);

        let witness_map_time = start_timer!(|| "R1CS to QAP witness map");
        let h = QAP::witness_map::<
            <E as MpcPairingTrait<B>>::ScalarField,
            D<<E as MpcPairingTrait<B>>::ScalarField>,
        >(cs.clone())?;
        end_timer!(witness_map_time);

        let prover = cs.borrow().unwrap();
        let proof = Self::create_proof_with_assignment(
            pk,
            r,
            s,
            v,
            link_v,
            &h,
            &prover.instance_assignment[1..],
            &prover.witness_assignment,
        )?;

        end_timer!(prover_time);

        Ok(proof)
    }

    fn calculate_coeff<G: AffineRepr>(
        initial: G::Group,
        query: &[G],
        vk_param: G,
        assignment: &[<G as AffineRepr>::ScalarField],
    ) -> G::Group
    where
        G::Group: VariableBaseMSM<MulBase = G>,
    {
        let el = query[0];

        // let acc = G::Group::msm(&query[1..], assignment);
        let acc: G::Group = custom_msm(&query[1..], assignment);

        let mut res = initial;
        res.add_assign(&el);
        res += &acc;

        // P0 has Public value here, and P1 Shared. This cannot be.
        res.add_assign(&vk_param);

        res
    }
}

/// Custom multi-scalar multiplication
pub fn custom_msm<G: CurveGroup>(bases: &[G::Affine], scalars: &[G::ScalarField]) -> G {
    assert_eq!(bases.len(), scalars.len());

    let mut acc = G::zero();

    // TODO: Improve with optimized version ƒrom ark_groth16

    for (base, scalar) in bases.iter().zip(scalars.iter()) {
        acc += base.mul(*scalar);
    }
    acc
}
