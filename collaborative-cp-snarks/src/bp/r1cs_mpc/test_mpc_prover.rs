use std::{env, iter};
use std::ops::Mul;

use digest::Digest;
use itertools::Itertools;
use merlin::Transcript;
use crate::bp::errors::R1CSError;
use crate::bp::{r1cs_mpc::SharedInnerProductProof, util};
use crate::bp::transcript_381::TranscriptProtocol;
use crate::bp::{inner_product_proof_381::InnerProductProof, ProofError};
use rand::{rngs::OsRng, thread_rng, Rng};
use tokio::runtime::Handle;
use crate::bp::r1cs_mpc::{
    mpc_generators::{BulletproofGens,PedersenGens},
    mpc_constraint_system::ConstraintSystem,
    mpc_prover::MpcProver,
    mpc_linear_combination::{LinearCombination,Variable},
    proof::SharedR1CSProof,
};

use ark_bls12_381::Bls12_381 as P;
use ark_bls12_381::G1Affine as GA;
use ark_bls12_381::G1Projective as G;
use ark_bls12_381::Fr;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::One;

use ark_std::{cfg_iter, rand::RngCore, vec::Vec, UniformRand};
use ark_std::iterable::Iterable;
use ark_std::rand::{prelude::StdRng, SeedableRng};
use crate::globals::{get_party_id, set_experiment_name};

use crate::mpc::spdz_field::{SpdzSharedField as SF, SpdzSharedFieldTrait};
use crate::mpc::spdz_group::g1_affine::SpdzSharedG1Affine as SG;
use crate::mpc::spdz_group::g1::SpdzSharedG1 as G1;
use crate::mpc::spdz_group::group::{SpdzSharedAffine, SpdzSharedAffineTrait};
use crate::network::Net;
use crate::mpc::{
    spdz::Spdz,
    spdz_pairing::MpcPairing
};
use futures_util::TryFutureExt;

use crate::bp::r1cs::{R1CSProof, Verifier, ConstraintSystem as verifierCS, LinearCombination as verifierLC, Variable as verifierVar};
use crate::bp::generators_381::{PedersenGens as verifierGens, BulletproofGens as verifierBPGens};


struct DummyCircuit;

impl DummyCircuit {

    fn cs_multiply<CS: ConstraintSystem>(
        cs: &mut CS,
        a: Vec<Variable>,
        b: Vec<Variable>,
        expected_out: Variable,
    ) -> Result<(), R1CSError> {
        let (_, _, mul_out) = cs
            .multiply(
                ( a[0] * SF::<Fr>::from_public(Fr::from(5u64)) + a[1] * SF::<Fr>::from_public(Fr::from(10u64))),
                ( b[0] * SF::<Fr>::from_public(Fr::from(2u64)) +  b[1] * SF::<Fr>::from_public(Fr::from(3u64))),
            );

        cs.constrain(mul_out - expected_out);

        Ok(())
    }

    fn prover_gen_constraints<CS: ConstraintSystem>(
        cs: &mut CS,
        a: Vec<Variable>,
        b: Vec<Variable>,
        expected_out: Variable,
    ) -> Result<(), R1CSError> {
        let (_, _, mul_out) = cs.multiply(
            ( a[0] * SF::<Fr>::from_public(Fr::from(5u64)) + a[1] * SF::<Fr>::from_public(Fr::from(10u64))),
            ( b[0] * SF::<Fr>::from_public(Fr::from(2u64)) +  b[1] * SF::<Fr>::from_public(Fr::from(3u64))),
        );

        cs.constrain(mul_out - expected_out);

        Ok(())
    }

    fn verifier_gen_constraints<CS: verifierCS>(
        cs: &mut CS,
        a: Vec<verifierVar>,
        b: Vec<verifierVar>,
        expected_out: verifierVar,
    ) -> Result<(), R1CSError> {
        let (_, _, mul_out) = cs.multiply(
            ( a[0] * Fr::from(5u64) + a[1] * Fr::from(10u64)),
            ( b[0] * Fr::from(2u64) +  b[1] * Fr::from(3u64)),
        );

        cs.constrain(mul_out - expected_out);

        Ok(())
    }

    fn gen_proof(
        a: &[SF<Fr>],
        b: &[SF<Fr>],
        expected_out: SF<Fr>,
    ) -> Result<
        (
            SharedR1CSProof,
            Vec<SG<P>>,
            Vec<SG<P>>,
            SG<P>,
        ),
        String,
    > {
        assert_eq!(a.len(), 2);
        assert_eq!(a.len(), b.len());

        // Setup
        let mut rng = StdRng::seed_from_u64(5u64);

        // Create the proof system
        let pc_gens = PedersenGens::default();
        let mut prover_transcript = Transcript::new("test".as_bytes());
        let mut prover = MpcProver::new(&pc_gens, &mut prover_transcript);

        let mut a_commit = vec![];
        let mut a_vars = vec![];
        for ai in a {
            let (a_c, a_var) =
                prover.commit(*ai,SF::<Fr>::rand(&mut rng));
            a_commit.push(a_c);
            a_vars.push(a_var);
        }
        let mut b_commit = vec![];
        let mut b_vars = vec![];
        for bi in b {
            let (b_c, b_var) =
                prover.commit(*bi,SF::<Fr>::rand(&mut rng));
            b_commit.push(b_c);
            b_vars.push(b_var);
        }

        let (c_commit, c_var) = prover
            .commit(expected_out, SF::<Fr>::from_public(Fr::from(1)));

        Self::cs_multiply(&mut prover, a_vars, b_vars, c_var)
            .map_err(|err| format!("Error building constraints: {:?}", err))?;

        let bp_gens =
            BulletproofGens::new(16 /* gens_capacity */, 1 /* party_capacity */);
        let proof = prover
            .prove(&bp_gens).unwrap();

        Ok((proof, a_commit, b_commit, c_commit))
    }

    fn verify_proof(
        proof: SharedR1CSProof,
        a_commit: Vec<SG<P>>,
        b_commit: Vec<SG<P>>,
        c_commit: SG<P>,
    ) -> Result<(), R1CSError> {
        let pc_gens = verifierGens::default();
        let bp_gens =
            verifierBPGens::new(16, 1 );

        let opened_proof = proof.reveal().unwrap();
        let mut opened_a_comms: Vec<GA> = a_commit.iter().map(|c| c.get_share_group_val()).collect();

        let mut opened_b_comms: Vec<GA> = b_commit.iter().map(|c| c.get_share_group_val()).collect();

        let opened_c_comm = c_commit.get_share_group_val();

        let mut verifier_transcript = Transcript::new("test".as_bytes());
        let mut verifier = Verifier::new(&pc_gens, &mut verifier_transcript);

        let a_input = opened_a_comms
            .iter()
            .map(|x| verifier.commit(*x))
            .collect_vec();

        let b_input = opened_b_comms
            .iter()
            .map(|x| verifier.commit(*x))
            .collect_vec();

        let c_input = verifier.commit(opened_c_comm);

        Self::verifier_gen_constraints(&mut verifier, a_input, b_input, c_input);

        verifier
            .verify(&opened_proof, &bp_gens)
    }
}

#[test]
fn test_mpc_r1cs() {
    let mut rng = StdRng::seed_from_u64(5u64);

    let args: Vec<String> = env::args().collect();

    // Parse arguments
    let party_id = args[4].parse::<usize>().unwrap();
    let n_parties = args[5].parse::<usize>().unwrap();

    // Experiment setup
    let experiment_name = String::from("mpc-bp-r1cs/")
        + n_parties.to_string().as_str()
        + "/";
    set_experiment_name(&experiment_name);

    Net::init_network(party_id, n_parties);
    let a_values: Vec<u64> =
        vec![2u64, 3u64];
    let b_values: Vec<u64> =
        vec![4u64, 5u64];

    let expected_result = 920u64;

    let a_value_shares_0: Vec<SF<Fr>> =
        Spdz::<P, MpcPairing<P>>::generate_shares_for_value(
            n_parties, Fr::from(a_values[0]), &mut rng,
        );

    let a_value_shares_1: Vec<SF<Fr>> =
        Spdz::<P, MpcPairing<P>>::generate_shares_for_value(
            n_parties, Fr::from(a_values[1]), &mut rng,
        );

    let b_value_shares_0: Vec<SF<Fr>> =
        Spdz::<P, MpcPairing<P>>::generate_shares_for_value(
            n_parties, Fr::from(b_values[0]), &mut rng,
        );

    let b_value_shares_1: Vec<SF<Fr>> =
        Spdz::<P, MpcPairing<P>>::generate_shares_for_value(
            n_parties, Fr::from(b_values[1]), &mut rng,
        );

    let mut a_witness_input: Vec<SF<Fr>> = Vec::new();
    let mut b_witness_input: Vec<SF<Fr>> = Vec::new();

    a_witness_input.push(a_value_shares_0[party_id]);
    a_witness_input.push(a_value_shares_1[party_id]);

    b_witness_input.push(b_value_shares_0[party_id]);
    b_witness_input.push(b_value_shares_1[party_id]);

    let (proof, a_commit, b_commit, c_commit) = DummyCircuit::gen_proof(
        &a_witness_input,
        &b_witness_input,
        SF::<Fr>::from(expected_result),
    ).unwrap();

    assert!(DummyCircuit::verify_proof(proof, a_commit, b_commit, c_commit).is_ok());

    Net::deinit_network();
}