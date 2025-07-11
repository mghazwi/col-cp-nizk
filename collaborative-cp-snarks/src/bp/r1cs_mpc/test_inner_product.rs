//! Groups integration tests for shared inner product proofs

use std::{env, iter};
use std::ops::Mul;

use digest::Digest;
use itertools::Itertools;
use merlin::Transcript;
use crate::bp::errors::MPCError;
use crate::bp::{r1cs_mpc::SharedInnerProductProof, util, BulletproofGens};
use crate::bp::transcript_381::TranscriptProtocol;
use crate::bp::{inner_product_proof_381::InnerProductProof, ProofError};
use rand::{rngs::OsRng, thread_rng, Rng};
use tokio::runtime::Handle;

use ark_bls12_381::Bls12_381 as P;
use ark_bls12_381::G1Affine as GA;
use ark_bls12_381::Fr;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::One;

use ark_std::{cfg_iter, rand::RngCore, vec::Vec, UniformRand};
use ark_std::rand::{prelude::StdRng, SeedableRng};
use crate::globals::{get_party_id, set_experiment_name};

use crate::mpc::spdz_field::{SpdzSharedField as SF, SpdzSharedFieldTrait};
use crate::mpc::spdz_group::g1_affine::SpdzSharedG1Affine as SG;
use crate::mpc::spdz_group::group::{SpdzSharedAffine, SpdzSharedAffineTrait};
use crate::network::Net;
use crate::mpc::{
    spdz::Spdz,
    spdz_pairing::MpcPairing
};
use crate::mpc::spdz_witness_distribution::distribute_witnesses;
use crate::bp::r1cs_mpc::mpc_inner_product::shared_custom_msm;

fn get_comm(
    a: &[SF<Fr>],
    b: &[SF<Fr>],
    c: &SF<Fr>,
    y_inv: SF<Fr>,
) -> SG<P> {
    assert_eq!(a.len(), b.len());
    let n = a.len();
    assert!(n.is_power_of_two());

    let bp_gens = BulletproofGens::new(n, 1);
    let ga_G: Vec<GA> = bp_gens.share(0).G(n).copied().collect_vec();
    let ga_H: Vec<GA> = bp_gens.share(0).H(n).copied().collect_vec();
    let G:Vec<SG<P>>  = ga_G.iter().map(|g|SG::from_public(*g)).collect();
    let H:Vec<SG<P>>  = ga_H.iter().map(|g|SG::from_public(*g)).collect();

    let mut rng = StdRng::seed_from_u64(5u64);
    let Q_a = (GA::generator()*Fr::rand(&mut rng)).into_affine();
    let Q = SG::from_public(Q_a);

    let y_inv_powers = util::exp_iter_result(y_inv, b.len());
    let b_prime = b.iter().zip(y_inv_powers.iter()).map(|(bi, yi)| *bi * yi);

    let scalars = a.iter().cloned().chain(b_prime);
    let bases = G.iter().chain(H.iter()).copied();

    // TODO: replace this with call to msm
    let mut acc = SG::zero();

    for (base, scalar) in bases.zip(scalars) {
        acc = (acc + base.mul(scalar)).into_affine();
    }
    let com = acc.clone();

    let com = (com + (Q * c)).into_affine();
    com
}

fn gen_proof(
    a: &[SF<Fr>],
    b: &[SF<Fr>],
    c: &SF<Fr>,
    y_inv: SF<Fr>,
) -> Result<(SharedInnerProductProof, SG<P>), String> {
    assert_eq!(a.len(), b.len());
    let n = a.len();
    assert!(n.is_power_of_two());

    let input_commitment = get_comm(a, b, c, y_inv.clone());

    let bp_gens = BulletproofGens::new(n, 1);
    let ga_G: Vec<GA> = bp_gens.share(0).G(n).copied().collect_vec();
    let ga_H: Vec<GA> = bp_gens.share(0).H(n).copied().collect_vec();
    let G:Vec<SG<P>>  = ga_G.iter().map(|g|SG::from_public(*g)).collect();
    let H:Vec<SG<P>>  = ga_H.iter().map(|g|SG::from_public(*g)).collect();

    let G_factors: Vec<SF<Fr>> = iter::repeat(SF::one())
        .take(n)
        .collect();
    let H_factors: Vec<SF<Fr>> = util::exp_iter_result(y_inv, n);

    let mut rng = StdRng::seed_from_u64(5u64);
    let Q_a = (GA::generator()*Fr::rand(&mut rng)).into_affine();
    let Q = SG::from_public(Q_a);

    let mut transcript = Transcript::new("test".as_bytes());
    Ok((
        SharedInnerProductProof::create(
            &mut transcript,
            Q,
            &G_factors,
            &H_factors,
            G,
            H,
            a.to_vec(),
            b.to_vec(),
        )
        .map_err(|err| format!("Error proving: {:?}", err))?,
        input_commitment,
    ))
}

fn verify(
    n: usize,
    input_comm: GA,
    y_inv: Fr,
    proof: InnerProductProof,
) -> Result<(), ProofError> {
    // Create the generators for the proof
    let bp_gens = BulletproofGens::new(n, 1);
    let G: Vec<GA> = bp_gens.share(0).G(n).cloned().collect_vec();
    let H: Vec<GA> = bp_gens.share(0).H(n).cloned().collect_vec();
    let mut rng = StdRng::seed_from_u64(5u64);
    let Q = (GA::generator()*Fr::rand(&mut rng)).into_affine();

    // Create multipliers for the generators
    let G_factors: Vec<Fr> = iter::repeat(Fr::one()).take(n).collect();
    let H_factors: Vec<Fr> = util::exp_iter(y_inv).take(n).collect();

    let mut verifier_transcript = Transcript::new("test".as_bytes());
    proof.verify(
        n,
        &mut verifier_transcript,
        G_factors,
        H_factors,
        &input_comm,
        &Q,
        &G,
        &H,
    )
}

fn run_ipp(
    a: &Vec<SF<Fr>>,
    b: &Vec<SF<Fr>>,
    c: &SF<Fr>,
    y_inv: SF<Fr>,
) -> Result<(), String> {
    let n = a.len();
    assert_eq!(a.len(), b.len());
    assert!(n.is_power_of_two());

    let (proof, input_comm) = gen_proof(a, b, c, y_inv.clone())?;
    println!("proof opened = {:?}",proof);
    let y_inv = y_inv.reveal().get_share_field_val();

    let proof_opened = proof.reveal().unwrap();
    println!("proof opened = {:?}",proof_opened);
    let comm_opened = input_comm.reveal().get_share_group_val();

    verify(n, comm_opened, y_inv, proof_opened)
        .map_err(|err| format!("error verifying proof: {err:?}"))
}

#[test]
fn test_mpc_ipp() -> Result<(), String> {

    let mut rng = StdRng::seed_from_u64(5u64);

    let args: Vec<String> = env::args().collect();

    // Parse arguments
    let party_id = args[4].parse::<usize>().unwrap();
    let n_parties = args[5].parse::<usize>().unwrap();

    // Experiment setup
    let experiment_name = String::from("ipp/")
        + n_parties.to_string().as_str()
        + "/";
    set_experiment_name(&experiment_name);

    Net::init_network(party_id, n_parties);
    // Party 0 holds the first vector, party 1 holds the second
    let a_values: Vec<u64> =
        vec![13, 42];
    let b_values: Vec<u64> =
        vec![5, 0];

    let expected_inner_product = 65u64;

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

    let public_input = SF::from(Fr::from(expected_inner_product));

    let witness_size = 2;

    let mut a_witness_input: Vec<SF<Fr>> = Vec::new();
    let mut b_witness_input: Vec<SF<Fr>> = Vec::new();

    a_witness_input.push(a_value_shares_0[party_id]);
    a_witness_input.push(a_value_shares_1[party_id]);

    b_witness_input.push(b_value_shares_0[party_id]);
    b_witness_input.push(b_value_shares_1[party_id]);

    let challenge = SF::from_shared(Fr::rand(&mut rng));
    let y_inv = challenge.reveal();

    let ver = run_ipp(
        &a_witness_input,
        &b_witness_input,
        &public_input,
        y_inv,
    );

    Net::deinit_network();
    ver
}

#[test]
fn test_single_party_inner_product() {

    let mut rng = StdRng::seed_from_u64(5u64);
    //
    let args: Vec<String> = env::args().collect();
    //
    // Parse arguments
    let party_id = args[4].parse::<usize>().unwrap();
    let n_parties = args[5].parse::<usize>().unwrap();

    // Experiment setup
    let experiment_name = String::from("ipp-single/")
        + n_parties.to_string().as_str()
        + "/";
    set_experiment_name(&experiment_name);
    //
    Net::init_network(party_id, n_parties);
    // Party 0 holds the first vector, party 1 holds the second
    let a_values: Vec<u64> =
        vec![13, 42];
    let b_values: Vec<u64> =
        vec![5, 0];

    let expected_inner_product = 65u64;

    let public_input = SF::from(Fr::from(expected_inner_product));

    let witness_size = 2;

    let mut a_witness_input: Vec<SF<Fr>> = a_values.iter().map(|v| SF::from_public(Fr::from(*v))).collect();
    let mut b_witness_input: Vec<SF<Fr>> = b_values.iter().map(|v| SF::from_public(Fr::from(*v))).collect();

    let challenge = SF::from_shared(Fr::rand(&mut rng));
    let y_inv = challenge.reveal();

    let ver = run_ipp(
        &a_witness_input,
        &b_witness_input,
        &public_input,
        y_inv,
    );

    Net::deinit_network();
}
