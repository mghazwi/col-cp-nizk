use std::env;
use crate::bp::errors::R1CSError;
use crate::bp::r1cs_mpc::{mpc_constraint_system::ConstraintSystem, mpc_linear_combination::LinearCombination,
                          mpc_prover::MpcProver as Prover, proof::SharedR1CSProof, mpc_generators::{BulletproofGens, PedersenGens}};
use crate::bp::r1cs::{R1CSProof, Verifier, ConstraintSystem as verifierCS, LinearCombination as verifierLC};
use ark_bls12_381::Fr;
use ark_bls12_381::G1Affine as G;
use ark_bls12_381::Bls12_381 as P;
use ark_std::UniformRand;
use merlin::Transcript;
use rand::SeedableRng;
use crate::bp::transcript_381::TranscriptProtocol;
use crate::mpc::spdz_field::{SpdzSharedField as SF, SpdzSharedFieldTrait};
use crate::mpc::spdz_group::g1_affine::SpdzSharedG1Affine as SG;
use crate::network::Net;

use crate::bp::generators_381::{PedersenGens as verifierGens, BulletproofGens as verifierBPGens};

fn cs_multiply<CS: ConstraintSystem>(
    cs: &mut CS,
    a1: LinearCombination,
    a2: LinearCombination,
    b1: LinearCombination,
    b2: LinearCombination,
    c1: LinearCombination,
    c2: LinearCombination,
) {
    let (_, _, c_var) = cs.multiply(a1 + a2, b1 + b2);
    cs.constrain(c1 + c2 - c_var);
}
fn verifier_cs_multiply<CS: verifierCS>(
    cs: &mut CS,
    a1: verifierLC,
    a2: verifierLC,
    b1: verifierLC,
    b2: verifierLC,
    c1: verifierLC,
    c2: verifierLC,
) {
    let (_, _, c_var) = cs.multiply(a1 + a2, b1 + b2);
    cs.constrain(c1 + c2 - c_var);
}

fn gen_proof(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    a1: u64,
    a2: u64,
    b1: u64,
    b2: u64,
    c1: u64,
    c2: u64,
) -> Result<(R1CSProof, Vec<SG<P>>), R1CSError> {
    let mut transcript = Transcript::new(b"R1CSExampleGadget");

    // TODO: rng not safe
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(5u64);

    let mut prover = Prover::new(pc_gens, &mut transcript);

    let (commitments, vars): (Vec<_>, Vec<_>) = [a1, a2, b1, b2, c1]
        .into_iter()
        .map(|x| prover.commit(SF::<Fr>::from_public(Fr::from(x)), SF::<Fr>::from_public(Fr::rand(&mut rng))))
        .unzip();

    cs_multiply(
        &mut prover,
        vars[0].into(),
        vars[1].into(),
        vars[2].into(),
        vars[3].into(),
        vars[4].into(),
        SF::<Fr>::from_public(Fr::from(c2)).into(),
    );

    let proof = prover.prove(bp_gens);

    Ok((proof.unwrap().reveal().unwrap(), commitments))
}

fn verify_proof(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    c2: u64,
    proof: R1CSProof,
    commitments: Vec<G>,
) -> Result<(), R1CSError> {
    let mut transcript = Transcript::new(b"R1CSExampleGadget");

    let pc_gens_f = verifierGens{
        B: pc_gens.B.get_share_group_val(),
        B_blinding: pc_gens.B_blinding.get_share_group_val(),
    };
    let bp_gens_f = verifierBPGens {
      party_capacity: bp_gens.party_capacity,
        gens_capacity: bp_gens.gens_capacity,
        G_vec: bp_gens.G_vec.iter().map(|gv| gv.iter().map(|g|g.get_share_group_val()).collect()).collect(),
        H_vec: bp_gens.H_vec.iter().map(|hv| hv.iter().map(|h|h.get_share_group_val()).collect()).collect()
    };

    let mut verifier = Verifier::new(&pc_gens_f,&mut transcript);

    let vars: Vec<_> = commitments.iter().map(|v| verifier.commit(*v)).collect();

    verifier_cs_multiply(
        &mut verifier,
        vars[0].into(),
        vars[1].into(),
        vars[2].into(),
        vars[3].into(),
        vars[4].into(),
        Fr::from(c2).into(),
    );

    verifier
        .verify(&proof, &bp_gens_f)
        .map_err(|_| R1CSError::VerificationError)
}

fn run_mpc_bp_r1cs(
    a1: u64,
    a2: u64,
    b1: u64,
    b2: u64,
    c1: u64,
    c2: u64,
) -> Result<(), R1CSError> {
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(128, 1);

    let (proof, commitments) = gen_proof(&pc_gens, &bp_gens, a1, a2, b1, b2, c1, c2).unwrap();

    let commitments = commitments.iter().map(|c|c.get_share_group_val()).collect();

    verify_proof(&pc_gens, &bp_gens, c2, proof, commitments)
}

#[test]
fn test_mpc_r1cs_on_public_val() {
    let args: Vec<String> = env::args().collect();

    // Parse arguments
    let party_id = 0;
    let n_parties = 1;

    Net::init_network(party_id, n_parties);
    assert!(run_mpc_bp_r1cs(3, 4, 6, 1, 40, 9).is_ok());
    assert!(run_mpc_bp_r1cs(3, 4, 6, 1, 40, 10).is_err());

    Net::deinit_network();
}