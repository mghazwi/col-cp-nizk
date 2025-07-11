use std::env;
use crate::bp::errors::R1CSError;
use crate::bp::r1cs::{ConstraintSystem, LinearCombination, Prover, R1CSProof, Verifier};
use ark_bls12_381::Fr;
use ark_bls12_381::G1Affine as G;
use ark_std::{end_timer, start_timer, UniformRand};
use merlin::Transcript;
use rand::SeedableRng;
use crate::bp::generators_381::{BulletproofGens, PedersenGens};
use crate::bp::transcript_381::TranscriptProtocol;
use crate::globals::{print_stats, set_experiment_name, set_phase, set_phase_time};
use crate::network::Net;

fn multiply_gadget<CS: ConstraintSystem>(
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

fn multiply_n_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    a: LinearCombination,
    b: LinearCombination,
    n_const: usize
) {
    for _ in 0..n_const {
            let (a, b, mul_out) = cs
                .multiply(
                    a.clone().into(),
                    b.clone().into()
                );
        }
    // println!("num constraints = {}", cs.constraints());
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
) -> Result<(R1CSProof, Vec<G>), R1CSError> {
    let mut transcript = Transcript::new(b"R1CSExampleGadget");

    // TODO: rng not safe
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(5u64);

    let mut prover = Prover::new(pc_gens, &mut transcript);

    let (commitments, vars): (Vec<_>, Vec<_>) = [a1, a2, b1, b2, c1]
        .into_iter()
        .map(|x| prover.commit(Fr::from(x), Fr::rand(&mut rng)))
        .unzip();

    multiply_gadget(
        &mut prover,
        vars[0].into(),
        vars[1].into(),
        vars[2].into(),
        vars[3].into(),
        vars[4].into(),
        Fr::from(c2).into(),
    );

    let proof = prover.prove(bp_gens)?;

    Ok((proof, commitments))
}

fn gen_proof_n_const(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    a: u64,
    b: u64,
    n_const: usize,
) -> Result<(R1CSProof, Vec<G>), R1CSError> {

    // Experiment setup
    let n_parties = 1;
    let experiment_name = String::from("single_bp/")
        + n_parties.to_string().as_str()
        + "/"
        + n_const.to_string().as_str()
        + "/";
    set_experiment_name(&experiment_name);

    Net::init_network(0, n_parties);

    let single_bp_timer = start_timer!(|| "single_bp");

    set_phase("setup");
    let setup_timer = start_timer!(|| "Setup");

    let mut transcript = Transcript::new(b"R1CSExampleGadget");

    // TODO: rng not safe
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(5u64);

    let mut prover = Prover::new(pc_gens, &mut transcript);

    let (commitments, vars): (Vec<_>, Vec<_>) = [a, b]
        .into_iter()
        .map(|x| prover.commit(Fr::from(x), Fr::rand(&mut rng)))
        .unzip();

    multiply_n_gadget(
        &mut prover,
        vars[0].into(),
        vars[1].into(),
        n_const,
    );

    end_timer!(setup_timer);
    set_phase_time(setup_timer.time.elapsed().as_micros());

    set_phase("proving");
    let prover_timer = start_timer!(|| "Prover");

    let proof = prover.prove(bp_gens)?;

    end_timer!(prover_timer);
    set_phase_time(prover_timer.time.elapsed().as_micros());

    end_timer!(single_bp_timer);
    set_phase("total");
    set_phase_time(single_bp_timer.time.elapsed().as_micros());

    print_stats();

    Ok((proof, commitments))
}

fn verify_proof(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    c2: u64,
    proof: R1CSProof,
    commitments: Vec<G>,
) -> Result<(), R1CSError> {
    let mut transcript = Transcript::new(b"R1CSExampleGadget");

    let mut verifier = Verifier::new(pc_gens,&mut transcript);

    let vars: Vec<_> = commitments.iter().map(|V| verifier.commit(*V)).collect();

    multiply_gadget(
        &mut verifier,
        vars[0].into(),
        vars[1].into(),
        vars[2].into(),
        vars[3].into(),
        vars[4].into(),
        Fr::from(c2).into(),
    );

    verifier
        .verify(&proof, &bp_gens)
        .map_err(|_| R1CSError::VerificationError)
}

fn run_bp_r1cs(
    a1: u64,
    a2: u64,
    b1: u64,
    b2: u64,
    c1: u64,
    c2: u64,
) -> Result<(), R1CSError> {
    // Common
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(128, 1);

    let (proof, commitments) = gen_proof(&pc_gens, &bp_gens, a1, a2, b1, b2, c1, c2)?;

    verify_proof(&pc_gens, &bp_gens, c2, proof, commitments)
}

fn run_bp_r1cs_n_const(
    a: u64,
    b: u64,
    n_const: usize,
) -> Result<(), R1CSError> {
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(n_const, 1);

    let (proof, commitments) = gen_proof_n_const(&pc_gens, &bp_gens, a, b, n_const)?;

    // example_gadget_verify(&pc_gens, &bp_gens, c2, proof, commitments)
    Ok(())
}

#[test]
fn test_bp_r1cs() {
    assert!(run_bp_r1cs(3, 4, 6, 1, 40, 9).is_ok());
    assert!(run_bp_r1cs(3, 4, 6, 1, 40, 10).is_err());
}

#[test]
fn test_bp_r1cs_n_const() {
    let args: Vec<String> = env::args().collect();
    let n_const = args[4].parse::<usize>().unwrap();
    assert!(run_bp_r1cs_n_const(2, 4, n_const).is_ok());

}