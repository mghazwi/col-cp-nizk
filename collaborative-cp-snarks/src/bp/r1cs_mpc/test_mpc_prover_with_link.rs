use std::{env, iter};
use std::ops::Mul;
use std::time::Instant;

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

use ark_std::{cfg_iter, rand::RngCore, vec::Vec, UniformRand, start_timer, end_timer};
use ark_std::iterable::Iterable;
use ark_std::rand::{prelude::StdRng, SeedableRng};
use crate::globals::{get_party_id, set_experiment_name, set_phase, set_phase_time};

use crate::mpc::spdz_field::{SpdzSharedField as SF, SpdzSharedFieldTrait};
use crate::mpc::spdz_group::g1_affine::SpdzSharedG1Affine as SG;
use crate::mpc::spdz_group::g2_affine::SpdzSharedG2Affine as SG2;
use crate::mpc::spdz_group::g1::SpdzSharedG1 as G1;
use crate::mpc::spdz_group::group::{SpdzSharedAffine, SpdzSharedAffineTrait};
use crate::network::Net;
use crate::mpc::{
    spdz::Spdz,
    spdz_pairing::MpcPairing
};
use crate::mpc::spdz_pairing::MpcPairingTrait;
use crate::snark::legogroth16::link::{PESubspaceSnark, PP, SparseMatrix, SubspaceSnark, SubspaceSnarkProvingKey};
use crate::snark::legogroth16::link::SubspaceSnarkVerificationKey;
use crate::snark::legogroth16::prover::custom_msm;
use futures_util::TryFutureExt;

use crate::bp::r1cs::{R1CSProof, Verifier, ConstraintSystem as verifierCS, LinearCombination as verifierLC, Variable as verifierVar};
use crate::bp::generators_381::{PedersenGens as verifierGens, BulletproofGens as verifierBPGens};

struct DummyCircuit;

impl DummyCircuit {
    fn cs_multiply<CS: ConstraintSystem>(
        cs: &mut CS,
        a: Variable,
        b: Variable,
        expected_out: Variable,
    ) -> Result<(), R1CSError> {
        let (_, _, mul_out) = cs
            .multiply(
                a.into(),
                b.into()
            );

        cs.constrain(mul_out - expected_out);
        // println!("num constraints = {}", cs.num_constraints());
        Ok(())
    }

    fn mul_n_const<CS: ConstraintSystem>(
        cs: &mut CS,
        a: Variable,
        b: Variable,
        expected_out: Variable,
        n_const: usize
    ) -> Result<(), R1CSError> {
        for _ in 0..n_const {
            let (a, b, mul_out) = cs
                .multiply(
                    a.into(),
                    b.into()
                );
        }
        // cs.constrain(mul_out - expected_out);
        // println!("num constraints = {}", cs.constraints());

        Ok(())
    }

    fn verifier_gen_const<CS: verifierCS>(
        cs: &mut CS,
        a: verifierVar,
        b: verifierVar,
        expected_out: verifierVar,
    ) -> Result<(), R1CSError> {
        let (_, _, mul_out) = cs.multiply(
             a.into(),
             b.into(),
        );

        cs.constrain(mul_out - expected_out);

        Ok(())
    }

    fn gen_proof(
        a: SF<Fr>,
        b: SF<Fr>,
        expected_out: SF<Fr>,
    ) -> Result<
        (
            SharedR1CSProof,
            SG<P>,
            SG<P>,
            SG<P>,
        ),
        String,
    > {
        let mut rng = StdRng::seed_from_u64(5u64);

        let pc_gens = PedersenGens::default();
        let mut prover_transcript = Transcript::new("test".as_bytes());
        let mut prover = MpcProver::new(&pc_gens, &mut prover_transcript);

        let v = SF::<Fr>::rand(&mut rng);

        let (a_c, a_var) =
            prover.commit(a,v.clone());

        let (b_c, b_var) =
            prover.commit(b,v.clone());

        let (c_commit, c_var) = prover
            .commit(expected_out, SF::<Fr>::from_public(Fr::from(1)));

        Self::cs_multiply(&mut prover, a_var, b_var, c_var)
            .map_err(|err| format!("Error: {:?}", err))?;

        let bp_gens =
            BulletproofGens::new(16, 1 );

        let proof = prover
            .prove(&bp_gens).unwrap();

        let witness_num = 2;
        let link_rows = 2;
        let link_cols = witness_num + 2;

        let link_pp =
            PP
            {
                l: link_rows,
                t: link_cols,
                g1: SG::<P>::generator(),
                g2: SG2::<P>::generator(),
            };

        type MP = MpcPairing<P>;

        let pedersen_bases = (0..witness_num +1)
            .map(|_| SG::<P>::rand(&mut rng))
            .collect::<Vec<_>>();

        let pc_gens_n = vec![pc_gens.B; witness_num];

        let mut link_m =
            SparseMatrix::<SG<P>>::new(link_rows, link_cols);
        link_m.insert_row_slice(0, 0, &pedersen_bases);
        link_m.insert_row_slice(
            1,
            0,
            &pc_gens_n,
        );
        link_m.insert_row_slice(1, pc_gens_n.len() + 1, &[pc_gens.B]);

        let (link_ek, link_vk) = PESubspaceSnark::<P, MP>::keygen(&mut rng, &link_pp, link_m);

        let link_v = SF::<Fr>::rand(&mut rng);

        let w_with_link_hider =
            [&[a],&[b], &[link_v][..]].concat();
        let w_with_hiders =
            [&w_with_link_hider, &[v+v][..]].concat(); // v+v is used here because each value in a is committed with v and given 2 values in vector a then v+v

        let link_pi = PESubspaceSnark::<P, MP>::prove(
            &link_pp,
            &link_ek,
            &w_with_hiders,
        );

        let mut acc = SG::<P>::zero();

        // TODO: replace with a call to msm

        for (base, scalar) in pedersen_bases.iter().zip(w_with_link_hider.iter()) {
            acc =  (acc + base.mul(*scalar)).into_affine();
        }
        let g_d_link = acc;
        //
        let a_combined_com = a_c+b_c;
        //
        let g_d_link_open = acc.reveal();

        let commitments = vec![g_d_link_open, a_combined_com.into_affine()];

        let link_pi_open = link_pi.reveal();

        assert!( PESubspaceSnark::<P, MP>::verify(
            &link_pp,
            &link_vk,
            &commitments,
            &link_pi_open,
        ));
        Ok((proof, a_c, b_c, c_commit))
    }

    fn gen_proof_n_const(
        a: SF<Fr>,
        b: SF<Fr>,
        expected_out: SF<Fr>,
        n_const: usize
    ) -> Result<
        (
            SharedR1CSProof,
            SG<P>,
            SG<P>,
            SG<P>,
        ),
        String,
    > {
        // Setup
        let mut rng = StdRng::seed_from_u64(5u64);

        // Create the proof system
        let pc_gens = PedersenGens::default();
        let mut prover_transcript = Transcript::new("test".as_bytes());
        let mut prover = MpcProver::new(&pc_gens, &mut prover_transcript);

        let v = SF::<Fr>::rand(&mut rng);

        let (a_c, a_var) =
            prover.commit(a,v.clone());

        let (b_c, b_var) =
            prover.commit(b,v.clone());

        let (c_commit, c_var) = prover
            .commit(expected_out, SF::<Fr>::from_public(Fr::from(1)));

        let setup_time = Instant::now();
        Self::mul_n_const(&mut prover, a_var, b_var, c_var, n_const)
            .map_err(|err| format!("Error: {:?}", err))?;
        let setup_duration = setup_time.elapsed();
        // println!("setup time = {:?}", setup_duration);

        let bp_gens =
            BulletproofGens::new(n_const, 1);

        let proof = prover
            .prove_ipa(&bp_gens).unwrap();

        let witness_num = 2;
        let link_rows = 2;
        let link_cols = witness_num + 2;

        let link_pp =
            PP
            {
                l: link_rows,
                t: link_cols,
                g1: SG::<P>::generator(),
                g2: SG2::<P>::generator(),
            };

        type MP = MpcPairing<P>;

        let pedersen_bases = (0..witness_num +1)
            .map(|_| SG::<P>::rand(&mut rng))
            .collect::<Vec<_>>();

        let pc_gens_n = vec![pc_gens.B; witness_num];

        let mut link_m =
            SparseMatrix::<SG<P>>::new(link_rows, link_cols);
        link_m.insert_row_slice(0, 0, &pedersen_bases);
        link_m.insert_row_slice(
            1,
            0,
            &pc_gens_n,
        );
        link_m.insert_row_slice(1, pc_gens_n.len() + 1, &[pc_gens.B]);

        let (link_ek, link_vk) = PESubspaceSnark::<P, MP>::keygen(&mut rng, &link_pp, link_m);

        let link_v = SF::<Fr>::rand(&mut rng);

        let w_with_link_hider =
            [&[a],&[b], &[link_v][..]].concat();
        let w_with_hiders =
            [&w_with_link_hider, &[v+v][..]].concat(); // v+v is used here because each value in a is committed with v and given 2 values in vector a then v+v

        let link_time = Instant::now();
        let link_pi = PESubspaceSnark::<P, MP>::prove(
            &link_pp,
            &link_ek,
            &w_with_hiders,
        );
        let link_duration = link_time.elapsed();
        // println!("link time = {:?}", link_duration);

        let mut acc = SG::<P>::zero();

        // TODO: replace with a call to msm
        for (base, scalar) in pedersen_bases.iter().zip(w_with_link_hider.iter()) {
            acc =  (acc + base.mul(*scalar)).into_affine();
        }
        let g_d_link = acc;
        let a_combined_com = a_c+b_c;
        let g_d_link_open = acc.reveal();

        let commitments = vec![g_d_link_open, a_combined_com.into_affine()];

        let link_pi_open = link_pi.reveal();

        assert!( PESubspaceSnark::<P, MP>::verify(
            &link_pp,
            &link_vk,
            &commitments,
            &link_pi_open,
        ));
        Ok((proof, a_c, b_c, c_commit))
    }

    fn verify_proof(
        proof: SharedR1CSProof,
        a_commit: SG<P>,
        b_commit: SG<P>,
        c_commit: SG<P>,
    ) -> Result<(), R1CSError> {
        let pc_gens = verifierGens::default();
        let bp_gens =
            verifierBPGens::new(16 /* gens_capacity */, 1 /* party_capacity */);

        let opened_proof = proof.reveal().unwrap();
        let mut opened_a_comm = a_commit.get_share_group_val();

        let mut opened_b_comm = b_commit.get_share_group_val();

        let opened_c_comm = c_commit.get_share_group_val();

        let mut verifier_transcript = Transcript::new("test".as_bytes());
        let mut verifier = Verifier::new(&pc_gens, &mut verifier_transcript);

        let a_input = verifier.commit(opened_a_comm);

        let b_input = verifier.commit(opened_b_comm);

        let c_input = verifier.commit(opened_c_comm);

        Self::verifier_gen_const(&mut verifier, a_input, b_input, c_input);

        verifier
            .verify(&opened_proof, &bp_gens)
    }
}


#[test]
fn test_mpc_bp_r1cs_on_shares() {
    let mut rng = StdRng::seed_from_u64(5u64);

    let args: Vec<String> = env::args().collect();

    // Parse arguments
    let party_id = args[4].parse::<usize>().unwrap();
    let n_parties = args[5].parse::<usize>().unwrap();

    // Experiment setup
    let experiment_name = String::from("bp_r1cs/")
        + n_parties.to_string().as_str()
        + "/";
    set_experiment_name(&experiment_name);

    Net::init_network(party_id, n_parties);
    let a_value: u64 = 2;
    let b_value: u64 = 4;

    let expected_result = 8u64;

    let a_value_shares: Vec<SF<Fr>> =
        Spdz::<P, MpcPairing<P>>::generate_shares_for_value(
            n_parties, Fr::from(a_value), &mut rng,
        );

    let b_value_shares: Vec<SF<Fr>> =
        Spdz::<P, MpcPairing<P>>::generate_shares_for_value(
            n_parties, Fr::from(b_value), &mut rng,
        );

    let a_witness_input = a_value_shares[party_id];

    let b_witness_input = b_value_shares[party_id];


    let (proof, a_commit, b_commit, c_commit) = DummyCircuit::gen_proof(
        a_witness_input,
        b_witness_input,
        SF::<Fr>::from(expected_result),
    ).unwrap();

    assert!(DummyCircuit::verify_proof(proof, a_commit, b_commit, c_commit).is_ok());

    Net::deinit_network();
}

#[test]
fn test_mpc_bp_r1cs_n_const() {
    let mut rng = StdRng::seed_from_u64(5u64);

    let args: Vec<String> = env::args().collect();

    // Parse arguments
    let party_id = args[4].parse::<usize>().unwrap();
    let n_parties = args[5].parse::<usize>().unwrap();
    let n_const = args[6].parse::<usize>().unwrap();

    // Experiment setup
    let experiment_name = String::from("bp_r1cs/")
        + n_parties.to_string().as_str()
        + "/";
    set_experiment_name(&experiment_name);

    Net::init_network(party_id, n_parties);
    let a_value: u64 = 2;
    let b_value: u64 = 4;

    let expected_result = 8u64;

    let a_value_shares: Vec<SF<Fr>> =
        Spdz::<P, MpcPairing<P>>::generate_shares_for_value(
            n_parties, Fr::from(a_value), &mut rng,
        );

    let b_value_shares: Vec<SF<Fr>> =
        Spdz::<P, MpcPairing<P>>::generate_shares_for_value(
            n_parties, Fr::from(b_value), &mut rng,
        );

    let a_witness_input = a_value_shares[party_id];

    let b_witness_input = b_value_shares[party_id];


    let (proof, a_commit, b_commit, c_commit) = DummyCircuit::gen_proof_n_const(
        a_witness_input,
        b_witness_input,
        SF::<Fr>::from(expected_result),
        n_const
    ).unwrap();

    // assert!(SimpleCircuit::verify(proof, a_commit, b_commit, c_commit).is_ok());

    Net::deinit_network();
}

#[test]
fn test_mpc_bp_r1cs_n_const_with_link() {
    let mut rng = StdRng::seed_from_u64(5u64);

    let args: Vec<String> = env::args().collect();

    // Parse arguments
    let party_id = args[4].parse::<usize>().unwrap();
    let n_parties = args[5].parse::<usize>().unwrap();
    let n_const = args[6].parse::<usize>().unwrap();

    // Experiment setup
    let experiment_name = String::from("bp_r1cs_link_bench/")
        + n_parties.to_string().as_str()
        + "/"
        + (n_const*2).to_string().as_str()
        + "/";
    set_experiment_name(&experiment_name);

    Net::init_network(party_id, n_parties);
    let a_value: u64 = 2;
    let b_value: u64 = 4;

    let expected_result = 8u64;

    let a_value_shares: Vec<SF<Fr>> =
        Spdz::<P, MpcPairing<P>>::generate_shares_for_value(
            n_parties, Fr::from(a_value), &mut rng,
        );

    let b_value_shares: Vec<SF<Fr>> =
        Spdz::<P, MpcPairing<P>>::generate_shares_for_value(
            n_parties, Fr::from(b_value), &mut rng,
        );

    let a_witness_input = a_value_shares[party_id];

    let b_witness_input = b_value_shares[party_id];

    let a = a_witness_input;
    let b = b_witness_input;
    let expected_out = SF::<Fr>::from(expected_result);

    let mut rng = StdRng::seed_from_u64(5u64);

    let pc_gens = PedersenGens::default();
    let mut prover_transcript = Transcript::new("test".as_bytes());
    let mut prover = MpcProver::new(&pc_gens, &mut prover_transcript);

    let v = SF::<Fr>::rand(&mut rng);

    let (a_c, a_var) =
        prover.commit(a,v.clone());

    let (b_c, b_var) =
        prover.commit(b,v.clone());

    let (c_commit, c_var) = prover
        .commit(expected_out, SF::<Fr>::from_public(Fr::from(1)));

    let setup_time = Instant::now();
    DummyCircuit::mul_n_const(&mut prover, a_var, b_var, c_var, n_const)
        .map_err(|err| format!("Error: {:?}", err));
    let setup_duration = setup_time.elapsed();
    // println!("setup time = {:?}", setup_duration);

    let bp_gens =
        BulletproofGens::new(n_const, 1);

    set_phase("proving");
    let prover_timer = start_timer!(|| "Prover");

    let proof = prover
        // .prove(&bp_gens).await.unwrap();
        .prove(&bp_gens).unwrap();

    end_timer!(prover_timer);
    set_phase_time(prover_timer.time.elapsed().as_micros());

    // link
    let witness_num = 2;
    let link_rows = 2;
    let link_cols = witness_num + 2;

    let link_pp =
        PP
        {
            l: link_rows,
            t: link_cols,
            g1: SG::<P>::generator(),
            g2: SG2::<P>::generator(),
        };

    type MP = MpcPairing<P>;

    let pedersen_bases = (0..witness_num +1)
        .map(|_| SG::<P>::rand(&mut rng))
        .collect::<Vec<_>>();

    let pc_gens_n = vec![pc_gens.B; witness_num];

    let mut link_m =
        SparseMatrix::<SG<P>>::new(link_rows, link_cols);
    link_m.insert_row_slice(0, 0, &pedersen_bases);
    link_m.insert_row_slice(
        1,
        0,
        &pc_gens_n,
    );
    link_m.insert_row_slice(1, pc_gens_n.len() + 1, &[pc_gens.B]);

    let (link_ek, link_vk) = PESubspaceSnark::<P, MP>::keygen(&mut rng, &link_pp, link_m);

    let link_v = SF::<Fr>::rand(&mut rng);

    let w_with_link_hider =
        [&[a],&[b], &[link_v][..]].concat();
    let w_with_hiders =
        [&w_with_link_hider, &[v+v][..]].concat(); // v+v is used here because each value in a is committed with v and given 2 values in vector a then v+v

    set_phase("link");
    let link_timer = start_timer!(|| "linking");

        let link_time = Instant::now();
        let link_pi = PESubspaceSnark::<P, MP>::prove(
            &link_pp,
            &link_ek,
            &w_with_hiders,
        );

    end_timer!(link_timer);
    set_phase_time(link_timer.time.elapsed().as_micros());
    let link_duration = link_time.elapsed();
    // println!("link time = {:?}", link_duration);

    let mut acc = SG::<P>::zero();

    // TODO: replace with a call to msm

    for (base, scalar) in pedersen_bases.iter().zip(w_with_link_hider.iter()) {
        acc =  (acc + base.mul(*scalar)).into_affine();
    }
    let g_d_link = acc;
    let a_combined_com = a_c+b_c;
    let g_d_link_open = acc.reveal();

    let commitments = vec![g_d_link_open, a_combined_com.into_affine()];

    let link_pi_open = link_pi.reveal();

    assert!( PESubspaceSnark::<P, MP>::verify(
        &link_pp,
        &link_vk,
        &commitments,
        &link_pi_open,
    ));

    // assert!(SimpleCircuit::verify(proof, a_commit, b_commit, c_commit).is_ok());

    Net::deinit_network();
}