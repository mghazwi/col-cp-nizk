mod test_legogroth16 {
    use super::*;
    use crate::globals::{get_n_parties, get_party_id, set_experiment_name, set_phase, set_phase_time};
    use crate::mpc::spdz_field::SpdzSharedField as SharedField;
    use crate::mpc::spdz_field::SpdzSharedFieldTrait as SharedFieldTrait;
    use crate::mpc::spdz_group::group::SpdzSharedAffineTrait as SharedAffineTrait;
    use crate::mpc::spdz_pairing::MpcPairing;
    use crate::mpc::spdz_pairing::MpcPairingTrait;
    use crate::mpc::spdz_witness_distribution::distribute_witnesses;
    use crate::network::Net;
    use crate::snark::circuit::VerifyMultiplicationCircuit;
    use crate::snark::legogroth16::verifier::prepare_verifying_key;
    use crate::snark::legogroth16::ConstraintSynthesizer;
    use crate::snark::legogroth16::{data_structures::Proof, LegoGroth16};
    use crate::mpc::spdz::Spdz;
    use ark_bls12_381::{Bls12_381, FrConfig};
    use ark_ec::pairing::Pairing;
    use ark_ff::PrimeField;
    use ark_ff::{Fp, MontBackend};
    use ark_snark::CircuitSpecificSetupSNARK;
    use ark_snark::SNARK;
    use ark_std::UniformRand;
    use ark_std::{end_timer, start_timer, test_rng};
    use num_bigint::BigUint;
    use rand::RngCore;
    use rand::SeedableRng;
    use std::env;
    use std::fmt::Debug;
    use std::str::FromStr;
    use tokio::time::Instant;

    fn reveal_proof<B, P>(proof: Proof<B, P>) -> Proof<B, P>
        where
            B: Pairing,
            P: MpcPairingTrait<B>,
    {
        let a = proof.a;
        let b = proof.b;
        let c: <P as MpcPairingTrait<B>>::G1Affine = proof.c;
        let d = proof.d;
        let link_d = proof.link_d;
        let link_pi = proof.link_pi;

        let revealed_a = a.reveal();
        let revealed_b = b.reveal();
        let revealed_c = c.reveal();
        let revealed_d = d.reveal();
        let revealed_link_d = link_d.reveal();
        let revealed_link_pi = link_pi.reveal();

        Proof {
            a: revealed_a,
            b: revealed_b,
            c: revealed_c,
            d: revealed_d,
            link_d: revealed_link_d,
            link_pi: revealed_link_pi,
        }
    }

    #[test]
    fn legogroth16() {
        let args: Vec<String> = env::args().collect();

        // Parse arguments
        let party_id = args[4].parse::<usize>().unwrap();
        let my_value_arg = args[5].parse::<usize>().unwrap();
        let n_constraints = args[6].parse::<usize>().unwrap();
        let n_parties = args[7].parse::<usize>().unwrap();

        // Experiment setup
        let experiment_name = String::from("legogroth/")
            + n_parties.to_string().as_str()
            + "/"
            + n_constraints.to_string().as_str()
            + "/";
        set_experiment_name(&experiment_name);

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let my_value = <Bls12_381 as Pairing>::ScalarField::from(my_value_arg as u64).into();
        let my_value_shares = Spdz::<Bls12_381, MpcPairing<Bls12_381>>::generate_shares_for_value(
            n_parties, my_value, &mut rng,
        );
        let public_input = vec![<Bls12_381 as Pairing>::ScalarField::from(91u64).into()];

        type B = Bls12_381;
        type P = MpcPairing<B>;

        Net::init_network(party_id, n_parties);

        let groth_16_timer = start_timer!(|| "Groth16");

        // // ### Witness distribution ###
        set_phase("witness_distribution");
        let witness_distribution_timer = start_timer!(|| "witness_distribution");
        let witness_size = 2;
        let witness_input = distribute_witnesses(
            party_id,
            my_value_shares,
            // n_constraints,
            n_parties,
            // witness_size,
        );
        end_timer!(witness_distribution_timer);
        set_phase_time(witness_distribution_timer.time.elapsed().as_micros());

        // ### Setup ###
        set_phase("setup");
        let setup_timer = start_timer!(|| "Setup");
        let (pk, vk) = {
            let c = VerifyMultiplicationCircuit {
                a: None,
                b: None,
                n: n_constraints,
            };

            let pedersen_bases = (0..3)
                .map(|_| <P as MpcPairingTrait<B>>::G1::rand(&mut rng).into())
                .collect::<Vec<_>>();

            LegoGroth16::<B, P>::setup(c, &pedersen_bases, &mut rng).unwrap()
        };

        let pvk = prepare_verifying_key(&vk);

        let a = witness_input[0];
        let b = witness_input[1];
        let c: <P as MpcPairingTrait<B>>::ScalarField = public_input[0];

        let circuit = VerifyMultiplicationCircuit {
            a: Some(a),
            b: Some(b),
            n: n_constraints,
        };
        end_timer!(setup_timer);
        set_phase_time(setup_timer.time.elapsed().as_micros());

        // ### Proving ###
        set_phase("proving");
        let prover_timer = start_timer!(|| "Prover");
        let v = <P as MpcPairingTrait<B>>::ScalarField::rand(&mut rng);
        let link_v = <P as MpcPairingTrait<B>>::ScalarField::rand(&mut rng);
        let t = Instant::now();
        let proof = LegoGroth16::<B, P>::prove(&pk, circuit, v, link_v, &mut rng).unwrap();
        let d = t.elapsed();
        println!("prover {} time = {:?}", get_party_id(), d);
        end_timer!(prover_timer);
        set_phase_time(prover_timer.time.elapsed().as_micros());

        // // ### Reveal proof ###
        set_phase("reveal");
        let reveal_timer = start_timer!(|| "Reveal proof");
        let proof = reveal_proof(proof);
        end_timer!(reveal_timer);
        set_phase_time(reveal_timer.time.elapsed().as_micros());

        // ### Verification ###
        // set_phase("verification");
        // let verify_timer = start_timer!(|| "Verify proof");
        // assert!(LegoGroth16::<B, P>::verify_proof(&pvk, &proof, &[c.into()],).unwrap(),);
        // assert!(
        //     LegoGroth16::<B, P>::verify_commitment(&pvk, &proof, &[c.into()], &v, &link_v).unwrap()
        // );
        // end_timer!(verify_timer);
        // set_phase_time(verify_timer.time.elapsed().as_micros());

        // ### Wrapping up ###
        end_timer!(groth_16_timer);
        set_phase("total");
        set_phase_time(groth_16_timer.time.elapsed().as_micros());
        Net::deinit_network();
    }
}
