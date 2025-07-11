mod test_groth16 {
    use super::*;
    use crate::globals::{get_n_parties, get_party_id, set_experiment_name, set_phase, set_phase_time};
    use crate::mpc::spdz_field::SpdzSharedField;
    use crate::mpc::spdz_field::SpdzSharedFieldTrait;
    use crate::mpc::spdz_group::group::{SpdzSharedAffine, SpdzSharedAffineTrait, SpdzSharedGroupTrait};
    use crate::mpc::spdz_group::group::SpdzSharedGroup;
    use crate::mpc::spdz_pairing::MpcPairing;
    use crate::mpc::spdz_pairing::MpcPairingTrait;
    use crate::mpc::spdz_witness_distribution::distribute_witnesses;
    use crate::network::Net;
    use crate::snark::circuit::VerifyMultiplicationCircuit;
    use crate::snark::groth16::ConstraintSynthesizer;
    use crate::snark::groth16::{data_structures::Proof, Groth16};
    use crate::mpc::spdz::Spdz;
    use ark_bls12_381::{Bls12_381, FrConfig};
    use ark_ec::pairing::Pairing;
    use ark_ff::{Field, PrimeField, Zero};
    use ark_ff::{Fp, MontBackend};
    use ark_snark::CircuitSpecificSetupSNARK;
    use ark_snark::SNARK;
    use ark_std::{end_timer, start_timer, test_rng, UniformRand};
    use num_bigint::BigUint;
    use rand::{Rng, RngCore};
    use rand::SeedableRng;
    use std::env;
    use std::fmt::Debug;
    use std::ops::AddAssign;
    use std::ops::SubAssign;
    use std::str::FromStr;
    use ark_ec::{AffineRepr, Group};
    use tokio::time::Instant;
    use crate::mpc::spdz_group::g1::SpdzSharedG1;
    use crate::mpc::spdz_group::g1_affine::SpdzSharedG1Affine;
    use crate::mpc::spdz_group::g2::SpdzSharedG2;
    use crate::mpc::spdz_group::g2_affine::SpdzSharedG2Affine;
    use crate::snark::gwas_circuits::maf_circuit::MAFCircuit;
    use crate::stats::StatsField::SharedGroup;

    fn reveal_proof<B, P>(proof: Proof<B, P>) -> Proof<B, P>
    where
        B: Pairing,
        P: MpcPairingTrait<B>,
    {
        let a = proof.a;
        let b = proof.b;
        let c = proof.c;

        let revealed_a = a.reveal();
        let revealed_b = b.reveal();
        let revealed_c = c.reveal();

        Proof {
            a: revealed_a,
            b: revealed_b,
            c: revealed_c,
        }
    }

    #[test]
    fn groth16() {
        let args: Vec<String> = env::args().collect();

        // Parse arguments
        let party_id = args[4].parse::<usize>().unwrap();
        let my_value_arg = args[5].parse::<usize>().unwrap();
        let n_constraints = args[6].parse::<usize>().unwrap();
        let n_parties = args[7].parse::<usize>().unwrap();

        // Experiment setup
        let experiment_name = String::from("groth/")
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

        // ### Witness distribution ###
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
        // .await;
        end_timer!(witness_distribution_timer);
        set_phase_time(witness_distribution_timer.time.elapsed().as_micros());

        // // ### Setup ###
        set_phase("setup");
        let setup_timer = start_timer!(|| "Setup");
        let (pk, vk) = {
            let c = VerifyMultiplicationCircuit {
                a: None,
                b: None,
                n: n_constraints,
            };

            Groth16::<B, P>::setup(c, &mut rng).unwrap()
        };

        let pvk = Groth16::<B, P>::process_vk(&vk).unwrap();

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
        let t = Instant::now();
        let proof = Groth16::<B, P>::prove(&pk, circuit, &mut rng).unwrap();
        let d = t.elapsed();
        println!("groth prover {} time = {:?}", get_party_id(),d);
        end_timer!(prover_timer);
        set_phase_time(prover_timer.time.elapsed().as_micros());

        // ### Reveal proof ###
        set_phase("reveal");
        let reveal_timer = start_timer!(|| "Reveal proof");
        let proof = reveal_proof(proof);
        end_timer!(reveal_timer);
        set_phase_time(reveal_timer.time.elapsed().as_micros());

        // // ### Verification ###
        // set_phase("verification");
        // let verify_timer = start_timer!(|| "Verify proof");
        // assert!(Groth16::<B, P>::verify_with_processed_vk(&pvk, &[c.into()], &proof).unwrap());
        // end_timer!(verify_timer);
        // set_phase_time(verify_timer.time.elapsed().as_micros());

        // ### Wrapping up ###
        end_timer!(groth_16_timer);
        set_phase("total");
        set_phase_time(groth_16_timer.time.elapsed().as_micros());
        Net::deinit_network();
    }

    #[test]
    fn single_party_groth16() {
        let args: Vec<String> = env::args().collect();

        // Parse arguments
        let party_id = 0;
        // let my_value_arg = args[5].parse::<usize>().unwrap();
        let n_constraints = args[4].parse::<usize>().unwrap();
        let n_parties = 1;

        // Experiment setup
        let experiment_name = String::from("single_groth/")
            + n_parties.to_string().as_str()
            + "/"
            + n_constraints.to_string().as_str()
            + "/";
        set_experiment_name(&experiment_name);

        Net::init_network(party_id, n_parties);

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        // let my_value: <Bls12_381 as Pairing>::ScalarField = <Bls12_381 as Pairing>::ScalarField::from(5u64).into();
        // let my_value_shares = Spdz::<Bls12_381, MpcPairing<Bls12_381>>::generate_shares_for_value(
        //     n_parties, my_value, &mut rng,
        // );
        // let my_value_public = <P as MpcPairingTrait<B>>::ScalarField::from_public(my_value);
        // let c_input = <Bls12_381 as Pairing>::ScalarField::from(25u64);
        // let public_input = <P as MpcPairingTrait<B>>::ScalarField::from_public(c_input);

        type B = Bls12_381;
        // type P = Pairing;

        let groth_16_timer = start_timer!(|| "single_Groth16");

        // ### Witness distribution ###
        // set_phase("witness_distribution");
        // let witness_distribution_timer = start_timer!(|| "witness_distribution");
        // let witness_size = 2;
        // let witness_input = distribute_witnesses(
        //     party_id,
        //     my_value_shares,
        //     // n_constraints,
        //     n_parties,
        //     // witness_size,
        // );
        // .await;
        // end_timer!(witness_distribution_timer);
        // set_phase_time(witness_distribution_timer.time.elapsed().as_micros());

        // // ### Setup ###
        set_phase("setup");
        let setup_timer = start_timer!(|| "Setup");
        let (pk, vk) = {
            let c = VerifyMultiplicationCircuit {
                a: None,
                b: None,
                n: n_constraints,
            };

            ark_groth16::Groth16::<B>::setup(c, &mut rng).unwrap()
        };

        let pvk = ark_groth16::Groth16::<B>::process_vk(&vk).unwrap();

        let a = <B as Pairing>::ScalarField::rand(&mut rng);
        let b = <B as Pairing>::ScalarField::rand(&mut rng);
        let c = <B as Pairing>::ScalarField::rand(&mut rng);;

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
        let t = Instant::now();
        let proof = ark_groth16::Groth16::<B>::prove(&pk, circuit, &mut rng).unwrap();
        let d = t.elapsed();
        end_timer!(prover_timer);
        set_phase_time(prover_timer.time.elapsed().as_micros());

        // ### Reveal proof ###
        // set_phase("reveal");
        // let reveal_timer = start_timer!(|| "Reveal proof");
        // let proof = reveal_proof(proof);
        // end_timer!(reveal_timer);
        // set_phase_time(reveal_timer.time.elapsed().as_micros());

        // // ### Verification ###
        // set_phase("verification");
        // let verify_timer = start_timer!(|| "Verify proof");
        // assert!(Groth16::<B, P>::verify_with_processed_vk(&pvk, &[c.into()], &proof).unwrap());
        // end_timer!(verify_timer);
        // set_phase_time(verify_timer.time.elapsed().as_micros());

        // ### Wrapping up ###
        end_timer!(groth_16_timer);
        set_phase("total");
        set_phase_time(groth_16_timer.time.elapsed().as_micros());
        Net::deinit_network();
    }

    #[test]
    fn maf_groth16() {
        let args: Vec<String> = env::args().collect();

        // Parse arguments
        let party_id = args[4].parse::<usize>().unwrap();
        let n_constraints = args[5].parse::<usize>().unwrap();
        let n_parties = args[6].parse::<usize>().unwrap();

        // Experiment setup
        let experiment_name = String::from("groth/")
            + n_parties.to_string().as_str()
            + "/"
            + n_constraints.to_string().as_str()
            + "/";
        set_experiment_name(&experiment_name);

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        type B = Bls12_381;
        type P = MpcPairing<B>;
        type F = <Bls12_381 as Pairing>::ScalarField;

        Net::init_network(party_id, n_parties);

        let groth_16_timer = start_timer!(|| "Groth16");

        // ### Witness distribution ###
        set_phase("witness_distribution");
        let witness_distribution_timer = start_timer!(|| "witness_distribution");
        let n = n_constraints; // Number of individuals

        // For demonstration, we will generate random x_list and v_list
        // In practice, these should be securely shared among the parties
        let mut x_list = Vec::with_capacity(n);
        let mut v_list = Vec::with_capacity(n);

        for _ in 0..n {
            // Generate random x_i ∈ {0,1,2}
            let x_i_value = rng.gen_range(0u64..=2u64);
            let x_i = F::from(x_i_value);

            // Generate random v_i ∈ {0,1}
            let v_i_value = rng.gen_range(0u64..=1u64);
            let v_i = F::from(v_i_value);

            x_list.push(Some(x_i));
            v_list.push(Some(v_i));
        }

        // Compute sum_x = Σ x_i
        let sum_x = x_list.iter().fold(F::zero(), |acc, x| acc + x.unwrap());

        // Compute sum_v = Σ v_i
        let sum_v = v_list.iter().fold(F::zero(), |acc, v| acc + v.unwrap());

        // Compute denom = 2 * (n - sum_v)
        let n_f = F::from(n as u64);
        let denom = F::from(2u64) * (n_f - sum_v);

        // Ensure denom is not zero to avoid division by zero
        assert!(!denom.is_zero(), "Denominator is zero, cannot compute MAF");

        // Compute maf = sum_x / denom
        let maf = sum_x * denom.inverse().unwrap(); // Multiply by the inverse of denom

        // Convert maf to the field used by the circuit
        let maf_field_element = maf;

        // Distribute witnesses among parties (for MPC)
        // Here we simulate the distribution by generating shares of the inputs
        // In practice, this should be replaced with actual MPC witness distribution
        let x_list_shares = x_list
            .iter()
            .map(|x| {
                Spdz::<B, P>::generate_shares_for_value(
                    n_parties,
                    x.unwrap().into(),
                    &mut rng,
                )
            })
            .collect::<Vec<_>>();

        let v_list_shares = v_list
            .iter()
            .map(|v| {
                Spdz::<B, P>::generate_shares_for_value(
                    n_parties,
                    v.unwrap().into(),
                    &mut rng,
                )
            })
            .collect::<Vec<_>>();

        let maf_shares = Spdz::<B, P>::generate_shares_for_value(
            n_parties,
            maf_field_element.into(),
            &mut rng,
        );

        // Prepare the witnesses for this party
        let x_list_witnesses = x_list_shares
            .iter()
            .map(|shares| shares[party_id - 1])
            .collect::<Vec<_>>();

        let v_list_witnesses = v_list_shares
            .iter()
            .map(|shares| shares[party_id - 1])
            .collect::<Vec<_>>();

        let maf_witness = maf_shares[party_id - 1];

        end_timer!(witness_distribution_timer);
        set_phase_time(witness_distribution_timer.time.elapsed().as_micros());

        // ### Setup ###
        set_phase("setup");
        let setup_timer = start_timer!(|| "Setup");
        let (pk, vk) = {
            let c = MAFCircuit::<<P as MpcPairingTrait<B>>::ScalarField> {
                x_list: vec![None; n],
                v_list: vec![None; n],
                n,
                maf: None,
            };

            Groth16::<B, P>::setup(c, &mut rng).unwrap()
        };

        let pvk = Groth16::<B, P>::process_vk(&vk).unwrap();

        // Prepare the circuit with witnesses
        let circuit = MAFCircuit::<<P as MpcPairingTrait<B>>::ScalarField> {
            x_list: x_list_witnesses.iter().map(|x| Some(*x)).collect(),
            v_list: v_list_witnesses.iter().map(|v| Some(*v)).collect(),
            n,
            maf: Some(maf_witness),
        };

        // The public input is the MAF value (maf_j)
        let public_input = vec![maf_field_element.into()];

        end_timer!(setup_timer);
        set_phase_time(setup_timer.time.elapsed().as_micros());

        // ### Proving ###
        set_phase("proving");
        let prover_timer = start_timer!(|| "Prover");
        let t = Instant::now();
        let proof = Groth16::<B, P>::prove(&pk, circuit, &mut rng).unwrap();
        let d = t.elapsed();
        println!("groth prover {} time = {:?}", get_party_id(), d);
        end_timer!(prover_timer);
        set_phase_time(prover_timer.time.elapsed().as_micros());

        // ### Reveal proof ###
        set_phase("reveal");
        let reveal_timer = start_timer!(|| "Reveal proof");
        let proof = reveal_proof(proof);
        end_timer!(reveal_timer);
        set_phase_time(reveal_timer.time.elapsed().as_micros());

        // ### Verification ###
        set_phase("verification");
        let verify_timer = start_timer!(|| "Verify proof");
        assert!(Groth16::<B, P>::verify_with_processed_vk(&pvk, &public_input, &proof).unwrap());
        end_timer!(verify_timer);
        set_phase_time(verify_timer.time.elapsed().as_micros());

        // ### Wrapping up ###
        end_timer!(groth_16_timer);
        set_phase("total");
        set_phase_time(groth_16_timer.time.elapsed().as_micros());
        Net::deinit_network();
    }


    // test operations on spdz shared field and group
    #[test]
    fn test_ops() {
        let args: Vec<String> = env::args().collect();

        // Parse arguments
        let party_id = args[4].parse::<usize>().unwrap();
        let my_value_arg = args[5].parse::<usize>().unwrap();
        let n_constraints = args[6].parse::<usize>().unwrap();
        let n_parties = args[7].parse::<usize>().unwrap();

        // Experiment setup
        let experiment_name = String::from("groth/")
            + n_parties.to_string().as_str()
            + "/"
            + n_constraints.to_string().as_str()
            + "/";
        set_experiment_name(&experiment_name);

        Net::init_network(party_id, n_parties);

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let my_value = <Bls12_381 as Pairing>::ScalarField::from(my_value_arg as u64).into();
        let my_value_shares = Spdz::<Bls12_381, MpcPairing<Bls12_381>>::generate_shares_for_value(
            n_parties, my_value, &mut rng,
        );
        let public_input = vec![<Bls12_381 as Pairing>::ScalarField::from(91u64).into()];

        type B = Bls12_381;
        type P = MpcPairing<B>;


        let c: <P as MpcPairingTrait<B>>::ScalarField = public_input[0];

        let val = <Bls12_381 as Pairing>::ScalarField::from(120u64);
        let ga_val = <Bls12_381 as Pairing>::G1Affine::generator();
        let val_sh = <Bls12_381 as Pairing>::ScalarField::from(40u64);
        let p = <P as MpcPairingTrait<B>>::ScalarField::from_public(val); //as Pairing>::ScalarField::from(91u64).into();
        let s = <P as MpcPairingTrait<B>>::ScalarField::from_shared(val_sh);

        let g1_generator = <P as MpcPairingTrait<B>>::G1::rand(&mut rng);
        let g2_generator = <P as MpcPairingTrait<B>>::G2::rand(&mut rng);

        let g1_gr = g1_generator.value;
        let g1_out = g1_gr.get_share_group_val();

        type EG = <B as Pairing>::G1;
        type EG2 = <B as Pairing>::G2;
        type EG1A = <B as Pairing>::G1Affine;
        type EG2A = <B as Pairing>::G2Affine;
        let ggg = <B as Pairing>::G1::generator();
        let ggg3 = ggg*<B as Pairing>::ScalarField::from(3u64);
        let gpub = <SpdzSharedGroup<EG> as SpdzSharedGroupTrait<EG>>::from_public(ggg);
        let gsh = <SpdzSharedGroup<EG> as SpdzSharedGroupTrait<EG>>::from_shared(ggg);

        assert_eq!(ggg3, ggg+ggg+ggg);
        //
        let g1_gr = gpub.clone();
        let g1_out = ggg.clone();
        //
        // // add
        let gag = g1_gr + &(g1_gr.clone());
        assert_eq!(gag.get_share_group_val(), g1_out+g1_out.clone());
        //
        let mut gag = g1_gr.clone();
        gag += g1_gr.clone();
        assert_eq!(gag.get_share_group_val(), g1_out+g1_out.clone());

        let gag = g1_gr.clone() + &(gsh);
        let gag = gag.reveal();
        assert_eq!(gag.get_share_group_val(), ggg+(ggg3.clone()));
        //
        let mut gag = g1_gr.clone();
        gag += gsh.clone();
        let gag = gag.reveal();
        assert_eq!(gag.get_share_group_val(), ggg+(ggg3.clone()));
        //
        let gag = gsh + &(gsh.clone());
        let gag = gag.reveal();
        assert_eq!(gag.get_share_group_val(), ggg3+(ggg3.clone()));
        //
        let mut gag = gsh.clone();
        gag += gsh.clone();
        let gag = gag.reveal();
        assert_eq!(gag.get_share_group_val(), ggg3+(ggg3.clone()));
        //
        // // sub
        let gag = g1_gr.clone() - &(g1_gr.clone());
        assert_eq!(gag.get_share_group_val(), g1_out-g1_out.clone());

        let mut gag = g1_gr.clone();
        gag -= g1_gr.clone();
        assert_eq!(gag.get_share_group_val(), g1_out-g1_out.clone());

        let gag = gsh.clone() - &g1_gr;
        let gag = gag.reveal();
        assert_eq!(gag.get_share_group_val(), (ggg3.clone())-ggg);

        let mut gag = gsh.clone();
        gag -= g1_gr.clone();
        let gag = gag.reveal();
        assert_eq!(gag.get_share_group_val(), (ggg3.clone())-ggg);

        let gag = gsh.clone() - &(gsh.clone());
        let gag = gag.reveal();
        assert_eq!(gag.get_share_group_val(), ggg3-(ggg3.clone()));

        let mut gag = gsh.clone();
        gag -= gsh.clone();
        let gag = gag.reveal();
        assert_eq!(gag.get_share_group_val(), ggg3-(ggg3.clone()));
        //
        // // g1 tests
        let g1_gen = <B as Pairing>::G1::generator();
        let g1_gen_mul3 = g1_gen*<B as Pairing>::ScalarField::from(3u64);
        let g1pub = <SpdzSharedG1<B> as SpdzSharedGroupTrait<EG>>::from_public(g1_gen);
        let g1sh = <SpdzSharedG1<B> as SpdzSharedGroupTrait<EG>>::from_shared(g1_gen);
        // add
        let gag = g1pub + &(g1pub.clone());
        assert_eq!(gag.value.get_share_group_val(), g1_gen+g1_gen.clone());
        // //mul
        let gag = g1pub * &(p.clone());
        assert_eq!(gag.value.get_share_group_val(), g1_gen*val);
        //
        let mut gag = g1pub.clone();
        gag *= &p.clone();
        assert_eq!(gag.value.get_share_group_val(), g1_gen*val);
        //
        let gag = g1sh * &(p.clone());
        let gag = gag.reveal();
        assert_eq!(gag.value.get_share_group_val(), g1_gen_mul3*val);
        //
        let mut gag = g1sh.clone();
        gag *= &(p.clone());
        let gag = gag.reveal();
        assert_eq!(gag.value.get_share_group_val(), g1_gen_mul3*val);
        //
        // // g2 tests
        let g2_gen = <B as Pairing>::G2::generator();
        let g2_gen_mul3 = g2_gen*<B as Pairing>::ScalarField::from(3u64);
        let g2pub = <SpdzSharedG2<B> as SpdzSharedGroupTrait<EG2>>::from_public(g2_gen);
        let g2sh = <SpdzSharedG2<B> as SpdzSharedGroupTrait<EG2>>::from_shared(g2_gen);
        // add
        let gag = g2pub + &(g2pub.clone());
        assert_eq!(gag.value.get_share_group_val(), g2_gen+g2_gen.clone());
        //mul
        let gag = g2pub * &(p.clone());
        assert_eq!(gag.value.get_share_group_val(), g2_gen*val);

        let mut gag = g2pub.clone();
        gag *= &p.clone();
        assert_eq!(gag.value.get_share_group_val(), g2_gen*val);

        let gag = g2sh * &(p.clone());
        let gag = gag.reveal();
        assert_eq!(gag.value.get_share_group_val(), g2_gen_mul3*val);

        let mut gag = g2sh.clone();
        gag *= &(p.clone());
        let gag = gag.reveal();
        assert_eq!(gag.value.get_share_group_val(), g2_gen_mul3*val);
        //
        //
        // // g1affine tests
        let g1af_gen = <B as Pairing>::G1Affine::generator();
        let g1af_gen_mul3 = g1_gen*<B as Pairing>::ScalarField::from(3u64);
        let g1afpub = <SpdzSharedG1Affine<B> as SpdzSharedAffineTrait<EG1A>>::from_public(g1af_gen);
        let g1afsh = <SpdzSharedG1Affine<B> as SpdzSharedAffineTrait<EG1A>>::from_shared(g1af_gen);
        // // add
        let gag = g1afpub + (g1afpub.clone());
        assert_eq!(gag.value.get_share_group_val(), g1af_gen+g1af_gen.clone());
        // //mul
        let gag = g1afpub * &(p.clone());
        assert_eq!(gag.value.get_share_group_val(), g1af_gen*val);


        let gag = g1afsh * (p.clone());
        let gag = gag.reveal();
        assert_eq!(gag.value.get_share_group_val(), g1af_gen_mul3*val);

        // // g2affine tests
        let g2af_gen = <B as Pairing>::G2Affine::generator();
        let g2af_gen_mul3 = g2_gen*<B as Pairing>::ScalarField::from(3u64);
        let g2afpub = <SpdzSharedG2Affine<B> as SpdzSharedAffineTrait<EG2A>>::from_public(g2af_gen);
        let g2afsh = <SpdzSharedG2Affine<B> as SpdzSharedAffineTrait<EG2A>>::from_shared(g2af_gen);
        // // add
        let gag = g2afpub + (g2afpub.clone());
        assert_eq!(gag.value.get_share_group_val(), g2af_gen+g2af_gen.clone());
        // //mul
        let gag = g2afpub * &(p.clone());
        assert_eq!(gag.value.get_share_group_val(), g2af_gen*val);


        let gag = g2afsh * (p.clone());
        let gag = gag.reveal();
        assert_eq!(gag.value.get_share_group_val(), g2af_gen_mul3*val);


        // test addition
        let pap = p+p;
        let papr = p+&p;
        let mut pasp = p.clone();
        pasp.add_assign(&p);
        assert_eq!(pap.get_share_field_val(), val+val);
        assert_eq!(papr.get_share_field_val(), val+val);
        assert_eq!(pasp.get_share_field_val(), val+val);
        //
        let pas = p+s;
        let pas2 = pas.reveal();
        assert_eq!(pas2.get_share_field_val(), val+val);

        let pas = p+&s;
        let pas2 = pas.reveal();
        assert_eq!(pas2.get_share_field_val(), val+val);

        let mut pas = p.clone();
        pas.add_assign(&s);
        let pas2 = pas.reveal();
        assert_eq!(pas2.get_share_field_val(), val+val);

        let pas = s+p;
        let pas2 = pas.reveal();
        assert_eq!(pas2.get_share_field_val(), val+val);

        let pas = s+&p;
        let pas2 = pas.reveal();
        assert_eq!(pas2.get_share_field_val(), val+val);

        let mut pas = s.clone();
        pas.add_assign(&p);
        let pas2 = pas.reveal();
        assert_eq!(pas2.get_share_field_val(), val+val);

        let pas = s+s;
        let pas2 = pas.reveal();
        assert_eq!(pas2.get_share_field_val(), val+val);

        let pas = s+&s;
        let pas2 = pas.reveal();
        assert_eq!(pas2.get_share_field_val(), val+val);

        let mut pas = s.clone();
        pas.add_assign(&s);
        let pas2 = pas.reveal();
        assert_eq!(pas2.get_share_field_val(), val+val);

        // test sub
        let psp = p-(p.clone());
        println!("psp={}",psp.get_share_field_val());
        let pspr = p-&p;
        let mut psap = p.clone();
        psap.sub_assign(&p);
        assert_eq!(psp.get_share_field_val(), val-val);
        assert_eq!(pspr.get_share_field_val(), val-val);
        assert_eq!(psap.get_share_field_val(), val-val);

        let pas = s-p;
        let pas2 = pas.reveal();
        assert_eq!(pas2.get_share_field_val(), val-val);

        let pas = p-s;
        let pas2 = pas.reveal();
        assert_eq!(pas2.get_share_field_val(), val-val);

        let pas = s-&p;
        let pas2 = pas.reveal();
        assert_eq!(pas2.get_share_field_val(), val-val);

        let mut pas = s.clone();
        pas.sub_assign(p);
        let pas2 = pas.reveal();
        assert_eq!(pas2.get_share_field_val(), val-val);

        let pas = s-s;
        let pas2 = pas.reveal();
        assert_eq!(pas2.get_share_field_val(), val-val);

        let pas = s-&s;
        let pas2 = pas.reveal();
        assert_eq!(pas2.get_share_field_val(), val-val);

        let mut pas = s.clone();
        pas.sub_assign(s);
        let pas2 = pas.reveal();
        assert_eq!(pas2.get_share_field_val(), val-val);
        // //
        // // //test mul
        let mut pas = s.clone();
        pas *= (&p);
        let pas2 = pas.reveal();
        assert_eq!(pas2.get_share_field_val(), val*val);
        let psp = p*p;
        // println!("psp={}",psp.get_share_field_val());
        assert_eq!(p.get_share_field_val(), val);
        let pspr = p*&p;
        let mut psap = p.clone();
        psap *= (&p);
        assert_eq!(psp.get_share_field_val(), val*val);
        assert_eq!(pspr.get_share_field_val(), val*val);
        assert_eq!(psap.get_share_field_val(), val*val);
        //
        let pas = s*p;
        let pas2 = pas.reveal();
        assert_eq!(pas2.get_share_field_val(), val*val);
        //
        let pas = s*&p;
        let pas2 = pas.reveal();
        assert_eq!(pas2.get_share_field_val(), val*val);
        //
        let mut pas = s.clone();
        pas*=(p);
        let pas2 = pas.reveal();
        assert_eq!(pas2.get_share_field_val(), val*val);

        let pas = p*s;
        let pas2 = pas.reveal();
        assert_eq!(pas2.get_share_field_val(), val*val);
        //
        let pas = p*&s;
        let pas2 = pas.reveal();
        assert_eq!(pas2.get_share_field_val(), val*val);
        //
        let mut pas = p.clone();
        pas*=(s);
        let pas2 = pas.reveal();
        assert_eq!(pas2.get_share_field_val(), val*val);
        //
        let pas = s*s;
        let pas2 = pas.reveal();
        assert_eq!(pas2.get_share_field_val(), val*val);
        // //
        let pas = s*&s;
        let pas2 = pas.reveal();
        assert_eq!(pas2.get_share_field_val(), val*val);
        //
        let mut pas = s.clone();
        pas *= &(s.clone());
        let pas2 = pas.reveal();
        assert_eq!(pas2.get_share_field_val(), val*val);
    }
}
