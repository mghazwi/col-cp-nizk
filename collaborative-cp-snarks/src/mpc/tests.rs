mod test_collaborative_commitment {
    // TODO: Add these two tests (copy from test_shared_commitments), determine which is the "best" one, and use that one explicitly in the groth and legogroth tests/evaluations.
    // TODO: Check whether the commitment is shared (IE, are these shared elements), and if so, try to reveal it before starting the prover and see if that effects things. Probably not, since currently Legogroth16 and Groth16 have the same amount of S op S operations anyway...
    use crate::mpc::spdz_field::SpdzSharedFieldTrait;
    use crate::mpc::spdz_group::group::SpdzSharedAffineTrait;
    use crate::{
        globals::{set_experiment_name, set_phase, set_phase_time, set_party_id},
        mpc::{
            spdz_pairing::{MpcPairing, MpcPairingTrait},
            spdz_witness_distribution::distribute_witnesses,
        },
        network::{ElementType, Net},
        snark::groth16::prover::custom_msm,
        mpc::spdz::Spdz,
    };
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use ark_ec::AffineRepr;
    use ark_ec::CurveGroup;
    use ark_std::UniformRand;
    use ark_std::Zero;
    use ark_std::{end_timer, start_timer, test_rng};
    use rand::{RngCore, SeedableRng};
    use std::env;
    use crate::mpc::spdz_field::SpdzSharedField;

    #[test]
    fn commit_and_share() {
        type B = Bls12_381;
        type P = MpcPairing<B>;

        let args: Vec<String> = env::args().collect();

        // Parse arguments
        let party_id = args[4].parse::<usize>().unwrap();
        let my_value_arg = args[5].parse::<usize>().unwrap();
        let n_witnesses = args[6].parse::<usize>().unwrap();
        let n_parties = args[7].parse::<usize>().unwrap();
        // let witness_size = n_parties;

        // Experiment setup
        let experiment_name = String::from("commit_and_share/")
            + n_parties.to_string().as_str()
            + "/"
            + n_witnesses.to_string().as_str()
            + "/";
        set_experiment_name(&experiment_name);

        Net::init_network(party_id, n_parties);

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let my_values: Vec<<Bls12_381 as Pairing>::ScalarField> = (0..n_witnesses).into_iter().map(|_i| <Bls12_381 as Pairing>::ScalarField::from(my_value_arg as u64).into()).collect();

        let my_values_public: Vec<<P as MpcPairingTrait<B>>::ScalarField> =  (0..n_witnesses).into_iter().map(|i| <P as MpcPairingTrait<B>>::ScalarField::from_public(my_values[i])).collect();

        // let my_value_shares = Spdz::<Bls12_381, MpcPairing<Bls12_381>>::generate_shares_for_value(
        //     n_parties, my_value, &mut rng,
        // );


        let total_timer = start_timer!(|| "Total");

        // ### Witness distribution ###
        // set_phase("witness_distribution");
        // let witness_distribution_timer = start_timer!(|| "witness_distribution");
        // let witness_input = distribute_witnesses(
        //     party_id,
        //     my_value_shares,
        //     // n_constraints,
        //     n_parties,
        //     witness_size,
        // );
        // end_timer!(witness_distribution_timer);
        // set_phase_time(witness_distribution_timer.time.elapsed().as_micros());

        // ### Commit ###
        set_phase("local");
        let commit_timer = start_timer!(|| "local");

        // Commitment key generation
        let pedersen_bases = (0..n_witnesses)
            .map(|_| <P as MpcPairingTrait<B>>::G1::rand(&mut rng).into())
            .collect::<Vec<_>>();

        // Commit-and-Share
        let my_commitment: <P as MpcPairingTrait<B>>::G1 =
            custom_msm(&pedersen_bases, &my_values_public);

        end_timer!(commit_timer);
        set_phase_time(commit_timer.time.elapsed().as_micros());

        set_phase("exchange");
        let exchange_timer = start_timer!(|| "exchange");
        let all_commitments = Net::exchange_elements(my_commitment.into_affine(), ElementType::G1);
        let mut result = <P as MpcPairingTrait<B>>::G1::zero();

        for commitment in all_commitments {
            result = result + commitment;
        }

        end_timer!(exchange_timer);
        set_phase_time(exchange_timer.time.elapsed().as_micros());

        end_timer!(total_timer);
        set_phase("total");
        set_phase_time(total_timer.time.elapsed().as_micros());

        Net::deinit_network();
    }

    #[test]
    fn share_and_commit() {
        type B = Bls12_381;
        type P = MpcPairing<B>;

        let args: Vec<String> = env::args().collect();

        // Parse arguments
        let party_id = args[4].parse::<usize>().unwrap();
        let my_value_arg = args[5].parse::<usize>().unwrap();
        let n_witnesses = args[6].parse::<usize>().unwrap();
        let n_parties = args[7].parse::<usize>().unwrap();
        // let witness_size = n_parties;

        // Experiment setup
        let experiment_name = String::from("share_and_commit/")
            + n_parties.to_string().as_str()
            + "/"
            + n_witnesses.to_string().as_str()
            + "/";
        set_experiment_name(&experiment_name);

        Net::init_network(party_id, n_parties);

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let my_value = <Bls12_381 as Pairing>::ScalarField::from(my_value_arg as u64).into();

        let my_values: Vec<<Bls12_381 as Pairing>::ScalarField> = (0..n_witnesses).into_iter().map(|_i| <Bls12_381 as Pairing>::ScalarField::from(my_value_arg as u64).into()).collect();

        let mut all_values_shares = Vec::with_capacity(n_witnesses);

        for i in 0..n_witnesses {
            let my_value_shares = Spdz::<Bls12_381, MpcPairing<Bls12_381>>::generate_shares_for_value(
                n_parties, my_value, &mut rng,
            );
            all_values_shares.push(my_value_shares);
        }

        let total_timer = start_timer!(|| "Total");

        // ### Witness distribution ###
        set_phase("witness_distribution");
        let witness_distribution_timer = start_timer!(|| "witness_distribution");
        let mut all_witness_inputs = vec![];
        for i in 0..n_witnesses {
            let witness_input = distribute_witnesses(
                party_id,
                all_values_shares[i].clone(),
                // n_constraints,
                n_parties,
                // witness_size,
            );
            all_witness_inputs.push(witness_input);
        }
        end_timer!(witness_distribution_timer);
        set_phase_time(witness_distribution_timer.time.elapsed().as_micros());

        // ### Commit ###
        set_phase("local");
        let commit_timer = start_timer!(|| "local");

        // Commitment key generation
        let pedersen_bases = (0..n_witnesses*n_parties)
            .map(|_| <P as MpcPairingTrait<B>>::G1::rand(&mut rng).into())
            .collect::<Vec<_>>();

        // Share-and-Commit
        let mut all_witness_inputs_flat = Vec::with_capacity(n_witnesses*n_parties);
        all_witness_inputs_flat = all_witness_inputs.into_iter().flatten().collect();
        let commitment: <P as MpcPairingTrait<B>>::G1 = custom_msm(&pedersen_bases, &all_witness_inputs_flat);

        end_timer!(commit_timer);
        set_phase_time(commit_timer.time.elapsed().as_micros());

        set_phase("exchange");
        let exchange_timer = start_timer!(|| "exchange");
        let revealed_commitment = commitment.into_affine().reveal();

        end_timer!(exchange_timer);
        set_phase_time(exchange_timer.time.elapsed().as_micros());

        end_timer!(total_timer);
        set_phase("total");
        set_phase_time(total_timer.time.elapsed().as_micros());

        Net::deinit_network();
    }
}
