mod test_network {
    use crate::mpc::field::SharedFieldTrait;
    use crate::{
        globals::{set_phase, STATS},
        mpc::pairing::{MpcPairing, MpcPairingTrait},
        network::{ElementType, Net},
    };
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use std::env;
    use std::ops::Add;

    #[test]
    fn test_network() {
        let args: Vec<String> = env::args().collect();

        let party_id = args[4].parse::<usize>().unwrap();
        let n_parties = args[7].parse::<usize>().unwrap();

        Net::init_network(party_id, n_parties);
        set_phase("witness_distribution");

        let my_element = <Bls12_381 as Pairing>::ScalarField::from(party_id as u128);

        let elements_received = Net::exchange_elements(my_element, ElementType::Field);

        let sum: <Bls12_381 as Pairing>::ScalarField = elements_received.iter().sum();

        assert_eq!(
            sum,
            <Bls12_381 as Pairing>::ScalarField::from((n_parties * (n_parties - 1) / 2) as u128)
        );

        Net::deinit_network();
    }

    #[test]
    fn test_interactions() {
        let args: Vec<String> = env::args().collect();

        let party_id = args[4].parse::<usize>().unwrap();
        let n_parties = args[7].parse::<usize>().unwrap();

        Net::init_network(party_id, n_parties);

        let my_base = <Bls12_381 as Pairing>::ScalarField::from(party_id as u128);

        let mut my_share =
            <MpcPairing<Bls12_381> as MpcPairingTrait<Bls12_381>>::ScalarField::from_shared(
                my_base,
            );

        let expected_result =
            <MpcPairing<Bls12_381> as MpcPairingTrait<Bls12_381>>::ScalarField::from_public(
                <Bls12_381 as Pairing>::ScalarField::from(
                    (n_parties * (n_parties - 1) / 2) as u128,
                ),
            );

        assert_eq!(my_share.reveal(), expected_result);

        // Repeatedly add 1 to the element and assert the result
        for i in 1..1000 {
            println!("Iteration {}", i);

            let reveal_result = my_share.reveal();

            println!("{:?} == {:?}", reveal_result, expected_result);

            assert_eq!(reveal_result, expected_result,);
        }

        Net::deinit_network();
    }
}
