use crate::{
    globals::{get_n_parties, get_party_id},
    mpc::{
        field::{SharedField, SharedFieldTrait},
        group::group::SharedAffineTrait,
        pairing::{MpcPairing, MpcPairingTrait},
    },
    network::Net,
};
use ark_bls12_381::{Bls12_381, FrConfig};
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::{Fp, MontBackend, PrimeField, UniformRand};
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_std::{fmt::Debug, str::FromStr, test_rng};
use num_bigint::BigUint;
use rand::{rngs::StdRng, RngCore, SeedableRng};

pub struct Spdz<B, P>
    where
        B: Pairing,
        P: MpcPairingTrait<B>,
{
    _base_pairing: std::marker::PhantomData<B>,
    _pairing: std::marker::PhantomData<P>,
}

impl<B, P> Spdz<B, P>
    where
        B: Pairing,
        P: MpcPairingTrait<B>,
{
    pub fn generate_shares_for_value(
        n: usize,
        value: <B as Pairing>::ScalarField,
        rng: &mut StdRng,
    ) -> Vec<<P as MpcPairingTrait<B>>::ScalarField>
        where
            SharedField<<P as Pairing>::ScalarField>:
            From<<<P as Pairing>::ScalarField as PrimeField>::BigInt>,
            <<P as Pairing>::ScalarField as PrimeField>::BigInt:
            From<SharedField<<P as Pairing>::ScalarField>>,
            BigUint: From<SharedField<<P as Pairing>::ScalarField>>,

            <<P as Pairing>::ScalarField as FromStr>::Err: Debug,
            <<P as Pairing>::BaseField as FromStr>::Err: Debug,
    {
        // Generate n-1 random values, and then calculate the nth value as the difference between the sum of the random values and the original value
        let base_share_values = (0..n - 1)
            .map(|_| <B as Pairing>::ScalarField::rand(rng))
            .collect::<Vec<<B as Pairing>::ScalarField>>();

        let sum: <B as Pairing>::ScalarField = base_share_values.iter().sum();

        let difference = value - sum;
        let shares = [base_share_values, vec![difference]].concat();

        let shares = shares
            .iter()
            .map(|share| <P as MpcPairingTrait<B>>::ScalarField::from_shared(*share))
            .collect::<Vec<_>>();

        shares
    }
}

// mod test_commitments {
//     use super::*;
//     use crate::globals::{get_n_parties, get_party_id, set_experiment_name};
//     use crate::snark::circuit::VerifyMultiplicationCircuit;
//     use crate::snark::groth16::prover::custom_msm;
//     use crate::snark::legogroth16::verifier::prepare_verifying_key;
//     use crate::snark::legogroth16::{data_structures::Proof, LegoGroth16};
//     use ark_std::{end_timer, start_timer, test_rng};
//     use std::env;
//
//     async fn test_shared_commitments<B, P>(
//         plain_inputs: Vec<<P as MpcPairingTrait<B>>::ScalarField>,
//         shared_inputs: Vec<<P as MpcPairingTrait<B>>::ScalarField>,
//     ) where
//         B: Pairing,
//         P: MpcPairingTrait<B>,
//     {
//         let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
//
//         let pedersen_bases = (0..3)
//             .map(|_| <P as MpcPairingTrait<B>>::G1::rand(&mut rng).into())
//             .collect::<Vec<_>>();
//
//         // Share-and-Commit
//         let commitment: <P as MpcPairingTrait<B>>::G1 = custom_msm(&pedersen_bases, &shared_inputs);
//         let revealed_commitment = commitment.into_affine().reveal();
//
//         // Commit-and-Share
//         let party_id = get_party_id();
//         let commitment = pedersen_bases[party_id] * plain_inputs[party_id];
//
//         // Share the commitment
//         let commitments: Vec<_> = Network::exchange_elements(commitment.into_affine()).await;
//         let result = commitments[0] + commitments[1];
//
//         assert_eq!(result, revealed_commitment.into());
//     }
//
//     // #[tokio::test]
//     // async fn shared_commitments() {
//     //     let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
//     //
//     //     let args: Vec<String> = env::args().collect();
//     //
//     //     let party_id = args[4].parse::<usize>().unwrap();
//     //     let n_parties = args[7].parse::<usize>().unwrap();
//     //
//     //     Network::init_network(party_id, n_parties).await;
//     //
//     //     let a = <Bls12_377 as Pairing>::ScalarField::from(7u64);
//     //     let b = <Bls12_377 as Pairing>::ScalarField::from(13u64);
//     //
//     //     let n_parties = get_n_parties();
//     //
//     //     let a_shares = Spdz::<Bls12_377, MpcPairing<Bls12_377>>::generate_shares_for_value(
//     //         n_parties, a, &mut rng,
//     //     );
//     //
//     //     let b_shares = Spdz::<Bls12_377, MpcPairing<Bls12_377>>::generate_shares_for_value(
//     //         n_parties, b, &mut rng,
//     //     );
//     //
//     //     let my_party_id = get_party_id();
//     //
//     //     let my_a_share = a_shares[my_party_id];
//     //     let my_b_share = b_shares[my_party_id];
//     //
//     //     let inputs = vec![my_a_share, my_b_share];
//     //     let plain_inputs = vec![a.into(), b.into()];
//     //
//     //     test_shared_commitments::<Bls12_377, MpcPairing<Bls12_377>>(plain_inputs, inputs).await;
//     //
//     //     Network::deinit_network().await;
//     // }
// }
