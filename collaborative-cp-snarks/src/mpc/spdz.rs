use crate::{
    globals::{get_n_parties, get_party_id},
    mpc::{
        spdz_field::{SpdzSharedField, SpdzSharedFieldTrait},
        spdz_group::group::SpdzSharedAffineTrait,
        spdz_pairing::{MpcPairing, MpcPairingTrait},
    }
};
// use ark_bls12_377::{Bls12_377, FrConfig};
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_ff::{Fp, MontBackend, PrimeField, UniformRand, Field};
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_std::{fmt::Debug, str::FromStr, test_rng};
use num_bigint::BigUint;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use crate::mpc::spdz_group::g1::SpdzSharedG1;
use crate::mpc::spdz_group::g1_affine::SpdzSharedG1Affine;
use crate::mpc::spdz_group::group::SpdzSharedGroupTrait;

// #[inline]
// pub fn mac_share<F: Field>() -> F {
//     if get_party_id() == 0 {
//         F::one()
//     } else {
//         F::zero()
//     }
// }
//
// #[derive(Clone, Copy)]
// pub struct SpdzSharedField<P: Pairing> {
//     sh: MpcPairing<P>,
//     mac: MpcPairing<P>,
// }

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
        SpdzSharedField<<P as Pairing>::ScalarField>:
            From<<<P as Pairing>::ScalarField as PrimeField>::BigInt>,
        <<P as Pairing>::ScalarField as PrimeField>::BigInt:
            From<SpdzSharedField<<P as Pairing>::ScalarField>>,
        BigUint: From<SpdzSharedField<<P as Pairing>::ScalarField>>,

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

    pub fn generate_group_shares_for_value(
        n: usize,
        value: <B as Pairing>::G1,
        rng: &mut StdRng,
    ) -> Vec<<P as MpcPairingTrait<B>>::G1>
    where
        SpdzSharedField<<P as Pairing>::ScalarField>:
            From<<<P as Pairing>::ScalarField as PrimeField>::BigInt>,
        <<P as Pairing>::ScalarField as PrimeField>::BigInt:
            From<SpdzSharedField<<P as Pairing>::ScalarField>>,
        BigUint: From<SpdzSharedField<<P as Pairing>::ScalarField>>,

        <<P as Pairing>::ScalarField as FromStr>::Err: Debug,
        <<P as Pairing>::BaseField as FromStr>::Err: Debug,
    {
        // Generate n-1 random values, and then calculate the nth value as the difference between the sum of the random values and the original value
        let base_share_values = (0..n - 1)
            .map(|_| <B as Pairing>::G1::rand(rng))
            .collect::<Vec<<B as Pairing>::G1>>();

        let sum: <B as Pairing>::G1 = base_share_values.iter().sum();

        let difference = value - sum;
        let shares = [base_share_values, vec![difference]].concat();
        // type EG1A = B::G1Affine;
        let shares = shares
            .iter()
            // .map(|share| <<P as MpcPairingTrait<B>>::G1::from_shared(*share))
            .map(|share| <<P as MpcPairingTrait<B>>::G1 as SpdzSharedGroupTrait<B::G1>>::from_shared(*share))
            .collect::<Vec<_>>();
        // <SpdzSharedGroup<EG> as SpdzSharedGroupTrait<EG>>::from_shared(ggg)
        //     <SpdzSharedG1Affine<B> as SpdzSharedAffineTrait<EG1A>>::from_shared(*share)
        shares
    }
}

