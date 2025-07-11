use ark_ec::{
    pairing::{MillerLoopOutput, Pairing, PairingOutput},
    AffineRepr, CurveGroup,
};
use ark_ff::{CyclotomicMultSubgroup, Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use derivative::Derivative;
use num_bigint::BigUint;
use std::{fmt::Debug, ops::MulAssign, str::FromStr};

use super::{
    spdz_field::{SpdzSharedField, SpdzSharedFieldTrait},
    spdz_group::{
        g1::SpdzSharedG1,
        g1_affine::SpdzSharedG1Affine,
        g1_prepared::SpdzSharedG1Prepared,
        g2::SpdzSharedG2,
        g2_affine::SpdzSharedG2Affine,
        g2_prepared::SpdzSharedG2Prepared,
        group::{SpdzSharedAffineTrait, SpdzSharedGroupTrait, SpdzSharedPreparedTrait},
    },
};

#[derive(Derivative)]
#[derivative(Copy, Clone, PartialEq, Eq, Debug, Hash)]

pub struct MpcPairing<P: Pairing> {
    _pairing: std::marker::PhantomData<P>,
}

pub trait MpcPairingTrait<P: Pairing>: Pairing {
    type ScalarField: SpdzSharedFieldTrait<P::ScalarField>;
    type BaseField: SpdzSharedFieldTrait<P::BaseField>;
    type TargetField: CyclotomicMultSubgroup + Field;

    type G1: SpdzSharedGroupTrait<P::G1>
        + CurveGroup<
            ScalarField = <Self as MpcPairingTrait<P>>::ScalarField,
            Affine = <Self as MpcPairingTrait<P>>::G1Affine,
        > + From<<Self as MpcPairingTrait<P>>::G1Affine>
        + Into<<Self as MpcPairingTrait<P>>::G1Affine>
        + MulAssign<<Self as MpcPairingTrait<P>>::ScalarField>;
    type G1Affine: SpdzSharedAffineTrait<P::G1Affine>
        + AffineRepr<
            Group = <Self as MpcPairingTrait<P>>::G1,
            ScalarField = <Self as MpcPairingTrait<P>>::ScalarField,
        > + From<<Self as MpcPairingTrait<P>>::G1>
        + Into<<Self as MpcPairingTrait<P>>::G1>
        + Into<<Self as MpcPairingTrait<P>>::G1Prepared>;
    type G1Prepared: SpdzSharedPreparedTrait<P::G1Prepared>
        + Default
        + Clone
        + Send
        + Sync
        + Debug
        + CanonicalSerialize
        + CanonicalDeserialize
        + for<'a> From<&'a <Self as MpcPairingTrait<P>>::G1>
        + for<'a> From<&'a <Self as MpcPairingTrait<P>>::G1Affine>
        + From<<Self as MpcPairingTrait<P>>::G1>
        + From<<Self as MpcPairingTrait<P>>::G1Affine>;

    type G2: SpdzSharedGroupTrait<P::G2>
        + CurveGroup<
            ScalarField = <Self as MpcPairingTrait<P>>::ScalarField,
            Affine = <Self as MpcPairingTrait<P>>::G2Affine,
        > + From<<Self as MpcPairingTrait<P>>::G2Affine>
        + Into<<Self as MpcPairingTrait<P>>::G2Affine>
        + MulAssign<<Self as MpcPairingTrait<P>>::ScalarField>;
    type G2Affine: SpdzSharedAffineTrait<P::G2Affine>
        + AffineRepr<
            Group = <Self as MpcPairingTrait<P>>::G2,
            ScalarField = <Self as MpcPairingTrait<P>>::ScalarField,
        > + From<<Self as MpcPairingTrait<P>>::G2>
        + Into<<Self as MpcPairingTrait<P>>::G2>
        + Into<<Self as MpcPairingTrait<P>>::G2Prepared>;
    type G2Prepared: SpdzSharedPreparedTrait<P::G2Prepared>
        + Default
        + Clone
        + Send
        + Sync
        + Debug
        + CanonicalSerialize
        + CanonicalDeserialize
        + for<'a> From<&'a <Self as MpcPairingTrait<P>>::G2>
        + for<'a> From<&'a <Self as MpcPairingTrait<P>>::G2Affine>
        + From<<Self as MpcPairingTrait<P>>::G2>
        + From<<Self as MpcPairingTrait<P>>::G2Affine>;

    fn pairing(
        p: impl Into<<Self as MpcPairingTrait<P>>::G1Prepared>,
        q: impl Into<<Self as MpcPairingTrait<P>>::G2Prepared>,
    ) -> PairingOutput<Self>;

    // Custom pairing fn so we have a <Self as MpcPairingTrait<P>>::TargetField
    // instead of PairingOutput<Self> where P is as Pairing
    fn my_pairing(
        p: impl Into<<Self as MpcPairingTrait<P>>::G1Prepared>,
        q: impl Into<<Self as MpcPairingTrait<P>>::G2Prepared>,
    ) -> <Self as MpcPairingTrait<P>>::TargetField;

    fn multi_pairing(
        p: impl IntoIterator<Item = impl Into<<Self as MpcPairingTrait<P>>::G1Prepared>>,
        q: impl IntoIterator<Item = impl Into<<Self as MpcPairingTrait<P>>::G2Prepared>>,
    ) -> PairingOutput<Self>;

    fn my_multi_pairing(
        p: impl IntoIterator<Item = impl Into<<Self as MpcPairingTrait<P>>::G1Prepared>>,
        q: impl IntoIterator<Item = impl Into<<Self as MpcPairingTrait<P>>::G2Prepared>>,
    ) -> <Self as MpcPairingTrait<P>>::TargetField;

    fn multi_miller_loop(
        a: impl IntoIterator<Item = impl Into<<Self as MpcPairingTrait<P>>::G1Prepared>>,
        b: impl IntoIterator<Item = impl Into<<Self as MpcPairingTrait<P>>::G2Prepared>>,
    ) -> MillerLoopOutput<Self>;

    fn final_exponentiation(mlo: MillerLoopOutput<Self>) -> Option<PairingOutput<Self>>;

    // Custom final exponentiation fn so we have a <Self as MpcPairingTrait<P>>::TargetField
    // instead of PairingOutput<Self> where P is as Pairing
    fn my_final_exponentiation(
        mlo: MillerLoopOutput<Self>,
    ) -> Option<<Self as MpcPairingTrait<P>>::TargetField>;
}

impl<P: Pairing> MpcPairingTrait<P> for MpcPairing<P>
where
    SpdzSharedField<<P as Pairing>::BaseField>: From<<<P as Pairing>::BaseField as PrimeField>::BigInt>,
    <<P as Pairing>::BaseField as PrimeField>::BigInt: From<SpdzSharedField<<P as Pairing>::BaseField>>,
    BigUint: From<SpdzSharedField<<P as Pairing>::BaseField>>,

    SpdzSharedField<<P as Pairing>::ScalarField>:
        From<<<P as Pairing>::ScalarField as PrimeField>::BigInt>,
    <<P as Pairing>::ScalarField as PrimeField>::BigInt:
        From<SpdzSharedField<<P as Pairing>::ScalarField>>,
    BigUint: From<SpdzSharedField<<P as Pairing>::ScalarField>>,

    SpdzSharedField<<P as Pairing>::ScalarField>: From<<P as Pairing>::ScalarField>,

    <<P as Pairing>::ScalarField as FromStr>::Err: Debug,
    <<P as Pairing>::BaseField as FromStr>::Err: Debug,
{
    type ScalarField = SpdzSharedField<P::ScalarField>;
    type BaseField = SpdzSharedField<P::BaseField>;
    type TargetField = P::TargetField;

    type G1 = SpdzSharedG1<P>;
    type G1Affine = SpdzSharedG1Affine<P>;
    type G1Prepared = SpdzSharedG1Prepared<P>;

    type G2 = SpdzSharedG2<P>;
    type G2Affine = SpdzSharedG2Affine<P>;
    type G2Prepared = SpdzSharedG2Prepared<P>;

    fn multi_pairing(
        p: impl IntoIterator<Item = impl Into<<Self as MpcPairingTrait<P>>::G1Prepared>>,
        q: impl IntoIterator<Item = impl Into<<Self as MpcPairingTrait<P>>::G2Prepared>>,
    ) -> PairingOutput<Self> {
        let base_result = P::multi_pairing(
            p.into_iter().map(|p| p.into().value),
            q.into_iter().map(|q| q.into().value),
        );
        PairingOutput(base_result.0)
    }

    fn my_multi_pairing(
        p: impl IntoIterator<Item = impl Into<<Self as MpcPairingTrait<P>>::G1Prepared>>,
        q: impl IntoIterator<Item = impl Into<<Self as MpcPairingTrait<P>>::G2Prepared>>,
    ) -> <Self as MpcPairingTrait<P>>::TargetField {
        let base_result = P::multi_pairing(
            p.into_iter().map(|p| p.into().value),
            q.into_iter().map(|q| q.into().value),
        );
        base_result.0
    }

    fn pairing(
        p: impl Into<<Self as MpcPairingTrait<P>>::G1Prepared>,
        q: impl Into<<Self as MpcPairingTrait<P>>::G2Prepared>,
    ) -> PairingOutput<Self> {
        <MpcPairing<P> as Pairing>::multi_pairing([p], [q])
    }

    fn my_pairing(
        p: impl Into<<Self as MpcPairingTrait<P>>::G1Prepared>,
        q: impl Into<<Self as MpcPairingTrait<P>>::G2Prepared>,
    ) -> <Self as MpcPairingTrait<P>>::TargetField {
        <MpcPairing<P> as Pairing>::multi_pairing([p], [q]).0
    }

    fn multi_miller_loop(
        a: impl IntoIterator<Item = impl Into<<Self as MpcPairingTrait<P>>::G1Prepared>>,
        b: impl IntoIterator<Item = impl Into<<Self as MpcPairingTrait<P>>::G2Prepared>>,
    ) -> MillerLoopOutput<Self> {
        let base_result = P::multi_miller_loop(
            a.into_iter().map(|a| a.into().value),
            b.into_iter().map(|b| b.into().value),
        );
        MillerLoopOutput(base_result.0)
    }

    fn final_exponentiation(mlo: MillerLoopOutput<Self>) -> Option<PairingOutput<Self>> {
        let base_mlo = MillerLoopOutput(mlo.0);
        let base_result = P::final_exponentiation(base_mlo);
        let pairing_output = PairingOutput(base_result.unwrap().0);

        Some(pairing_output)
    }

    fn my_final_exponentiation(
        mlo: MillerLoopOutput<Self>,
    ) -> Option<<Self as MpcPairingTrait<P>>::TargetField> {
        let base_mlo = MillerLoopOutput(mlo.0);
        let base_result = P::final_exponentiation(base_mlo);

        Some(base_result.unwrap().0)
    }
}

impl<P: Pairing> Pairing for MpcPairing<P>
where
    SpdzSharedField<<P as Pairing>::BaseField>: From<<<P as Pairing>::BaseField as PrimeField>::BigInt>,
    <<P as Pairing>::BaseField as PrimeField>::BigInt: From<SpdzSharedField<<P as Pairing>::BaseField>>,
    BigUint: From<SpdzSharedField<<P as Pairing>::BaseField>>,

    SpdzSharedField<<P as Pairing>::ScalarField>:
        From<<<P as Pairing>::ScalarField as PrimeField>::BigInt>,
    <<P as Pairing>::ScalarField as PrimeField>::BigInt:
        From<SpdzSharedField<<P as Pairing>::ScalarField>>,
    BigUint: From<SpdzSharedField<<P as Pairing>::ScalarField>>,

    SpdzSharedField<<P as Pairing>::ScalarField>: From<<P as Pairing>::ScalarField>,
    <<P as Pairing>::BaseField as FromStr>::Err: Debug,
    <<P as Pairing>::ScalarField as FromStr>::Err: Debug,
{
    type BaseField = SpdzSharedField<P::BaseField>;
    type ScalarField = SpdzSharedField<P::ScalarField>;

    type G1 = SpdzSharedG1<P>;
    type G1Affine = SpdzSharedG1Affine<P>;
    type G1Prepared = SpdzSharedG1Prepared<P>;

    type G2 = SpdzSharedG2<P>;
    type G2Affine = SpdzSharedG2Affine<P>;
    type G2Prepared = SpdzSharedG2Prepared<P>;

    type TargetField = P::TargetField;

    fn multi_miller_loop(
        a: impl IntoIterator<Item = impl Into<Self::G1Prepared>>,
        b: impl IntoIterator<Item = impl Into<Self::G2Prepared>>,
    ) -> MillerLoopOutput<Self> {
        let base_result = P::multi_miller_loop(
            a.into_iter().map(|a| a.into().value),
            b.into_iter().map(|b| b.into().value),
        );
        MillerLoopOutput(base_result.0)
    }

    fn final_exponentiation(mlo: MillerLoopOutput<Self>) -> Option<PairingOutput<Self>> {
        let base_mlo = MillerLoopOutput(mlo.0);
        let base_result = P::final_exponentiation(base_mlo);
        let pairing_output = PairingOutput(base_result.unwrap().0);

        Some(pairing_output)
    }
}
