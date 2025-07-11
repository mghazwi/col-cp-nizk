use std::{
    fmt::{Debug, Display, Formatter},
    iter::Sum,
    ops::{Add, AddAssign, Div, Mul, MulAssign, Neg, Sub, SubAssign},
    str::FromStr,
};

use ark_ec::{pairing::Pairing, CurveConfig, CurveGroup, Group, ScalarMul, VariableBaseMSM};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError, Valid, Write};
use ark_std::UniformRand;
use ark_std::Zero;
use derivative::Derivative;
use num_bigint::BigUint;
use rand::{
    distributions::{Distribution, Standard},
    Rng,
};
use zeroize::DefaultIsZeroes;

use crate::{globals::get_party_id, mpc::spdz_field::SpdzSharedField};

use super::{
    g1_affine::SpdzSharedG1Affine,
    group::{SpdzSharedAffine, SpdzSharedGroup, SpdzSharedGroupTrait},
};

#[derive(Derivative)]
#[derivative(Copy, Clone, PartialEq, Eq, Debug, Hash, Default)]
pub struct SpdzSharedG1<P: Pairing> {
    pub value: SpdzSharedGroup<P::G1>,
}

impl<P: Pairing> SpdzSharedGroupTrait<P::G1> for SpdzSharedG1<P>
where
    SpdzSharedField<<P as Pairing>::ScalarField>:
        From<<<P as Pairing>::ScalarField as PrimeField>::BigInt>,
    <<P as Pairing>::ScalarField as PrimeField>::BigInt:
        From<SpdzSharedField<<P as Pairing>::ScalarField>>,
    BigUint: From<SpdzSharedField<<P as Pairing>::ScalarField>>,

    <<P as Pairing>::ScalarField as FromStr>::Err: Debug,
{
    fn as_base(_value: Self) -> P::G1 {
        todo!()
    }

    fn reveal(self) -> SpdzSharedG1<P> {
        SpdzSharedG1{
            value: self.value.reveal()
        }
    }

    fn from_public(value: P::G1) -> Self {
        SpdzSharedG1 {
            value: SpdzSharedGroup::from_public(value),
        }
    }

    fn from_shared(value: P::G1) -> Self {
        SpdzSharedG1 {
            value: SpdzSharedGroup::from_shared(value),
        }
    }

}

impl<P: Pairing> From<SpdzSharedG1Affine<P>> for SpdzSharedG1<P> {
    fn from(value: SpdzSharedG1Affine<P>) -> Self {
        let g1 = match value.value {
            SpdzSharedAffine::Public{sh,mac} => SpdzSharedGroup::Public {sh: P::G1::from(sh), mac: P::G1::from(mac)},
            SpdzSharedAffine::Shared{sh,mac} => SpdzSharedGroup::Shared {sh: P::G1::from(sh), mac: P::G1::from(mac)},
        };

        SpdzSharedG1 {
            value: g1,
        }
    }
}

impl<P: Pairing> Group for SpdzSharedG1<P>
where
    SpdzSharedField<<P as Pairing>::ScalarField>:
        From<<<P as Pairing>::ScalarField as PrimeField>::BigInt>,
    <<P as Pairing>::ScalarField as PrimeField>::BigInt:
        From<SpdzSharedField<<P as Pairing>::ScalarField>>,
    BigUint: From<SpdzSharedField<<P as Pairing>::ScalarField>>,

    <<P as Pairing>::ScalarField as FromStr>::Err: Debug,
{
    type ScalarField = SpdzSharedField<P::ScalarField>;

    fn generator() -> Self {
        SpdzSharedG1::from_public(P::G1::generator())
    }

    fn double_in_place(&mut self) -> &mut Self {
        let new_value = match &self.value {
            SpdzSharedGroup::Public{sh:g1_value, mac:g1_mac} => {
                let mut g1 = g1_value.clone();
                let mut mac = g1_mac.clone();
                g1.double_in_place();
                mac.double_in_place();
                SpdzSharedGroup::Public{sh:g1, mac}
            }
            SpdzSharedGroup::Shared{sh:g1_value, mac:g1_mac} => {
                todo!();
            }
        };

        self.value = new_value;

        self
    }

    fn mul_bigint(&self, _other: impl AsRef<[u64]>) -> Self {
        todo!();
    }
}

// Arithmetic

// Add
impl<P: Pairing> Add<SpdzSharedG1<P>> for SpdzSharedG1<P> {
    type Output = Self;

    fn add(self, rhs: SpdzSharedG1<P>) -> Self::Output {
        let value = self.value.add(rhs.value);
        SpdzSharedG1 { value }
    }
}

impl<'a, P: Pairing> Add<&'a SpdzSharedG1<P>> for SpdzSharedG1<P> {
    type Output = Self;

    fn add(self, rhs: &'a SpdzSharedG1<P>) -> Self::Output {
        let value = self.value.add(rhs.value);
        SpdzSharedG1 { value }
    }
}

impl<'a, P: Pairing> AddAssign<&'a SpdzSharedG1<P>> for SpdzSharedG1<P> {
    fn add_assign(&mut self, rhs: &'a SpdzSharedG1<P>) {
        let new_value = self.value.add(rhs.value);
        *self = SpdzSharedG1 {value: new_value,};
    }
}

impl<P: Pairing> AddAssign<SpdzSharedG1<P>> for SpdzSharedG1<P> {
    fn add_assign(&mut self, rhs: SpdzSharedG1<P>) {
        self.add_assign(&rhs)
    }
}

impl<'a, P: Pairing> AddAssign<&'a SpdzSharedG1Affine<P>> for SpdzSharedG1<P> {
    fn add_assign(&mut self, rhs: &'a SpdzSharedG1Affine<P>) {
        match (&mut self.value, &rhs.value) {
            (SpdzSharedGroup::Public{sh:lhs_sh, mac:lhs_mac}, SpdzSharedAffine::Public{sh: rhs_sh,mac:rhs_mac}) => {
                lhs_sh.add_assign(rhs_sh);
                lhs_mac.add_assign(rhs_mac);
            }
            (SpdzSharedGroup::Public{sh:lhs_sh, mac:lhs_mac}, SpdzSharedAffine::Shared{sh: rhs_sh,mac:rhs_mac}) => {
                todo!();
            }
            (SpdzSharedGroup::Shared{sh:lhs_sh, mac:lhs_mac}, SpdzSharedAffine::Public{sh: rhs_sh,mac:rhs_mac}) => {
                if get_party_id() == 0 {
                    lhs_sh.add_assign(rhs_sh);
                    lhs_mac.add_assign(rhs_mac);
                }
            }
            (SpdzSharedGroup::Shared{sh:lhs_sh, mac:lhs_mac}, SpdzSharedAffine::Shared{sh: rhs_sh,mac:rhs_mac}) => {
                todo!();
            }
        }
    }
}

impl<P: Pairing> AddAssign<SpdzSharedG1Affine<P>> for SpdzSharedG1<P> {
    fn add_assign(&mut self, rhs: SpdzSharedG1Affine<P>) {
        self.add_assign(&rhs);
    }
}

impl<P: Pairing> Add<SpdzSharedG1Affine<P>> for SpdzSharedG1<P> {
    type Output = Self;

    fn add(self, rhs: SpdzSharedG1Affine<P>) -> Self::Output {
        self.add(&rhs)
    }
}

impl<'a, P: Pairing> Add<&'a SpdzSharedG1Affine<P>> for SpdzSharedG1<P> {
    type Output = Self;

    fn add(self, rhs: &'a SpdzSharedG1Affine<P>) -> Self::Output {
        let mut new_value = self.clone();
        new_value.add_assign(rhs);
        new_value
    }
}

// Sub
impl<'a, P: Pairing> Sub<&'a SpdzSharedG1<P>> for SpdzSharedG1<P> {
    type Output = Self;

    fn sub(self, rhs: &'a SpdzSharedG1<P>) -> Self::Output {
        let new_value = self.value.sub(rhs.value);
        SpdzSharedG1 { value:new_value }
    }
}

impl<P: Pairing> Sub<SpdzSharedG1<P>> for SpdzSharedG1<P> {
    type Output = Self;

    fn sub(self, rhs: SpdzSharedG1<P>) -> Self::Output {
        let new_value = self.value.sub(rhs.value);
        SpdzSharedG1 { value:new_value }
    }
}

impl<'a, P: Pairing> SubAssign<&'a SpdzSharedG1<P>> for SpdzSharedG1<P> {
    fn sub_assign(&mut self, rhs: &'a SpdzSharedG1<P>) {
        let new_value = self.value.sub(rhs.value);
        *self = SpdzSharedG1 {value: new_value,};
    }
}

impl<P: Pairing> SubAssign<SpdzSharedG1<P>> for SpdzSharedG1<P> {
    fn sub_assign(&mut self, rhs: SpdzSharedG1<P>) {
        self.sub_assign(&rhs)
    }
}

impl<'a, P: Pairing> SubAssign<&'a SpdzSharedG1Affine<P>> for SpdzSharedG1<P> {
    fn sub_assign(&mut self, rhs: &'a SpdzSharedG1Affine<P>) {
        match (&mut self.value, &rhs.value) {
            (SpdzSharedGroup::Public{sh:lhs_sh, mac:lhs_mac}, SpdzSharedAffine::Public{sh: rhs_sh,mac:rhs_mac}) => {
                lhs_sh.sub_assign(rhs_sh);
                lhs_mac.sub_assign(rhs_mac);
            }
            (SpdzSharedGroup::Public{sh:lhs_sh, mac:lhs_mac}, SpdzSharedAffine::Shared{sh: rhs_sh,mac:rhs_mac}) => {
                todo!();
            }
            (SpdzSharedGroup::Shared{sh:lhs_sh, mac:lhs_mac}, SpdzSharedAffine::Public{sh: rhs_sh,mac:rhs_mac}) => {
                todo!();
            }
            (SpdzSharedGroup::Shared{sh:lhs_sh, mac:lhs_mac}, SpdzSharedAffine::Shared{sh: rhs_sh,mac:rhs_mac}) => {
                todo!();
            }
        }
    }
}

impl<P: Pairing> SubAssign<SpdzSharedG1Affine<P>> for SpdzSharedG1<P> {
    fn sub_assign(&mut self, rhs: SpdzSharedG1Affine<P>) {
        self.sub_assign(&rhs)
    }
}

impl<'a, P: Pairing> Sub<&'a SpdzSharedG1Affine<P>> for SpdzSharedG1<P> {
    type Output = Self;

    fn sub(self, rhs: &'a SpdzSharedG1Affine<P>) -> Self::Output {
        let mut new_value = self.clone();
        new_value.sub_assign(rhs);
        new_value
    }
}

impl<P: Pairing> Sub<SpdzSharedG1Affine<P>> for SpdzSharedG1<P> {
    type Output = Self;

    fn sub(self, rhs: SpdzSharedG1Affine<P>) -> Self::Output {
        self.sub(&rhs)
    }
}

// Mul
impl<'a, P: Pairing> Mul<&'a SpdzSharedField<P::ScalarField>> for SpdzSharedG1<P> {
    type Output = Self;

    fn mul(self, rhs: &'a SpdzSharedField<P::ScalarField>) -> Self::Output {
        // match (&self.value, &rhs) {
        //     (SpdzSharedGroup::Public{sh:lhs_sh, mac:lhs_mac}, SpdzSharedField::Public{sh: rhs_sh,mac:rhs_mac}) => {
        //         let sh = lhs_sh.mul(rhs_sh);
        //         let mac = lhs_mac.mul(rhs_mac);
        //         SpdzSharedG1 {
        //             value: SpdzSharedGroup::Public{sh,mac},
        //         }
        //     }
        //     (SpdzSharedGroup::Public{sh:lhs_sh, mac:lhs_mac}, SpdzSharedField::Shared{sh: rhs_sh,mac:rhs_mac}) => {
        //         todo!();
        //     }
        //     (SpdzSharedGroup::Shared{sh:lhs_sh, mac:lhs_mac}, SpdzSharedField::Public{sh: rhs_sh,mac:rhs_mac}) => {
        //         let sh = lhs_sh.mul(rhs_sh);
        //         let mac = lhs_mac.mul(rhs_mac);
        //         SpdzSharedG1 {
        //             value: SpdzSharedGroup::Shared{sh,mac},
        //         }
        //     }
        //     (SpdzSharedGroup::Shared{sh:lhs_sh, mac:lhs_mac}, SpdzSharedField::Shared{sh: rhs_sh,mac:rhs_mac}) => {
        //         todo!();
        //     }
        // }
        SpdzSharedG1 {
            value: self.value*rhs
        }
    }
}

impl<'a, P: Pairing> MulAssign<&'a SpdzSharedField<P::ScalarField>> for SpdzSharedG1<P> {
    fn mul_assign(&mut self, rhs: &'a SpdzSharedField<P::ScalarField>) {
        *self = self.mul(rhs)
    }
}

impl<P: Pairing> MulAssign<SpdzSharedField<P::ScalarField>> for SpdzSharedG1<P> {
    fn mul_assign(&mut self, rhs: SpdzSharedField<P::ScalarField>) {
        *self = self.mul(rhs)
    }
}

impl<P: Pairing> Mul<SpdzSharedField<P::ScalarField>> for SpdzSharedG1<P> {
    type Output = Self;

    fn mul(self, rhs: SpdzSharedField<P::ScalarField>) -> Self::Output {
        self.mul(&rhs)
    }
}

// Div
impl<'a, P: Pairing> Div<&'a SpdzSharedField<P::ScalarField>> for SpdzSharedG1<P> {
    type Output = Self;

    fn div(self, _rhs: &'a SpdzSharedField<P::ScalarField>) -> Self::Output {
        todo!()
    }
}

// Sum
impl<'a, P: Pairing> Sum<&'a SpdzSharedG1<P>> for SpdzSharedG1<P> {
    fn sum<I: Iterator<Item = &'a SpdzSharedG1<P>>>(iter: I) -> Self {
        iter.fold(Self::zero(), core::ops::Add::add)
    }
}

impl<P: Pairing> Sum<SpdzSharedG1<P>> for SpdzSharedG1<P> {
    fn sum<I: Iterator<Item = SpdzSharedG1<P>>>(iter: I) -> Self {
        iter.fold(Self::zero(), core::ops::Add::add)
    }
}

impl<'a, P: Pairing> Sum<&'a SpdzSharedG1Affine<P>> for SpdzSharedG1<P> {
    fn sum<I: Iterator<Item = &'a SpdzSharedG1Affine<P>>>(iter: I) -> Self {
        iter.fold(Self::zero(), core::ops::Add::add)
    }
}

impl<P: Pairing> Sum<SpdzSharedG1Affine<P>> for SpdzSharedG1<P> {
    fn sum<I: Iterator<Item = SpdzSharedG1Affine<P>>>(iter: I) -> Self {
        iter.fold(Self::zero(), core::ops::Add::add)
    }
}

// Neg
impl<P: Pairing> Neg for SpdzSharedG1<P> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        SpdzSharedG1{
            value: -self.value
        }
    }
}

// Zero
impl<P: Pairing> Zero for SpdzSharedG1<P> {
    fn zero() -> Self {
        let g1 = P::G1::zero();
        SpdzSharedG1 {
            value: SpdzSharedGroup::new(g1),
        }
    }

    fn is_zero(&self) -> bool {
        self.value.is_zero()
    }
}

impl<P: Pairing> DefaultIsZeroes for SpdzSharedG1<P> {}

// Display
impl<P: Pairing> Display for SpdzSharedG1<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let value = match &self.value {
            SpdzSharedGroup::Public{sh,mac} => "Public".to_string() + &sh.to_string(),
            SpdzSharedGroup::Shared{sh,mac} => "Shared".to_string() + &sh.to_string(),
        };

        write!(f, "SharedG1({})", value)
    }
}

// Serialize
impl<P: Pairing> Valid for SpdzSharedG1<P> {
    fn check(&self) -> Result<(), SerializationError> {
        todo!()
    }
}

impl<P: Pairing> CanonicalSerialize for SpdzSharedG1<P> {
    fn serialize_with_mode<W: Write>(
        &self,
        writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), SerializationError> {
        self.value.serialize_with_mode(writer, compress)
    }

    fn serialized_size(&self, _compress: ark_serialize::Compress) -> usize {
        todo!()
    }
}

impl<P: Pairing> CanonicalDeserialize for SpdzSharedG1<P> {
    fn deserialize_with_mode<R: std::io::prelude::Read>(
        _reader: R,
        _compress: ark_serialize::Compress,
        _validate: ark_serialize::Validate,
    ) -> Result<Self, SerializationError> {
        todo!()
    }
}

// Standard
impl<P: Pairing> Distribution<SpdzSharedG1<P>> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> SpdzSharedG1<P> {
        let g1 = P::G1::rand(rng);
        SpdzSharedG1 {
            value: SpdzSharedGroup::new(g1),
        }
    }
}

pub struct Config<P: Pairing> {
    _pairing: std::marker::PhantomData<P>,
}

// Define our own CurveConfig where we use the shared versions of BaseField and ScalarField
impl<P: Pairing> CurveConfig for Config<P>
where
    SpdzSharedField<P::BaseField>: From<<<P as Pairing>::BaseField as PrimeField>::BigInt>,
    <<P as Pairing>::BaseField as PrimeField>::BigInt: From<SpdzSharedField<<P as Pairing>::BaseField>>,
    BigUint: From<SpdzSharedField<<P as Pairing>::BaseField>>,

    SpdzSharedField<P::ScalarField>: From<<<P as Pairing>::ScalarField as PrimeField>::BigInt>,
    <<P as Pairing>::ScalarField as PrimeField>::BigInt:
        From<SpdzSharedField<<P as Pairing>::ScalarField>>,
    BigUint: From<SpdzSharedField<<P as Pairing>::ScalarField>>,

    SpdzSharedField<<P as Pairing>::ScalarField>: From<<P as Pairing>::ScalarField>,
    <<P as Pairing>::ScalarField as FromStr>::Err: Debug,
    <<P as Pairing>::BaseField as FromStr>::Err: Debug,
{
    type BaseField = SpdzSharedField<P::BaseField>;
    type ScalarField = SpdzSharedField<P::ScalarField>;

    const COFACTOR: &'static [u64] =
        <<<P as Pairing>::G1 as CurveGroup>::Config as CurveConfig>::COFACTOR;

    const COFACTOR_INV: Self::ScalarField =
        SpdzSharedField::new(<<<P as Pairing>::G1 as CurveGroup>::Config as CurveConfig>::COFACTOR_INV);
}

// CurveGroup
impl<P: Pairing> CurveGroup for SpdzSharedG1<P>
where
    SpdzSharedField<<P as Pairing>::ScalarField>:
        From<<<P as Pairing>::ScalarField as PrimeField>::BigInt>,
    <<P as Pairing>::ScalarField as PrimeField>::BigInt:
        From<SpdzSharedField<<P as Pairing>::ScalarField>>,
    BigUint: From<SpdzSharedField<<P as Pairing>::ScalarField>>,

    SpdzSharedField<<P as Pairing>::BaseField>: From<<<P as Pairing>::BaseField as PrimeField>::BigInt>,
    <<P as Pairing>::BaseField as PrimeField>::BigInt: From<SpdzSharedField<<P as Pairing>::BaseField>>,
    BigUint: From<SpdzSharedField<<P as Pairing>::BaseField>>,

    SpdzSharedField<<P as Pairing>::ScalarField>: From<<P as Pairing>::ScalarField>,
    <<P as Pairing>::ScalarField as FromStr>::Err: Debug,
    <<P as Pairing>::BaseField as FromStr>::Err: Debug,
{
    type Config = Config<P>;
    type BaseField = SpdzSharedField<P::BaseField>;
    type Affine = SpdzSharedG1Affine<P>;
    type FullGroup = SpdzSharedG1Affine<P>;

    fn normalize_batch(v: &[Self]) -> Vec<Self::Affine> {
        let mut result = Vec::new();
        for g1 in v {
            result.push(g1.into_affine());
        }
        result
    }
}

// VariableBaseMSM

// ScalarMul
impl<P: Pairing> ScalarMul for SpdzSharedG1<P>
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
    type MulBase = SpdzSharedG1Affine<P>;

    const NEGATION_IS_CHEAP: bool = true;

    fn batch_convert_to_mul_base(bases: &[Self]) -> Vec<Self::MulBase> {
        Self::normalize_batch(bases)
    }
}

impl<P: Pairing> VariableBaseMSM for SpdzSharedG1<P>
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
}
