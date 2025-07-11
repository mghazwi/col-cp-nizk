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

use crate::{globals::get_party_id, mpc::field::SharedField};

use super::{
    g2_affine::SharedG2Affine,
    group::{SharedAffine, SharedGroup, SharedGroupTrait},
};

#[derive(Derivative)]
#[derivative(Copy, Clone, PartialEq, Eq, Debug, Hash, Default)]
pub struct SharedG2<P: Pairing> {
    pub value: SharedGroup<P::G2>,
}

impl<P: Pairing> SharedGroupTrait<P::G2> for SharedG2<P>
where
    SharedField<<P as Pairing>::ScalarField>:
        From<<<P as Pairing>::ScalarField as PrimeField>::BigInt>,
    <<P as Pairing>::ScalarField as PrimeField>::BigInt:
        From<SharedField<<P as Pairing>::ScalarField>>,
    BigUint: From<SharedField<<P as Pairing>::ScalarField>>,

    <<P as Pairing>::ScalarField as FromStr>::Err: Debug,
{
    fn as_base(_value: Self) -> P::G2 {
        todo!()
    }

    fn reveal(self) -> SharedG2<P> {
        todo!()
    }
}

impl<P: Pairing> From<SharedG2Affine<P>> for SharedG2<P> {
    fn from(value: SharedG2Affine<P>) -> Self {
        let g2 = match value.value {
            SharedAffine::Public(value) => P::G2::from(value),
            SharedAffine::Shared(value) => P::G2::from(value),
        };

        SharedG2 {
            value: SharedGroup::new(g2),
        }
    }
}

impl<P: Pairing> Group for SharedG2<P>
where
    SharedField<<P as Pairing>::ScalarField>:
        From<<<P as Pairing>::ScalarField as PrimeField>::BigInt>,
    <<P as Pairing>::ScalarField as PrimeField>::BigInt:
        From<SharedField<<P as Pairing>::ScalarField>>,
    BigUint: From<SharedField<<P as Pairing>::ScalarField>>,

    <<P as Pairing>::ScalarField as FromStr>::Err: Debug,
{
    type ScalarField = SharedField<P::ScalarField>;

    fn generator() -> Self {
        todo!()
    }

    fn double_in_place(&mut self) -> &mut Self {
        let new_value = match &self.value {
            SharedGroup::Public(g2_value) => {
                let mut g2 = g2_value.clone();
                g2.double_in_place();
                SharedGroup::Public(g2)
            }
            SharedGroup::Shared(_g2_value) => {
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
impl<P: Pairing> Add<SharedG2<P>> for SharedG2<P> {
    type Output = Self;

    fn add(self, rhs: SharedG2<P>) -> Self::Output {
        self.add(&rhs)
    }
}

impl<'a, P: Pairing> Add<&'a SharedG2<P>> for SharedG2<P> {
    type Output = Self;

    fn add(self, rhs: &'a SharedG2<P>) -> Self::Output {
        let value = self.value.add(rhs.value);
        SharedG2 { value }
    }
}

impl<'a, P: Pairing> AddAssign<&'a SharedG2<P>> for SharedG2<P> {
    fn add_assign(&mut self, rhs: &'a SharedG2<P>) {
        let new_value = self.value.add(rhs.value);
        *self = SharedG2 {value: new_value,};
    }
}

impl<P: Pairing> AddAssign<SharedG2<P>> for SharedG2<P> {
    fn add_assign(&mut self, rhs: SharedG2<P>) {
        self.add_assign(&rhs)
    }
}

impl<'a, P: Pairing> AddAssign<&'a SharedG2Affine<P>> for SharedG2<P> {
    fn add_assign(&mut self, rhs: &'a SharedG2Affine<P>) {
        match (&mut self.value, &rhs.value) {
            (SharedGroup::Public(g2_value), SharedAffine::Public(rhs_g2_value)) => {
                g2_value.add_assign(rhs_g2_value);
            }
            (SharedGroup::Public(_g2_value), SharedAffine::Shared(_rhs_g2_value)) => {
                todo!();
            }
            (SharedGroup::Shared(g2_value), SharedAffine::Public(rhs_g2_value)) => {
                if get_party_id() == 0 {
                    g2_value.add_assign(rhs_g2_value);
                }
            }
            (SharedGroup::Shared(_g2_value), SharedAffine::Shared(_rhs_g2_value)) => {
                todo!();
            }
        }
    }
}

impl<P: Pairing> AddAssign<SharedG2Affine<P>> for SharedG2<P> {
    fn add_assign(&mut self, rhs: SharedG2Affine<P>) {
        self.add_assign(&rhs)
    }
}

impl<P: Pairing> Add<SharedG2Affine<P>> for SharedG2<P> {
    type Output = Self;

    fn add(self, rhs: SharedG2Affine<P>) -> Self::Output {
        self.add(&rhs)
    }
}

impl<'a, P: Pairing> Add<&'a SharedG2Affine<P>> for SharedG2<P> {
    type Output = Self;

    fn add(self, rhs: &'a SharedG2Affine<P>) -> Self::Output {
        let mut new_value = self.clone();
        new_value.add_assign(rhs);
        new_value
    }
}

// Sub
impl<'a, P: Pairing> Sub<&'a SharedG2<P>> for SharedG2<P> {
    type Output = Self;

    fn sub(self, rhs: &'a SharedG2<P>) -> Self::Output {
        let new_value = self.value.sub(rhs.value);
        SharedG2 { value:new_value }
    }
}

impl<P: Pairing> Sub<SharedG2<P>> for SharedG2<P> {
    type Output = Self;

    fn sub(self, rhs: SharedG2<P>) -> Self::Output {
        self.sub(&rhs)
    }
}

impl<'a, P: Pairing> SubAssign<&'a SharedG2<P>> for SharedG2<P> {
    fn sub_assign(&mut self, rhs: &'a SharedG2<P>) {
        let new_value = self.value.sub(rhs.value);
        *self = SharedG2 {value: new_value,};
    }
}

impl<P: Pairing> SubAssign<SharedG2<P>> for SharedG2<P> {
    fn sub_assign(&mut self, rhs: SharedG2<P>) {
        self.sub_assign(&rhs)
    }
}

impl<'a, P: Pairing> SubAssign<&'a SharedG2Affine<P>> for SharedG2<P> {
    fn sub_assign(&mut self, rhs: &'a SharedG2Affine<P>) {
        match (&mut self.value, &rhs.value) {
            (SharedGroup::Public(g2_value), SharedAffine::Public(rhs_g2_value)) => {
                g2_value.sub_assign(rhs_g2_value);
            }
            (SharedGroup::Public(_g2_value), SharedAffine::Shared(_rhs_g2_value)) => {
                todo!();
            }
            (SharedGroup::Shared(_g2_value), SharedAffine::Public(_rhs_g2_value)) => {
                todo!();
            }
            (SharedGroup::Shared(_g2_value), SharedAffine::Shared(_rhs_g2_value)) => {
                todo!();
            }
        }
    }
}

impl<P: Pairing> SubAssign<SharedG2Affine<P>> for SharedG2<P> {
    fn sub_assign(&mut self, rhs: SharedG2Affine<P>) {
        self.sub_assign(&rhs)
    }
}

impl<'a, P: Pairing> Sub<&'a SharedG2Affine<P>> for SharedG2<P> {
    type Output = Self;

    fn sub(self, rhs: &'a SharedG2Affine<P>) -> Self::Output {
        let mut new_value = self.clone();
        new_value.sub_assign(rhs);
        new_value
    }
}

impl<P: Pairing> Sub<SharedG2Affine<P>> for SharedG2<P> {
    type Output = Self;

    fn sub(self, rhs: SharedG2Affine<P>) -> Self::Output {
        self.sub(&rhs)
    }
}

// Mul
impl<'a, P: Pairing> Mul<&'a SharedField<P::ScalarField>> for SharedG2<P> {
    type Output = Self;

    fn mul(self, rhs: &'a SharedField<P::ScalarField>) -> Self::Output {
        match (&self.value, &rhs) {
            (SharedGroup::Public(g2_value), SharedField::Public(rhs_value)) => {
                let g2 = g2_value.mul(rhs_value);
                SharedG2 {
                    value: SharedGroup::Public(g2),
                }
            }
            (SharedGroup::Public(_g2_value), SharedField::Shared(_rhs_value)) => {
                todo!();
            }
            (SharedGroup::Shared(_g2_value), SharedField::Public(_rhs_value)) => {
                todo!();
            }
            (SharedGroup::Shared(_g2_value), SharedField::Shared(_rhs_value)) => {
                todo!();
            }
        }
    }
}

impl<'a, P: Pairing> MulAssign<&'a SharedField<P::ScalarField>> for SharedG2<P> {
    fn mul_assign(&mut self, rhs: &'a SharedField<P::ScalarField>) {
        *self = self.mul(rhs)
    }
}

impl<P: Pairing> MulAssign<SharedField<P::ScalarField>> for SharedG2<P> {
    fn mul_assign(&mut self, rhs: SharedField<P::ScalarField>) {
        *self = self.mul(rhs)
    }
}

impl<P: Pairing> Mul<SharedField<P::ScalarField>> for SharedG2<P> {
    type Output = Self;

    fn mul(self, rhs: SharedField<P::ScalarField>) -> Self::Output {
        self.mul(&rhs)
    }
}

// Div
impl<'a, P: Pairing> Div<&'a SharedField<P::ScalarField>> for SharedG2<P> {
    type Output = Self;

    fn div(self, _rhs: &'a SharedField<P::ScalarField>) -> Self::Output {
        todo!()
    }
}

// Sum
impl<'a, P: Pairing> Sum<&'a SharedG2<P>> for SharedG2<P> {
    fn sum<I: Iterator<Item = &'a SharedG2<P>>>(_iter: I) -> Self {
        todo!()
    }
}

impl<P: Pairing> Sum<SharedG2<P>> for SharedG2<P> {
    fn sum<I: Iterator<Item = SharedG2<P>>>(_iter: I) -> Self {
        todo!()
    }
}

impl<'a, P: Pairing> Sum<&'a SharedG2Affine<P>> for SharedG2<P> {
    fn sum<I: Iterator<Item = &'a SharedG2Affine<P>>>(_iter: I) -> Self {
        todo!()
    }
}

impl<P: Pairing> Sum<SharedG2Affine<P>> for SharedG2<P> {
    fn sum<I: Iterator<Item = SharedG2Affine<P>>>(_iter: I) -> Self {
        todo!()
    }
}

// Neg
impl<P: Pairing> Neg for SharedG2<P> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        // TODO: Can we do this?
        Self { value: -self.value }
    }
}

// Zero
impl<P: Pairing> Zero for SharedG2<P> {
    fn zero() -> Self {
        let g2 = P::G2::zero();
        SharedG2 {
            value: SharedGroup::new(g2),
        }
    }

    fn is_zero(&self) -> bool {
        todo!()
    }
}

impl<P: Pairing> DefaultIsZeroes for SharedG2<P> {}

// Display
impl<P: Pairing> Display for SharedG2<P> {
    fn fmt(&self, _f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

// Serialize
impl<P: Pairing> Valid for SharedG2<P> {
    fn check(&self) -> Result<(), SerializationError> {
        todo!()
    }
}

impl<P: Pairing> CanonicalSerialize for SharedG2<P> {
    fn serialize_with_mode<W: Write>(
        &self,
        _writer: W,
        _compress: ark_serialize::Compress,
    ) -> Result<(), SerializationError> {
        todo!()
    }

    fn serialized_size(&self, _compress: ark_serialize::Compress) -> usize {
        todo!()
    }
}

impl<P: Pairing> CanonicalDeserialize for SharedG2<P> {
    fn deserialize_with_mode<R: std::io::prelude::Read>(
        _reader: R,
        _compress: ark_serialize::Compress,
        _validate: ark_serialize::Validate,
    ) -> Result<Self, SerializationError> {
        todo!()
    }
}

// Standard
impl<P: Pairing> Distribution<SharedG2<P>> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> SharedG2<P> {
        let g2 = P::G2::rand(rng);
        SharedG2 {
            value: SharedGroup::new(g2),
        }
    }
}

pub struct Config<P: Pairing> {
    _pairing: std::marker::PhantomData<P>,
}

// Define our own CurveConfig where we use the shared versions of BaseField and ScalarField
impl<P: Pairing> CurveConfig for Config<P>
where
    SharedField<P::BaseField>: From<<<P as Pairing>::BaseField as PrimeField>::BigInt>,
    <<P as Pairing>::BaseField as PrimeField>::BigInt: From<SharedField<<P as Pairing>::BaseField>>,
    BigUint: From<SharedField<<P as Pairing>::BaseField>>,

    SharedField<P::ScalarField>: From<<<P as Pairing>::ScalarField as PrimeField>::BigInt>,
    <<P as Pairing>::ScalarField as PrimeField>::BigInt:
        From<SharedField<<P as Pairing>::ScalarField>>,
    BigUint: From<SharedField<<P as Pairing>::ScalarField>>,

    SharedField<<P as Pairing>::ScalarField>: From<<P as Pairing>::ScalarField>,
    <<P as Pairing>::ScalarField as FromStr>::Err: Debug,
    <<P as Pairing>::BaseField as FromStr>::Err: Debug,
{
    type BaseField = SharedField<P::BaseField>;
    type ScalarField = SharedField<P::ScalarField>;

    const COFACTOR: &'static [u64] =
        <<<P as Pairing>::G2 as CurveGroup>::Config as CurveConfig>::COFACTOR;

    const COFACTOR_INV: Self::ScalarField =
        SharedField::new(<<<P as Pairing>::G2 as CurveGroup>::Config as CurveConfig>::COFACTOR_INV);
}

// CurveGroup
impl<P: Pairing> CurveGroup for SharedG2<P>
where
    SharedField<<P as Pairing>::ScalarField>:
        From<<<P as Pairing>::ScalarField as PrimeField>::BigInt>,
    <<P as Pairing>::ScalarField as PrimeField>::BigInt:
        From<SharedField<<P as Pairing>::ScalarField>>,
    BigUint: From<SharedField<<P as Pairing>::ScalarField>>,

    SharedField<<P as Pairing>::BaseField>: From<<<P as Pairing>::BaseField as PrimeField>::BigInt>,
    <<P as Pairing>::BaseField as PrimeField>::BigInt: From<SharedField<<P as Pairing>::BaseField>>,
    BigUint: From<SharedField<<P as Pairing>::BaseField>>,

    SharedField<<P as Pairing>::ScalarField>: From<<P as Pairing>::ScalarField>,
    <<P as Pairing>::ScalarField as FromStr>::Err: Debug,
    <<P as Pairing>::BaseField as FromStr>::Err: Debug,
{
    type Config = Config<P>;
    type BaseField = SharedField<P::BaseField>;
    type Affine = SharedG2Affine<P>;
    type FullGroup = SharedG2Affine<P>;

    fn normalize_batch(v: &[Self]) -> Vec<Self::Affine> {
        let mut result = Vec::new();
        for g2 in v {
            result.push(g2.into_affine());
        }
        result
    }
}

// VariableBaseMSM

// ScalarMul
impl<P: Pairing> ScalarMul for SharedG2<P>
where
    SharedField<<P as Pairing>::BaseField>: From<<<P as Pairing>::BaseField as PrimeField>::BigInt>,
    <<P as Pairing>::BaseField as PrimeField>::BigInt: From<SharedField<<P as Pairing>::BaseField>>,
    BigUint: From<SharedField<<P as Pairing>::BaseField>>,

    SharedField<<P as Pairing>::ScalarField>:
        From<<<P as Pairing>::ScalarField as PrimeField>::BigInt>,
    <<P as Pairing>::ScalarField as PrimeField>::BigInt:
        From<SharedField<<P as Pairing>::ScalarField>>,
    BigUint: From<SharedField<<P as Pairing>::ScalarField>>,

    SharedField<<P as Pairing>::ScalarField>: From<<P as Pairing>::ScalarField>,
    <<P as Pairing>::ScalarField as FromStr>::Err: Debug,
    <<P as Pairing>::BaseField as FromStr>::Err: Debug,
{
    type MulBase = SharedG2Affine<P>;

    const NEGATION_IS_CHEAP: bool = true;

    fn batch_convert_to_mul_base(bases: &[Self]) -> Vec<Self::MulBase> {
        Self::normalize_batch(bases)
    }
}

impl<P: Pairing> VariableBaseMSM for SharedG2<P>
where
    SharedField<<P as Pairing>::BaseField>: From<<<P as Pairing>::BaseField as PrimeField>::BigInt>,
    <<P as Pairing>::BaseField as PrimeField>::BigInt: From<SharedField<<P as Pairing>::BaseField>>,
    BigUint: From<SharedField<<P as Pairing>::BaseField>>,

    SharedField<<P as Pairing>::ScalarField>:
        From<<<P as Pairing>::ScalarField as PrimeField>::BigInt>,
    <<P as Pairing>::ScalarField as PrimeField>::BigInt:
        From<SharedField<<P as Pairing>::ScalarField>>,
    BigUint: From<SharedField<<P as Pairing>::ScalarField>>,

    SharedField<<P as Pairing>::ScalarField>: From<<P as Pairing>::ScalarField>,

    <<P as Pairing>::ScalarField as FromStr>::Err: Debug,
    <<P as Pairing>::BaseField as FromStr>::Err: Debug,
{
}
