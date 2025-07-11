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
    g1_affine::SharedG1Affine,
    group::{SharedAffine, SharedGroup, SharedGroupTrait},
};

#[derive(Derivative)]
#[derivative(Copy, Clone, PartialEq, Eq, Debug, Hash, Default)]
pub struct SharedG1<P: Pairing> {
    pub value: SharedGroup<P::G1>,
}

impl<P: Pairing> SharedGroupTrait<P::G1> for SharedG1<P>
where
    SharedField<<P as Pairing>::ScalarField>:
        From<<<P as Pairing>::ScalarField as PrimeField>::BigInt>,
    <<P as Pairing>::ScalarField as PrimeField>::BigInt:
        From<SharedField<<P as Pairing>::ScalarField>>,
    BigUint: From<SharedField<<P as Pairing>::ScalarField>>,

    <<P as Pairing>::ScalarField as FromStr>::Err: Debug,
{
    fn as_base(_value: Self) -> P::G1 {
        todo!()
    }

    fn reveal(self) -> SharedG1<P> {
        todo!()
    }
}

impl<P: Pairing> From<SharedG1Affine<P>> for SharedG1<P> {
    fn from(value: SharedG1Affine<P>) -> Self {
        let g1 = match value.value {
            SharedAffine::Public(value) => P::G1::from(value),
            SharedAffine::Shared(value) => P::G1::from(value),
        };

        SharedG1 {
            value: SharedGroup::new(g1),
        }
    }
}

impl<P: Pairing> Group for SharedG1<P>
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
            SharedGroup::Public(g1_value) => {
                let mut g1 = g1_value.clone();
                g1.double_in_place();
                SharedGroup::Public(g1)
            }
            SharedGroup::Shared(_g1_value) => {
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
impl<P: Pairing> Add<SharedG1<P>> for SharedG1<P> {
    type Output = Self;

    fn add(self, rhs: SharedG1<P>) -> Self::Output {
        let value = self.value.add(rhs.value);
        SharedG1 { value }
    }
}

impl<'a, P: Pairing> Add<&'a SharedG1<P>> for SharedG1<P> {
    type Output = Self;

    fn add(self, rhs: &'a SharedG1<P>) -> Self::Output {
        let value = self.value.add(rhs.value);
        SharedG1 { value }
    }
}

impl<'a, P: Pairing> AddAssign<&'a SharedG1<P>> for SharedG1<P> {
    fn add_assign(&mut self, rhs: &'a SharedG1<P>) {
        let new_value = self.value.add(rhs.value);
        *self = SharedG1 {value: new_value,};
    }
}

impl<P: Pairing> AddAssign<SharedG1<P>> for SharedG1<P> {
    fn add_assign(&mut self, rhs: SharedG1<P>) {
        self.value.add_assign(rhs.value)
    }
}

impl<'a, P: Pairing> AddAssign<&'a SharedG1Affine<P>> for SharedG1<P> {
    fn add_assign(&mut self, rhs: &'a SharedG1Affine<P>) {
        match (&mut self.value, &rhs.value) {
            (SharedGroup::Public(g1_value), SharedAffine::Public(rhs_g1_value)) => {
                g1_value.add_assign(rhs_g1_value);
            }
            (SharedGroup::Public(_g1_value), SharedAffine::Shared(_rhs_g1_value)) => {
                todo!();
            }
            (SharedGroup::Shared(g1_value), SharedAffine::Public(rhs_g1_value)) => {
                if get_party_id() == 0 {
                    g1_value.add_assign(rhs_g1_value);
                }
            }
            (SharedGroup::Shared(_g1_value), SharedAffine::Shared(_rhs_g1_value)) => {
                todo!();
            }
        }
    }
}

impl<P: Pairing> AddAssign<SharedG1Affine<P>> for SharedG1<P> {
    fn add_assign(&mut self, rhs: SharedG1Affine<P>) {
        self.add_assign(&rhs);
    }
}

impl<P: Pairing> Add<SharedG1Affine<P>> for SharedG1<P> {
    type Output = Self;

    fn add(self, rhs: SharedG1Affine<P>) -> Self::Output {
        self.add(&rhs)
    }
}

impl<'a, P: Pairing> Add<&'a SharedG1Affine<P>> for SharedG1<P> {
    type Output = Self;

    fn add(self, rhs: &'a SharedG1Affine<P>) -> Self::Output {
        let mut new_value = self.clone();
        new_value.add_assign(rhs);
        new_value
    }
}

// Sub
impl<'a, P: Pairing> Sub<&'a SharedG1<P>> for SharedG1<P> {
    type Output = Self;

    fn sub(self, rhs: &'a SharedG1<P>) -> Self::Output {
        let new_value = self.value.sub(rhs.value);
        SharedG1 { value:new_value }
    }
}

impl<P: Pairing> Sub<SharedG1<P>> for SharedG1<P> {
    type Output = Self;

    fn sub(self, rhs: SharedG1<P>) -> Self::Output {
        let new_value = self.value.sub(rhs.value);
        SharedG1 { value:new_value }
    }
}

impl<'a, P: Pairing> SubAssign<&'a SharedG1<P>> for SharedG1<P> {
    fn sub_assign(&mut self, rhs: &'a SharedG1<P>) {
        let new_value = self.value.sub(rhs.value);
        *self = SharedG1 {value: new_value,};
    }
}

impl<P: Pairing> SubAssign<SharedG1<P>> for SharedG1<P> {
    fn sub_assign(&mut self, rhs: SharedG1<P>) {
        self.value.sub_assign(rhs.value)
    }
}

impl<'a, P: Pairing> SubAssign<&'a SharedG1Affine<P>> for SharedG1<P> {
    fn sub_assign(&mut self, rhs: &'a SharedG1Affine<P>) {
        match (&mut self.value, &rhs.value) {
            (SharedGroup::Public(g1_value), SharedAffine::Public(rhs_g1_value)) => {
                g1_value.sub_assign(rhs_g1_value);
            }
            (SharedGroup::Public(_g1_value), SharedAffine::Shared(_rhs_g1_value)) => {
                todo!();
            }
            (SharedGroup::Shared(_g1_value), SharedAffine::Public(_rhs_g1_value)) => {
                todo!();
            }
            (SharedGroup::Shared(_g1_value), SharedAffine::Shared(_rhs_g1_value)) => {
                todo!();
            }
        }
    }
}

impl<P: Pairing> SubAssign<SharedG1Affine<P>> for SharedG1<P> {
    fn sub_assign(&mut self, rhs: SharedG1Affine<P>) {
        self.sub_assign(&rhs)
    }
}

impl<'a, P: Pairing> Sub<&'a SharedG1Affine<P>> for SharedG1<P> {
    type Output = Self;

    fn sub(self, rhs: &'a SharedG1Affine<P>) -> Self::Output {
        let mut new_value = self.clone();
        new_value.sub_assign(rhs);
        new_value
    }
}

impl<P: Pairing> Sub<SharedG1Affine<P>> for SharedG1<P> {
    type Output = Self;

    fn sub(self, rhs: SharedG1Affine<P>) -> Self::Output {
        self.sub(&rhs)
    }
}

// Mul
impl<'a, P: Pairing> Mul<&'a SharedField<P::ScalarField>> for SharedG1<P> {
    type Output = Self;

    fn mul(self, rhs: &'a SharedField<P::ScalarField>) -> Self::Output {
        match (&self.value, &rhs) {
            (SharedGroup::Public(g1_value), SharedField::Public(rhs_value)) => {
                let g1 = g1_value.mul(rhs_value);
                SharedG1 {
                    value: SharedGroup::Public(g1),
                }
            }
            (SharedGroup::Public(_g1_value), SharedField::Shared(_rhs_value)) => {
                todo!();
            }
            (SharedGroup::Shared(g1_value), SharedField::Public(rhs_value)) => {
                let g1 = g1_value.mul(rhs_value);
                SharedG1 {
                    value: SharedGroup::Shared(g1),
                }
            }
            (SharedGroup::Shared(_g1_value), SharedField::Shared(_rhs_value)) => {
                todo!();
            }
        }
    }
}

impl<'a, P: Pairing> MulAssign<&'a SharedField<P::ScalarField>> for SharedG1<P> {
    fn mul_assign(&mut self, rhs: &'a SharedField<P::ScalarField>) {
        *self = self.mul(rhs)
    }
}

impl<P: Pairing> MulAssign<SharedField<P::ScalarField>> for SharedG1<P> {
    fn mul_assign(&mut self, rhs: SharedField<P::ScalarField>) {
        *self = self.mul(rhs)
    }
}

impl<P: Pairing> Mul<SharedField<P::ScalarField>> for SharedG1<P> {
    type Output = Self;

    fn mul(self, rhs: SharedField<P::ScalarField>) -> Self::Output {
        self.mul(&rhs)
    }
}

// Div
impl<'a, P: Pairing> Div<&'a SharedField<P::ScalarField>> for SharedG1<P> {
    type Output = Self;

    fn div(self, _rhs: &'a SharedField<P::ScalarField>) -> Self::Output {
        todo!()
    }
}

// Sum
impl<'a, P: Pairing> Sum<&'a SharedG1<P>> for SharedG1<P> {
    fn sum<I: Iterator<Item = &'a SharedG1<P>>>(_iter: I) -> Self {
        todo!()
    }
}

impl<P: Pairing> Sum<SharedG1<P>> for SharedG1<P> {
    fn sum<I: Iterator<Item = SharedG1<P>>>(_iter: I) -> Self {
        todo!()
    }
}

impl<'a, P: Pairing> Sum<&'a SharedG1Affine<P>> for SharedG1<P> {
    fn sum<I: Iterator<Item = &'a SharedG1Affine<P>>>(_iter: I) -> Self {
        todo!()
    }
}

impl<P: Pairing> Sum<SharedG1Affine<P>> for SharedG1<P> {
    fn sum<I: Iterator<Item = SharedG1Affine<P>>>(_iter: I) -> Self {
        todo!()
    }
}

// Neg
impl<P: Pairing> Neg for SharedG1<P> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        todo!()
    }
}

// Zero
impl<P: Pairing> Zero for SharedG1<P> {
    fn zero() -> Self {
        let g1 = P::G1::zero();
        SharedG1 {
            value: SharedGroup::new(g1),
        }
    }

    fn is_zero(&self) -> bool {
        todo!()
    }
}

impl<P: Pairing> DefaultIsZeroes for SharedG1<P> {}

// Display
impl<P: Pairing> Display for SharedG1<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let value = match &self.value {
            SharedGroup::Public(g1_value) => "Public".to_string() + &g1_value.to_string(),
            SharedGroup::Shared(g1_value) => "Shared".to_string() + &g1_value.to_string(),
        };

        write!(f, "SharedG1({})", value)
    }
}

// Serialize
impl<P: Pairing> Valid for SharedG1<P> {
    fn check(&self) -> Result<(), SerializationError> {
        todo!()
    }
}

impl<P: Pairing> CanonicalSerialize for SharedG1<P> {
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

impl<P: Pairing> CanonicalDeserialize for SharedG1<P> {
    fn deserialize_with_mode<R: std::io::prelude::Read>(
        _reader: R,
        _compress: ark_serialize::Compress,
        _validate: ark_serialize::Validate,
    ) -> Result<Self, SerializationError> {
        todo!()
    }
}

// Standard
impl<P: Pairing> Distribution<SharedG1<P>> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> SharedG1<P> {
        let g1 = P::G1::rand(rng);
        SharedG1 {
            value: SharedGroup::new(g1),
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
        <<<P as Pairing>::G1 as CurveGroup>::Config as CurveConfig>::COFACTOR;

    const COFACTOR_INV: Self::ScalarField =
        SharedField::new(<<<P as Pairing>::G1 as CurveGroup>::Config as CurveConfig>::COFACTOR_INV);
}

// CurveGroup
impl<P: Pairing> CurveGroup for SharedG1<P>
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
    type Affine = SharedG1Affine<P>;
    type FullGroup = SharedG1Affine<P>;

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
impl<P: Pairing> ScalarMul for SharedG1<P>
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
    type MulBase = SharedG1Affine<P>;

    const NEGATION_IS_CHEAP: bool = true;

    fn batch_convert_to_mul_base(bases: &[Self]) -> Vec<Self::MulBase> {
        Self::normalize_batch(bases)
    }
}

impl<P: Pairing> VariableBaseMSM for SharedG1<P>
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
