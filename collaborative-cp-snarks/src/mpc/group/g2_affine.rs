use std::{
    fmt::{Debug, Display, Formatter},
    ops::{Add, Mul, Neg},
    str::FromStr,
};

use ark_ec::CurveGroup;
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError, Valid, Write};
use derivative::Derivative;
// use futures::executor::block_on;
use num_bigint::BigUint;
use rand::{
    distributions::{Distribution, Standard},
    Rng,
};
use zeroize::DefaultIsZeroes;

use crate::{mpc::field::SharedField, network::{ElementType, Net}};

use super::{
    g2::{Config, SharedG2},
    group::{SharedAffine, SharedAffineTrait, SharedGroup},
};

#[derive(Derivative)]
#[derivative(Copy, Clone, PartialEq, Eq, Debug, Hash, Default)]
pub struct SharedG2Affine<P: Pairing> {
    pub value: SharedAffine<P::G2Affine>,
}

impl<P: Pairing> From<SharedG2<P>> for SharedG2Affine<P> {
    fn from(value: SharedG2<P>) -> Self {
        match value.value {
            SharedGroup::Public(value) => SharedG2Affine {
                value: SharedAffine::Public(value.into_affine()),
            },
            SharedGroup::Shared(value) => SharedG2Affine {
                value: SharedAffine::Shared(value.into_affine()),
            },
        }
    }
}

impl<P: Pairing> SharedAffineTrait<P::G2Affine> for SharedG2Affine<P>
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
    type Base = P::G2Affine;

    fn reveal(self) -> SharedG2Affine<P> {
        match self.value {
            SharedAffine::Public(_) => self,
            SharedAffine::Shared(value) => {
                let shares: Vec<<P as Pairing>::G2Affine> =
                    Net::exchange_elements::<P::G2Affine>(value, ElementType::G2);

                let sum = shares
                    .iter()
                    .fold(P::G2Affine::zero(), |acc, x| (acc + x).into());

                SharedG2Affine {
                    value: SharedAffine::Public(sum),
                }
            }
        }
    }

    fn from_public(value: P::G2Affine) -> SharedG2Affine<P> {
        SharedG2Affine {
            value: SharedAffine::Public(value),
        }
    }

    fn from_shared(value: P::G2Affine) -> SharedG2Affine<P> {
        SharedG2Affine {
            value: SharedAffine::Shared(value),
        }
    }
}

// AffineRepr
impl<P: Pairing> AffineRepr for SharedG2Affine<P>
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
    type Config = Config<P>;

    type ScalarField = SharedField<P::ScalarField>;
    type BaseField = SharedField<P::BaseField>;

    type Group = SharedG2<P>;

    fn xy(&self) -> Option<(&Self::BaseField, &Self::BaseField)> {
        todo!()
    }

    fn zero() -> Self {
        todo!()
    }

    fn generator() -> Self {
        return SharedG2Affine {
            value: SharedAffine::Public(P::G2Affine::generator()),
        };
    }

    fn from_random_bytes(_bytes: &[u8]) -> Option<Self> {
        todo!()
    }

    fn mul_bigint(&self, _by: impl AsRef<[u64]>) -> Self::Group {
        todo!();
    }

    fn clear_cofactor(&self) -> Self {
        todo!()
    }

    fn mul_by_cofactor_to_group(&self) -> Self::Group {
        todo!()
    }
}

// Arithmetic
// Mul
impl<'a, P: Pairing> Mul<&'a SharedField<<P as Pairing>::ScalarField>> for SharedG2Affine<P>
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
    type Output = <Self as AffineRepr>::Group;

    fn mul(self, rhs: &'a SharedField<<P as Pairing>::ScalarField>) -> Self::Output {
        match (self.value, rhs) {
            (SharedAffine::Public(value), SharedField::Public(rhs)) => SharedG2 {
                value: SharedGroup::Public(value.mul(rhs)),
            },
            (SharedAffine::Shared(value), SharedField::Public(rhs)) => SharedG2 {
                value: SharedGroup::Shared(value.mul(rhs)),
            },
            (SharedAffine::Public(value), SharedField::Shared(rhs)) => SharedG2 {
                value: SharedGroup::Shared(value.mul(rhs)),
            },
            (SharedAffine::Shared(_value), SharedField::Shared(_rhs)) => {
                todo!();
            }
        }
    }
}

impl<P: Pairing> Mul<SharedField<<P as Pairing>::ScalarField>> for SharedG2Affine<P>
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
    type Output = <Self as AffineRepr>::Group;

    fn mul(self, rhs: SharedField<<P as Pairing>::ScalarField>) -> Self::Output {
        self.mul(&rhs)
    }
}

// Add
impl<P: Pairing> Add<SharedG2Affine<P>> for SharedG2Affine<P>
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
    type Output = <Self as AffineRepr>::Group;

    fn add(self, rhs: SharedG2Affine<P>) -> Self::Output {
        match (self.value, rhs.value) {
            (SharedAffine::Public(lhs), SharedAffine::Public(rhs)) => SharedG2 {
                value: SharedGroup::Public(lhs + rhs),
            },
            (SharedAffine::Shared(_lhs), SharedAffine::Public(_rhs)) => {
                todo!();
            }
            (SharedAffine::Public(_lhs), SharedAffine::Shared(_rhs)) => {
                todo!();
            }
            (SharedAffine::Shared(_lhs), SharedAffine::Shared(_rhs)) => {
                todo!();
            }
        }
    }
}

impl<'a, P: Pairing> Add<&'a SharedG2<P>> for SharedG2Affine<P>
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
    type Output = <Self as AffineRepr>::Group;

    fn add(self, rhs: &'a SharedG2<P>) -> Self::Output {
        self.add(*rhs)
    }
}

impl<P: Pairing> Add<SharedG2<P>> for SharedG2Affine<P>
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
    type Output = <Self as AffineRepr>::Group;

    fn add(self, _rhs: SharedG2<P>) -> Self::Output {
        todo!()
    }
}

impl<'a, P: Pairing> Add<&'a SharedG2Affine<P>> for SharedG2Affine<P>
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
    type Output = <Self as AffineRepr>::Group;

    fn add(self, _rhs: &'a SharedG2Affine<P>) -> Self::Output {
        todo!()
    }
}

// Neg
impl<P: Pairing> Neg for SharedG2Affine<P> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        todo!()
    }
}

impl<P: Pairing> DefaultIsZeroes for SharedG2Affine<P> {}

// Display
impl<P: Pairing> Display for SharedG2Affine<P> {
    fn fmt(&self, _f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

// Serialize
impl<P: Pairing> Valid for SharedG2Affine<P> {
    fn check(&self) -> Result<(), SerializationError> {
        todo!()
    }
}

impl<P: Pairing> CanonicalSerialize for SharedG2Affine<P> {
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

impl<P: Pairing> CanonicalDeserialize for SharedG2Affine<P> {
    fn deserialize_with_mode<R: std::io::prelude::Read>(
        _reader: R,
        _compress: ark_serialize::Compress,
        _validate: ark_serialize::Validate,
    ) -> Result<Self, SerializationError> {
        todo!()
    }
}

// Standard
impl<P: Pairing> Distribution<SharedG2Affine<P>> for Standard {
    fn sample<R: Rng + ?Sized>(&self, _rng: &mut R) -> SharedG2Affine<P> {
        todo!()
    }
}
