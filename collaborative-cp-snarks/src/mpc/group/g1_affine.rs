use std::{
    fmt::{Debug, Display, Formatter},
    ops::{Add, Mul, Neg},
    str::FromStr,
};

use ark_ec::CurveGroup;
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use derivative::Derivative;
use num_bigint::BigUint;
use rand::{
    distributions::{Distribution, Standard},
    Rng,
};
use zeroize::DefaultIsZeroes;

use crate::{mpc::field::SharedField, network::{ElementType, Net}};

use super::{
    g1::{Config, SharedG1},
    group::{SharedAffine, SharedAffineTrait, SharedGroup},
};

#[derive(CanonicalDeserialize, CanonicalSerialize, Derivative)]
#[derivative(Copy, Clone, PartialEq, Eq, Debug, Hash, Default)]
pub struct SharedG1Affine<P: Pairing> {
    pub value: SharedAffine<P::G1Affine>,
}

impl<P: Pairing> From<SharedG1<P>> for SharedG1Affine<P> {
    fn from(value: SharedG1<P>) -> Self {
        match value.value {
            SharedGroup::Public(value) => SharedG1Affine {
                value: SharedAffine::Public(value.into_affine()),
            },
            SharedGroup::Shared(value) => SharedG1Affine {
                value: SharedAffine::Shared(value.into_affine()),
            },
        }
    }
}

impl<P:Pairing> SharedG1Affine<P>{
    pub fn new(value: P::G1Affine) -> Self {
        SharedG1Affine{value:SharedAffine::new(value)}
    }

    pub fn get_share_group_val(self) -> P::G1Affine {
        self.value.get_share_group_val()
    }
}

impl<P: Pairing> SharedAffineTrait<P::G1Affine> for SharedG1Affine<P>
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
    type Base = P::G1Affine;

    fn reveal(self) -> SharedG1Affine<P> {
        match self.value {
            SharedAffine::Public(_) => self,
            SharedAffine::Shared(value) => {
                let shares: Vec<<P as Pairing>::G1Affine> =
                    Net::exchange_elements::<P::G1Affine>(value, ElementType::G1);

                let sum = shares
                    .iter()
                    .fold(P::G1Affine::zero(), |acc, x| (acc + x).into());

                SharedG1Affine {
                    value: SharedAffine::Public(sum),
                }
            }
        }
    }

    fn from_public(value: P::G1Affine) -> SharedG1Affine<P> {
        SharedG1Affine {
            value: SharedAffine::Public(value),
        }
    }

    fn from_shared(value: P::G1Affine) -> SharedG1Affine<P> {
        SharedG1Affine {
            value: SharedAffine::Shared(value),
        }
    }
}

// AffineRepr
impl<P: Pairing> AffineRepr for SharedG1Affine<P>
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

    type Group = SharedG1<P>;

    fn xy(&self) -> Option<(&Self::BaseField, &Self::BaseField)> {
        todo!()
    }

    fn zero() -> Self {
        todo!()
    }

    fn generator() -> Self {
        return SharedG1Affine {
            value: SharedAffine::Public(P::G1Affine::generator()),
        };
    }

    fn from_random_bytes(_bytes: &[u8]) -> Option<Self> {
        todo!()
    }

    fn mul_bigint(&self, by: impl AsRef<[u64]>) -> Self::Group {
        SharedG1 {
            value: SharedGroup::Public(match self.value {
                SharedAffine::Public(value) => value.mul_bigint(by),
                SharedAffine::Shared(_value) => {
                    todo!();
                }
            }),
        }
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
impl<'a, P: Pairing> Mul<&'a SharedField<<P as Pairing>::ScalarField>> for SharedG1Affine<P>
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
            (SharedAffine::Public(value), SharedField::Public(rhs)) => SharedG1 {
                value: SharedGroup::Public(value.mul(rhs)),
            },
            (SharedAffine::Shared(value), SharedField::Public(rhs)) => SharedG1 {
                value: SharedGroup::Shared(value.mul(rhs)),
            },
            (SharedAffine::Public(value), SharedField::Shared(rhs)) => SharedG1 {
                value: SharedGroup::Shared(value.mul(rhs)),
            },
            (SharedAffine::Shared(_value), SharedField::Shared(_rhs)) => {
                todo!();
            }
        }
    }
}

impl<P: Pairing> Mul<SharedField<<P as Pairing>::ScalarField>> for SharedG1Affine<P>
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
impl<P: Pairing> Add<SharedG1Affine<P>> for SharedG1Affine<P>
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

    fn add(self, rhs: SharedG1Affine<P>) -> Self::Output {
        match (self.value, rhs.value) {
            (SharedAffine::Public(lhs), SharedAffine::Public(rhs)) => SharedG1 {
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

impl<'a, P: Pairing> Add<&'a SharedG1<P>> for SharedG1Affine<P>
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

    fn add(self, rhs: &'a SharedG1<P>) -> Self::Output {
        self.add(*rhs)
    }
}

impl<P: Pairing> Add<SharedG1<P>> for SharedG1Affine<P>
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

    fn add(self, _rhs: SharedG1<P>) -> Self::Output {
        todo!()
    }
}

impl<'a, P: Pairing> Add<&'a SharedG1Affine<P>> for SharedG1Affine<P>
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

    fn add(self, _rhs: &'a SharedG1Affine<P>) -> Self::Output {
        todo!()
    }
}

// Neg
impl<P: Pairing> Neg for SharedG1Affine<P> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        todo!()
    }
}

impl<P: Pairing> DefaultIsZeroes for SharedG1Affine<P> {}

// Display
impl<P: Pairing> Display for SharedG1Affine<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.value.fmt(f)
    }
}

// Standard
impl<P: Pairing> Distribution<SharedG1Affine<P>> for Standard {
    fn sample<R: Rng + ?Sized>(&self, _rng: &mut R) -> SharedG1Affine<P> {
        todo!()
    }
}

// FromStr
impl<P: Pairing> FromStr for SharedG1Affine<P> {
    type Err = String;

    fn from_str(_s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}
