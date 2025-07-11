use std::{
    fmt::{Debug, Display, Formatter},
    ops::{Add, Mul, Neg},
    str::FromStr,
};

use ark_ec::CurveGroup;
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError, Valid, Write};
use ark_std::UniformRand;
use derivative::Derivative;
// use futures::executor::block_on;
use num_bigint::BigUint;
use rand::{distributions::{Distribution, Standard}, Rng, SeedableRng};
use zeroize::DefaultIsZeroes;

use crate::{mpc::spdz_field::SpdzSharedField, network::{ElementType, Net}};
use crate::globals::get_n_parties;
use crate::mpc::spdz_group::group::{mac_cheat, mac_share, SpdzSharedGroupTrait};

use super::{
    g2::{Config, SpdzSharedG2},
    group::{SpdzSharedAffine, SpdzSharedAffineTrait, SpdzSharedGroup},
};

#[derive(Derivative)]
#[derivative(Copy, Clone, PartialEq, Eq, Debug, Hash, Default)]
pub struct SpdzSharedG2Affine<P: Pairing> {
    pub value: SpdzSharedAffine<P::G2Affine>,
}

impl<P: Pairing> From<SpdzSharedG2<P>> for SpdzSharedG2Affine<P> {
    fn from(value: SpdzSharedG2<P>) -> Self {
        match value.value {
            SpdzSharedGroup::Public{sh,mac} => SpdzSharedG2Affine {
                value: SpdzSharedAffine::Public{sh:sh.into_affine(), mac:mac.into_affine()},
            },
            SpdzSharedGroup::Shared{sh,mac} => SpdzSharedG2Affine {
                value: SpdzSharedAffine::Shared{sh:sh.into_affine(), mac:mac.into_affine()},
            },
        }
    }
}

impl<P: Pairing> SpdzSharedAffineTrait<P::G2Affine> for SpdzSharedG2Affine<P>
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
    type Base = P::G2Affine;

    fn reveal(self) -> SpdzSharedG2Affine<P> {
        match self.value {
            SpdzSharedAffine::Public { sh,mac } => self,
            SpdzSharedAffine::Shared{sh,mac} => {
                let shares: Vec<<P as Pairing>::G2Affine> =
                    Net::exchange_elements::<P::G2Affine>(sh, ElementType::G2);

                let sum = shares
                    .iter()
                    .fold(P::G2Affine::zero(), |acc, x| (acc + x).into());

                let dx_t: <P as Pairing>::G2Affine = (sum * mac_share::<P::ScalarField>() - mac).into();

                let all_dx_ts = Net::exchange_elements(dx_t, ElementType::G2);

                let all_dx_ts_sum: <P as Pairing>::G2 = all_dx_ts.iter().sum();
                let all_dx_ts_sum_aff: <P as Pairing>::G2Affine = all_dx_ts_sum.into();

                assert_eq!(all_dx_ts_sum_aff, P::G2Affine::zero());

                SpdzSharedG2Affine::from_public(sum)
            }
        }
    }

    fn from_public(value: P::G2Affine) -> SpdzSharedG2Affine<P> {
        SpdzSharedG2Affine {
            value: SpdzSharedAffine::Public{sh:value, mac: (value*mac_share::<P::ScalarField>()).into()},
        }
    }

    fn from_shared(value: P::G2Affine) -> SpdzSharedG2Affine<P> {
        SpdzSharedG2Affine {
            value: SpdzSharedAffine::Shared{sh:value, mac: (value*mac_cheat::<P::ScalarField>()).into()},
        }
    }
}

// AffineRepr
impl<P: Pairing> AffineRepr for SpdzSharedG2Affine<P>
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
    type Config = Config<P>;

    type ScalarField = SpdzSharedField<P::ScalarField>;
    type BaseField = SpdzSharedField<P::BaseField>;

    type Group = SpdzSharedG2<P>;

    fn xy(&self) -> Option<(&Self::BaseField, &Self::BaseField)> {
        todo!()
    }

    fn zero() -> Self {
        SpdzSharedG2Affine {
            value: SpdzSharedAffine::Public {sh: P::G2Affine::zero(), mac: P::G2Affine::zero() }
        }
    }

    fn generator() -> Self {
        return SpdzSharedG2Affine {
            value: SpdzSharedAffine::Public{sh:P::G2Affine::generator(),mac:(P::G2Affine::generator()*mac_share::<P::ScalarField>()).into()},
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
impl<'a, P: Pairing> Mul<&'a SpdzSharedField<<P as Pairing>::ScalarField>> for SpdzSharedG2Affine<P>
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
    type Output = <Self as AffineRepr>::Group;

    fn mul(self, rhs: &'a SpdzSharedField<<P as Pairing>::ScalarField>) -> Self::Output {
        match (self.value, rhs) {
            (SpdzSharedAffine::Public{sh:lhs_sh,mac:lhs_mac}, SpdzSharedField::Public{sh:rhs_sh,mac:rhs_mac}) => SpdzSharedG2 {
                value: SpdzSharedGroup::Public{sh:lhs_sh.mul(rhs_sh), mac:lhs_mac.mul(rhs_mac)},
            },
            (SpdzSharedAffine::Shared{sh:lhs_sh,mac:lhs_mac}, SpdzSharedField::Public{sh:rhs_sh,mac:rhs_mac}) => {
                let sh = lhs_sh.mul(rhs_sh);
                SpdzSharedG2::from_shared(sh)
            },
            (SpdzSharedAffine::Public{sh:lhs_sh,mac:lhs_mac}, SpdzSharedField::Shared{sh:rhs_sh,mac:rhs_mac}) =>  {
                let sh = lhs_sh.mul(rhs_sh);
                SpdzSharedG2::from_shared(sh)
            },
            (SpdzSharedAffine::Shared{sh:lhs_sh,mac:lhs_mac}, SpdzSharedField::Shared{sh:rhs_sh,mac:rhs_mac}) => {
                todo!();
            }
        }
    }
}

impl<P: Pairing> Mul<SpdzSharedField<<P as Pairing>::ScalarField>> for SpdzSharedG2Affine<P>
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
    type Output = <Self as AffineRepr>::Group;

    fn mul(self, rhs: SpdzSharedField<<P as Pairing>::ScalarField>) -> Self::Output {
        self.mul(&rhs)
    }
}

// Add
impl<P: Pairing> Add<SpdzSharedG2Affine<P>> for SpdzSharedG2Affine<P>
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
    type Output = <Self as AffineRepr>::Group;

    fn add(self, rhs: SpdzSharedG2Affine<P>) -> Self::Output {
        match (self.value, rhs.value) {
            (SpdzSharedAffine::Public{sh:lhs_sh,mac:lhs_mac}, SpdzSharedAffine::Public{sh:rhs_sh,mac:rhs_mac}) => SpdzSharedG2 {
                value: SpdzSharedGroup::Public{sh:lhs_sh+rhs_sh, mac:lhs_mac+rhs_mac},
            },
            (SpdzSharedAffine::Shared{sh:lhs_sh,mac:lhs_mac}, SpdzSharedAffine::Public{sh:rhs_sh,mac:rhs_mac}) => {
                todo!();
            },
            (SpdzSharedAffine::Public{sh:lhs_sh,mac:lhs_mac}, SpdzSharedAffine::Shared{sh:rhs_sh,mac:rhs_mac}) => {
                todo!();
            },
            (SpdzSharedAffine::Shared{sh:lhs_sh,mac:lhs_mac}, SpdzSharedAffine::Shared{sh:rhs_sh,mac:rhs_mac}) => {
                todo!();
            }
            _ => {todo!();}
        }
    }
}

impl<'a, P: Pairing> Add<&'a SpdzSharedG2<P>> for SpdzSharedG2Affine<P>
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
    type Output = <Self as AffineRepr>::Group;

    fn add(self, rhs: &'a SpdzSharedG2<P>) -> Self::Output {
        self.add(*rhs)
    }
}

impl<P: Pairing> Add<SpdzSharedG2<P>> for SpdzSharedG2Affine<P>
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
    type Output = <Self as AffineRepr>::Group;

    fn add(self, _rhs: SpdzSharedG2<P>) -> Self::Output {
        todo!()
    }
}

impl<'a, P: Pairing> Add<&'a SpdzSharedG2Affine<P>> for SpdzSharedG2Affine<P>
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
    type Output = <Self as AffineRepr>::Group;

    fn add(self, _rhs: &'a SpdzSharedG2Affine<P>) -> Self::Output {
        todo!()
    }
}

// Neg
impl<P: Pairing> Neg for SpdzSharedG2Affine<P> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        todo!()
    }
}

impl<P: Pairing> DefaultIsZeroes for SpdzSharedG2Affine<P> {}

// Display
impl<P: Pairing> Display for SpdzSharedG2Affine<P> {
    fn fmt(&self, _f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

// Serialize
impl<P: Pairing> Valid for SpdzSharedG2Affine<P> {
    fn check(&self) -> Result<(), SerializationError> {
        todo!()
    }
}

impl<P: Pairing> CanonicalSerialize for SpdzSharedG2Affine<P> {
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

impl<P: Pairing> CanonicalDeserialize for SpdzSharedG2Affine<P> {
    fn deserialize_with_mode<R: std::io::prelude::Read>(
        _reader: R,
        _compress: ark_serialize::Compress,
        _validate: ark_serialize::Validate,
    ) -> Result<Self, SerializationError> {
        todo!()
    }
}

// Standard
impl<P: Pairing> Distribution<SpdzSharedG2Affine<P>> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> SpdzSharedG2Affine<P> {
        let g2a = P::G2Affine::rand(rng);
        SpdzSharedG2Affine {
            value: SpdzSharedAffine::new(g2a),
        }
    }
}
