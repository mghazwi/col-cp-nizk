use std::{
    fmt::{Debug, Display, Formatter},
    ops::{Add, Mul, Neg},
    str::FromStr,
};
use std::time::Instant;

use ark_ec::CurveGroup;
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
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
    g1::{Config, SpdzSharedG1},
    group::{SpdzSharedAffine, SpdzSharedAffineTrait, SpdzSharedGroup},
};

#[derive(CanonicalDeserialize, CanonicalSerialize, Derivative)]
#[derivative(Copy, Clone, PartialEq, Eq, Debug, Hash, Default)]
pub struct SpdzSharedG1Affine<P: Pairing> {
    pub value: SpdzSharedAffine<P::G1Affine>,
}

impl<P:Pairing> SpdzSharedG1Affine<P>{
    pub fn new(value: P::G1Affine) -> Self {
        SpdzSharedG1Affine{value:SpdzSharedAffine::new(value)}
    }

    pub fn get_share_group_val(self) -> P::G1Affine {
        self.value.get_share_group_val()
    }
}

impl<P: Pairing> From<SpdzSharedG1<P>> for SpdzSharedG1Affine<P> {
    fn from(value: SpdzSharedG1<P>) -> Self {
        match value.value {
            SpdzSharedGroup::Public{sh,mac} => SpdzSharedG1Affine {
                value: SpdzSharedAffine::Public{sh:sh.into_affine(), mac:mac.into_affine()},
            },
            SpdzSharedGroup::Shared{sh,mac} => SpdzSharedG1Affine {
                value: SpdzSharedAffine::Shared{sh:sh.into_affine(), mac:mac.into_affine()},
            },
        }
    }
}

impl<P: Pairing> SpdzSharedAffineTrait<P::G1Affine> for SpdzSharedG1Affine<P>
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
    type Base = P::G1Affine;

    fn reveal(self) -> SpdzSharedG1Affine<P> {
        match self.value {
            SpdzSharedAffine::Public { sh,mac } => self,
            SpdzSharedAffine::Shared{sh,mac} => {
                // let t = Instant::now();
                let shares: Vec<<P as Pairing>::G1Affine> =
                    Net::exchange_elements::<P::G1Affine>(sh, ElementType::G1);

                let sum = shares
                    .iter()
                    .fold(P::G1Affine::zero(), |acc, x| (acc + x).into());

                let dx_t: <P as Pairing>::G1Affine = (sum * mac_share::<P::ScalarField>() - mac).into();

                let all_dx_ts = Net::exchange_elements(dx_t, ElementType::G1);

                let all_dx_ts_sum: <P as Pairing>::G1 = all_dx_ts.iter().sum();
                let all_dx_ts_sum_aff: <P as Pairing>::G1Affine = all_dx_ts_sum.into();

                assert_eq!(all_dx_ts_sum_aff, P::G1Affine::zero());
                // let d = t.elapsed();
                // println!("reveal time: {:?}",d);
                SpdzSharedG1Affine::from_public(sum)
            }
        }
    }

    fn from_public(value: P::G1Affine) -> SpdzSharedG1Affine<P> {
        SpdzSharedG1Affine {
            value: SpdzSharedAffine::Public{sh:value, mac: (value*mac_share::<P::ScalarField>()).into()},
        }
    }

    fn from_shared(value: P::G1Affine) -> SpdzSharedG1Affine<P> {
        SpdzSharedG1Affine {
            value: SpdzSharedAffine::Shared{sh:value, mac: (value*mac_cheat::<P::ScalarField>()).into()},
        }
    }
}

// AffineRepr
impl<P: Pairing> AffineRepr for SpdzSharedG1Affine<P>
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

    type Group = SpdzSharedG1<P>;

    fn xy(&self) -> Option<(&Self::BaseField, &Self::BaseField)> {
        todo!()
    }

    fn zero() -> Self {
        SpdzSharedG1Affine {
            value: SpdzSharedAffine::Public {sh: P::G1Affine::zero(), mac: P::G1Affine::zero() }
        }
    }

    fn generator() -> Self {
        return SpdzSharedG1Affine {
            value: SpdzSharedAffine::Public{sh:P::G1Affine::generator(),mac:(P::G1Affine::generator()*mac_share::<P::ScalarField>()).into()},
        };
    }

    fn from_random_bytes(_bytes: &[u8]) -> Option<Self> {
        todo!()
    }

    fn mul_bigint(&self, by: impl AsRef<[u64]>) -> Self::Group {
        let (sh,mac) = match self.value {
            SpdzSharedAffine::Public { sh, mac } => (sh.mul_bigint(by), mac),
            SpdzSharedAffine::Shared { sh, mac } => {
                todo!();
            }
        };
        SpdzSharedG1 {
            value: SpdzSharedGroup::Public{sh, mac:mac.into()}
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
impl<'a, P: Pairing> Mul<&'a SpdzSharedField<<P as Pairing>::ScalarField>> for SpdzSharedG1Affine<P>
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
            (SpdzSharedAffine::Public{sh:lhs_sh,mac:lhs_mac}, SpdzSharedField::Public{sh:rhs_sh,mac:rhs_mac}) => SpdzSharedG1 {
                value: SpdzSharedGroup::Public{sh:lhs_sh.mul(rhs_sh), mac:lhs_mac.mul(rhs_mac)},
            },
            (SpdzSharedAffine::Shared{sh:lhs_sh,mac:lhs_mac}, SpdzSharedField::Public{sh:rhs_sh,mac:rhs_mac}) => {
                let sh = lhs_sh.mul(rhs_sh);
                SpdzSharedG1::from_shared(sh)
            },
            (SpdzSharedAffine::Public{sh:lhs_sh,mac:lhs_mac}, SpdzSharedField::Shared{sh:rhs_sh,mac:rhs_mac}) =>
                {
                    let sh = lhs_sh.mul(rhs_sh);
                    SpdzSharedG1::from_shared(sh)
                }
            (SpdzSharedAffine::Shared{sh:lhs_sh,mac:lhs_mac}, SpdzSharedField::Shared{sh:rhs_sh,mac:rhs_mac}) => {
                todo!();
            }
        }
    }
}

impl<P: Pairing> Mul<SpdzSharedField<<P as Pairing>::ScalarField>> for SpdzSharedG1Affine<P>
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
impl<P: Pairing> Add<SpdzSharedG1Affine<P>> for SpdzSharedG1Affine<P>
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

    fn add(self, rhs: SpdzSharedG1Affine<P>) -> Self::Output {
        self.into_group().add(rhs.into_group())
        // match (self.value, rhs.value) {
        //     (SpdzSharedAffine::Public{sh:lhs_sh,mac:lhs_mac}, SpdzSharedAffine::Public{sh:rhs_sh,mac:rhs_mac}) => SpdzSharedG1 {
        //         value: SpdzSharedGroup::Public{sh:lhs_sh+rhs_sh, mac:lhs_mac+rhs_mac},
        //     },
        //     (SpdzSharedAffine::Shared{sh:lhs_sh,mac:lhs_mac}, SpdzSharedAffine::Public{sh:rhs_sh,mac:rhs_mac}) => {
        //         todo!();
        //     },
        //     (SpdzSharedAffine::Public{sh:lhs_sh,mac:lhs_mac}, SpdzSharedAffine::Shared{sh:rhs_sh,mac:rhs_mac}) => {
        //         todo!();
        //     },
        //     (SpdzSharedAffine::Shared{sh:lhs_sh,mac:lhs_mac}, SpdzSharedAffine::Shared{sh:rhs_sh,mac:rhs_mac}) => {
        //         todo!();
        //     }
        //     _ => {todo!();}
        // }
    }
}

impl<'a, P: Pairing> Add<&'a SpdzSharedG1<P>> for SpdzSharedG1Affine<P>
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

    fn add(self, rhs: &'a SpdzSharedG1<P>) -> Self::Output {
        self.add(*rhs)
    }
}

impl<P: Pairing> Add<SpdzSharedG1<P>> for SpdzSharedG1Affine<P>
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

    fn add(self, rhs: SpdzSharedG1<P>) -> Self::Output {
        self.into_group().add(rhs)
    }
}

impl<'a, P: Pairing> Add<&'a SpdzSharedG1Affine<P>> for SpdzSharedG1Affine<P>
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

    fn add(self, rhs: &'a SpdzSharedG1Affine<P>) -> Self::Output {
        self.add(*rhs)
    }
}

// Neg
impl<P: Pairing> Neg for SpdzSharedG1Affine<P> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        todo!()
    }
}

impl<P: Pairing> DefaultIsZeroes for SpdzSharedG1Affine<P> {}

// Display
impl<P: Pairing> Display for SpdzSharedG1Affine<P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.value.fmt(f)
    }
}

// Standard
impl<P: Pairing> Distribution<SpdzSharedG1Affine<P>> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> SpdzSharedG1Affine<P> {
        let g1a = P::G1Affine::rand(rng);
        SpdzSharedG1Affine {
            value: SpdzSharedAffine::new(g1a),
        }
    }
}

// FromStr
impl<P: Pairing> FromStr for SpdzSharedG1Affine<P> {
    type Err = String;

    fn from_str(_s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}
