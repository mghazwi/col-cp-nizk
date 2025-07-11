use std::{
    fmt::{Debug, Display},
    iter::Sum,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use std::str::FromStr;

use ark_ec::{AffineRepr, Group, CurveConfig, CurveGroup,};
use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField};
use ark_serialize::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags, Valid,
};
use ark_std::Zero;
use derivative::Derivative;
// use futures::executor::block_on;
use num_bigint::BigUint;
use rand::{distributions::{Distribution, Standard}, Rng, SeedableRng};
use zeroize::DefaultIsZeroes;

use crate::{globals::get_party_id, mpc::spdz_field::SpdzSharedField};
use crate::globals::{get_n_parties, increment_n_s_s_operations};
use crate::mpc::beaver::{BeaverSource, DummyGroupTripleSource};
use crate::network::{ElementType, Net};

#[inline]
pub fn mac_share<F: Field>() -> F {
    if get_party_id() == 0 {
        F::one()
    } else {
        F::zero()
    }
}

#[inline]
pub fn mac_cheat<F: Field>() -> F {
    F::one()
}

pub trait SpdzSharedGroupTrait<G: Group>: Group {
    fn as_base(value: Self) -> G;
    fn reveal(self) -> Self;
    fn from_public(value: G) -> Self;
    fn from_shared(value: G) -> Self;
}

pub trait SpdzSharedAffineTrait<A: AffineRepr>: AffineRepr {
    type Base: AffineRepr;

    fn reveal(self) -> Self;
    fn from_public(value: A) -> Self;
    fn from_shared(value: A) -> Self;
}

pub trait SpdzSharedPreparedTrait<F>
where
    F: Default + Clone + Send + Sync + Debug + CanonicalSerialize + CanonicalDeserialize,
{
}

#[derive(Derivative)]
#[derivative(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum SpdzSharedGroup<G: Group> {
    Public { sh:G , mac: G},
    Shared { sh:G , mac: G},
}

impl<G: Group> SpdzSharedGroup<G> {
    pub fn new(value: G) -> Self {
        Self::Public{sh: value, mac: value*mac_share::<G::ScalarField>()}
    }

    pub fn get_share_group_val(self) -> G {
        match self{
            Self::Public{sh, mac} => sh,
            Self::Shared{sh, mac} => sh
        }
    }
}

impl<G: Group> SpdzSharedGroupTrait<G> for SpdzSharedGroup<G>
    where
        SpdzSharedField<G::ScalarField>:
        From<<G::ScalarField as PrimeField>::BigInt>,
        <G::ScalarField as PrimeField>::BigInt:
        From<SpdzSharedField<G::ScalarField>>,
        BigUint: From<SpdzSharedField<G::ScalarField>>,

        <G::ScalarField as FromStr>::Err: Debug,
{
    fn as_base(_value: Self) -> G {
        todo!()
    }

    fn reveal(self) -> SpdzSharedGroup<G> {
        match self {
            SpdzSharedGroup::Public { sh,mac } => self,
            SpdzSharedGroup::Shared{sh,mac} => {
                let element_type = if sh.compressed_size() == 96 {
                    ElementType::G2
                } else {
                    ElementType::G1
                };
                let shares: Vec<G> =
                    Net::exchange_elements::<G>(sh, element_type);

                let sum = shares
                    .iter()
                    .fold(G::zero(), |acc, x| (acc + x).into());

                let dx_t: G = sum * mac_share::<G::ScalarField>() - mac;

                let all_dx_ts = Net::exchange_elements(dx_t, element_type);

                let all_dx_ts_sum: G = all_dx_ts.iter().sum();

                assert!(all_dx_ts_sum.is_zero());

                SpdzSharedGroup::from_public(sum)
            }
        }
    }

    fn from_public(value: G) -> Self {
        SpdzSharedGroup::Public{sh:value, mac: (value*mac_share::<G::ScalarField>()).into()}
    }

    fn from_shared(value: G) -> Self {
        SpdzSharedGroup::Shared{sh:value, mac: (value*mac_cheat::<G::ScalarField>()).into()}
    }

}

impl<G: Group> Group for SpdzSharedGroup<G>
where
    SpdzSharedField<G::ScalarField>:
        From<<G::ScalarField as PrimeField>::BigInt>,
        <G::ScalarField as PrimeField>::BigInt:
        From<SpdzSharedField<G::ScalarField>>,
        BigUint: From<SpdzSharedField<G::ScalarField>>,

        <G::ScalarField as FromStr>::Err: Debug,
{
    type ScalarField = SpdzSharedField<G::ScalarField>;

    fn generator() -> Self {
        SpdzSharedGroup::Public {sh:G::generator(), mac:G::generator()*mac_share::<G::ScalarField>()}
    }

    fn double_in_place(&mut self) -> &mut Self {
        let new_value = match &self {
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

        *self = new_value;

        self
    }

    fn mul_bigint(&self, _other: impl AsRef<[u64]>) -> Self {
        todo!();
    }
}

impl<G: Group> Default for SpdzSharedGroup<G> {
    fn default() -> Self {
        Self::Public{sh:G::default(),mac: G::default()*mac_share::<G::ScalarField>()}
    }
}

// Neg
impl<G: Group> Neg for SpdzSharedGroup<G> {
    type Output = SpdzSharedGroup<G>;

    fn neg(self) -> Self::Output {
        match self {
            Self::Public{sh, mac} => Self::Public{sh:-sh, mac:-mac},
            Self::Shared{sh,mac} => {
                Self::Public{sh:-sh, mac:-mac}
            }
        }
    }
}

// Zero
impl<G: Group> Zero for SpdzSharedGroup<G> {
    fn zero() -> Self {
        SpdzSharedGroup::Public {sh:G::zero(), mac:G::zero()}
    }

    fn is_zero(&self) -> bool {
        match self {
            SpdzSharedGroup::Public{sh, mac} => sh.is_zero(),
            SpdzSharedGroup::Shared{sh,mac} => {
                sh.is_zero()
            }
        }
    }
}

impl<G: Group> DefaultIsZeroes for SpdzSharedGroup<G> {}

// Display
impl<G: Group> Display for SpdzSharedGroup<G> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public{sh,mac} => write!(f, "sh = {}, mac= {}", sh, mac),
            Self::Shared{sh,mac} => write!(f, "sh = {}, mac= {}", sh, mac),
        }
    }
}

// Mul
impl<G: Group> Mul<SpdzSharedField<G::ScalarField>> for SpdzSharedGroup<G> {
    type Output = SpdzSharedGroup<G>;

    fn mul(self, rhs: SpdzSharedField<G::ScalarField>) -> Self::Output {
        todo!()
    }
}

impl<'a, G: Group> Mul<&'a G> for SpdzSharedGroup<G> {
    type Output = SpdzSharedGroup<G>;

    fn mul(self, rhs: &'a G) -> Self::Output {
        todo!()
    }
}

impl<'a, G: Group> Mul<&'a SpdzSharedField<G::ScalarField>> for SpdzSharedGroup<G> {
    type Output = SpdzSharedGroup<G>;

    fn mul(self, rhs: &'a SpdzSharedField<G::ScalarField>) -> Self::Output {
        match self {
            SpdzSharedGroup::Public { sh: lhs_sh, mac: lhs_mac } => match rhs {
                SpdzSharedField::Public { sh: rhs_sh, mac: rhs_mac } =>
                    {
                        let sh = lhs_sh.mul(rhs_sh);
                        let mac = lhs_mac.mul(rhs_mac);
                        let mac_ch: G = (sh*mac_cheat::<G::ScalarField>()).into();
                        SpdzSharedGroup::Public { sh, mac:mac_ch }
                    },
                SpdzSharedField::Shared { sh: rhs_sh, mac: rhs_mac } => {
                    todo!();
                }
            },
            SpdzSharedGroup::Shared { sh: lhs_sh, mac: lhs_mac } => match rhs {
                SpdzSharedField::Public { sh: rhs_sh, mac: rhs_mac } => {
                    let sh = lhs_sh.mul(rhs_sh);
                    let mac = lhs_mac.mul(rhs_mac);
                    let mac_ch: G = (sh*mac_cheat::<G::ScalarField>()).into();
                    SpdzSharedGroup::Shared { sh, mac:mac_ch }
                },
                SpdzSharedField::Shared { sh: rhs_sh, mac: rhs_mac } => {
                    todo!();
                }
            }
        }
    }
}

// MulAssign
impl<'a, G: Group> MulAssign<&'a G> for SpdzSharedGroup<G> {
    fn mul_assign(&mut self, _rhs: &'a G) {
        todo!()
    }
}

// cannot multiply-assign `SharedGroup<G>` by `mpc::field::SharedField<<G as Group>::ScalarField>`
impl<G: Group> MulAssign<SpdzSharedField<G::ScalarField>> for SpdzSharedGroup<G> {
    fn mul_assign(&mut self, _rhs: SpdzSharedField<G::ScalarField>) {
        todo!()
    }
}

impl<'a, G: Group> MulAssign<&'a SpdzSharedField<G::ScalarField>> for SpdzSharedGroup<G> {
    fn mul_assign(&mut self, _rhs: &'a SpdzSharedField<G::ScalarField>) {
        todo!()
    }
}

// Sub
impl<G: Group> Sub<SpdzSharedGroup<G>> for SpdzSharedGroup<G> {
    type Output = SpdzSharedGroup<G>;

    fn sub(self, rhs: SpdzSharedGroup<G>) -> Self::Output {
        self.sub(&rhs)
    }
}

impl<'a, G: Group> Sub<&'a SpdzSharedGroup<G>> for SpdzSharedGroup<G> {
    type Output = SpdzSharedGroup<G>;

    fn sub(self, rhs: &'a SpdzSharedGroup<G>) -> Self::Output {
        match self {
            Self::Public{sh:lhs,mac:lmac} => match rhs {
                Self::Public{sh:rhs, mac:rmac} => Self::Public{sh:lhs-rhs, mac:lmac-rmac},
                Self::Shared{sh:rhs, mac:rmac} => {
                    let am_first_party = get_party_id() == 0;

                    if am_first_party {
                        Self::Shared{sh:lhs - rhs, mac: lmac-rmac}
                    }
                    else {
                        // let mac = lmac - rmac;
                        Self::Shared{sh:-rhs.clone(), mac:-rmac.clone()}
                    }
                    // else {
                    //     let mac = lmac - rmac;
                    //     Self::
                    // Shared{sh:rhs.clone(), mac}
                    // }
                }
            },
            Self::Shared{sh:lhs,mac:lmac} => match rhs {
                Self::Public{sh:rhs, mac:rmac} => {
                    let am_first_party = get_party_id() == 0;

                    if am_first_party {
                        Self::Shared{sh:lhs - rhs, mac: lmac-rmac}
                    }
                    else {
                        // let mac = lmac - rmac;
                        Self::Shared{sh:lhs, mac:lmac}
                    }
                    // else {
                    //     let mac = lmac - rmac;
                    //     Self::Shared{sh:lhs, mac}
                    // }
                }
                Self::Shared{sh:rhs, mac:rmac} => Self::Shared{sh:lhs - rhs, mac: lmac-rmac},
            },
        }
    }
}

// SubAssign
impl<'a, G: Group> SubAssign<&'a SpdzSharedGroup<G>> for SpdzSharedGroup<G> {
    fn sub_assign(&mut self, rhs: &'a SpdzSharedGroup<G>) {
        // match self {
        //     Self::Public{sh:lhs_sh,mac:lhs_mac} => match rhs {
        //         Self::Public{sh:rhs_sh, mac:rhs_mac} => {
        //             lhs_sh.sub_assign(rhs_sh);
        //             lhs_mac.sub_assign(rhs_mac);
        //         },
        //         Self::Shared{sh:rhs_sh, mac:rhs_mac} => {
        //             let am_first_party = get_party_id() == 0;
        //             if am_first_party {
        //                 let new_sh = lhs_sh.sub(rhs_sh);
        //                 let new_mac = lhs_mac.sub(rhs_mac);
        //                 *self = SpdzSharedGroup::Shared { sh:new_sh,mac:new_mac };
        //             } else {
        //                 *self = rhs.clone();
        //             }
        //         }
        //     },
        //     Self::Shared{sh:lhs_sh,mac:lhs_mac} => match rhs {
        //         Self::Public{sh:rhs_sh, mac:rhs_mac} => {
        //             let am_first_party = get_party_id() == 0;
        //             if am_first_party {
        //                 let new_sh = lhs_sh.sub(rhs_sh);
        //                 let new_mac = lhs_mac.sub(rhs_mac);
        //                 *self = SpdzSharedGroup::Shared{ sh:new_sh,mac:new_mac };
        //             } else {
        //                 *self = rhs.clone();
        //             }
        //         }
        //         Self::Shared{sh:rhs_sh, mac:rhs_mac} => {
        //             lhs_sh.sub_assign(rhs_sh);
        //             lhs_mac.sub_assign(rhs_mac);
        //         },
        //     },
        // }
        *self = *self - rhs;
    }
}

impl<G: Group> SubAssign<SpdzSharedGroup<G>> for SpdzSharedGroup<G> {
    fn sub_assign(&mut self, rhs: SpdzSharedGroup<G>) {
        self.sub_assign(&rhs)
    }
}

// Add
impl<G: Group> Add<SpdzSharedGroup<G>> for SpdzSharedGroup<G> {
    type Output = SpdzSharedGroup<G>;

    fn add(self, rhs: SpdzSharedGroup<G>) -> Self::Output {
        self.add(&rhs)
    }
}

impl<'a, G: Group> Add<&'a SpdzSharedGroup<G>> for SpdzSharedGroup<G> {
    type Output = SpdzSharedGroup<G>;

    fn add(self, rhs: &'a SpdzSharedGroup<G>) -> Self::Output {
        match self {
            Self::Public{sh:lhs,mac:lmac} => match rhs {
                Self::Public{sh:rhs, mac:rmac} => Self::Public{sh:lhs+rhs, mac:lmac+rmac},
                Self::Shared{sh:rhs, mac:rmac} => {
                    let am_first_party = get_party_id() == 0;

                    if am_first_party {
                        Self::Shared{sh:lhs + rhs, mac: lmac+rmac}
                    }else {
                        // let mac = lmac + rmac;
                        Self::Shared{sh:rhs.clone(), mac:rmac.clone()}
                    }
                    // else {
                    //     let mac = lmac + rmac;
                    //     Self::Shared{sh:rhs.clone(), mac}
                    // }
                }
            },
            Self::Shared{sh:lhs,mac:lmac} => match rhs {
                Self::Public{sh:rhs, mac:rmac} => {
                    let am_first_party = get_party_id() == 0;

                    if am_first_party {
                        Self::Shared{sh:lhs + rhs, mac: lmac+rmac}
                    } else {
                        // let mac = lmac + rmac;
                        Self::Shared{sh:lhs, mac:lmac}
                    }
                }
                Self::Shared{sh:rhs, mac:rmac} => Self::Shared{sh:lhs + rhs, mac: lmac+rmac},
            },
        }
    }
}

// AddAssign
impl<G: Group> AddAssign<SpdzSharedGroup<G>> for SpdzSharedGroup<G> {
    fn add_assign(&mut self, rhs: SpdzSharedGroup<G>) {
        // match self {
        //     Self::Public{sh:lhs_sh,mac:lhs_mac} => match rhs {
        //         Self::Public{sh:rhs_sh, mac:rhs_mac} => {
        //             lhs_sh.add_assign(rhs_sh);
        //             lhs_mac.add_assign(rhs_mac);
        //         },
        //         Self::Shared{sh:rhs_sh, mac:rhs_mac} => {
        //             let am_first_party = get_party_id() == 0;
        //             if am_first_party {
        //                 let new_sh = lhs_sh.add(rhs_sh);
        //                 let new_mac = lhs_sh.add(rhs_mac);
        //                 *self = SpdzSharedGroup::Shared{sh:new_sh,mac:new_mac};
        //             } else {
        //                 *self = rhs;
        //             }
        //         }
        //     },
        //     Self::Shared{sh:lhs_sh,mac:lhs_mac} => match rhs {
        //         Self::Public{sh:rhs_sh, mac:rhs_mac} => {
        //             let am_first_party = get_party_id() == 0;
        //             if am_first_party {
        //                 let new_sh = lhs_sh.add(rhs_sh);
        //                 let new_mac = lhs_sh.add(rhs_mac);
        //                 *self = SpdzSharedGroup::Shared{sh:new_sh,mac:new_mac};
        //             } else {
        //                 *self = rhs;
        //             }
        //         }
        //         Self::Shared{sh:rhs_sh, mac:rhs_mac} => {
        //             lhs_sh.add_assign(rhs_sh);
        //             lhs_mac.add_assign(rhs_mac);
        //         },
        //     },
        // }
        *self = *self + rhs;
    }
}

impl<'a, G: Group> AddAssign<&'a SpdzSharedField<G::ScalarField>> for SpdzSharedGroup<G> {
    fn add_assign(&mut self, rhs: &'a SpdzSharedField<G::ScalarField>) {
        todo!()
    }
}

impl<G: Group> AddAssign<SpdzSharedField<G::ScalarField>> for SpdzSharedGroup<G> {
    fn add_assign(&mut self, _rhs: SpdzSharedField<G::ScalarField>) {
        todo!()
    }
}

// cannot add-assign `&'a SharedGroup<G>` to `SharedGroup<G>`
impl<'a, G: Group> AddAssign<&'a SpdzSharedGroup<G>> for SpdzSharedGroup<G> {
    fn add_assign(&mut self, rhs: &'a SpdzSharedGroup<G>) {
        todo!()
    }
}

// Sum
impl<'a, G: Group> Sum<&'a SpdzSharedGroup<G>> for SpdzSharedGroup<G> {
    fn sum<I: Iterator<Item = &'a SpdzSharedGroup<G>>>(iter: I) -> Self {
        iter.fold(Self::zero(), core::ops::Add::add)
    }
}
impl<G: Group> Sum<SpdzSharedGroup<G>> for SpdzSharedGroup<G> {
    fn sum<I: Iterator<Item = SpdzSharedGroup<G>>>(iter: I) -> Self {
        iter.fold(Self::zero(), core::ops::Add::add)
    }
}

// Serialization
impl<G: Group> CanonicalSerialize for SpdzSharedGroup<G> {
    fn serialize_with_mode<W: std::io::prelude::Write>(
        &self,
        writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        let value = match self {
            Self::Public{sh:value, mac} => value,
            Self::Shared{sh:value, mac} => value,
        };

        value.serialize_with_mode(writer, compress)
    }

    fn serialized_size(&self, _compress: ark_serialize::Compress) -> usize {
        todo!()
    }
}

impl<G: Group> CanonicalSerializeWithFlags for SpdzSharedGroup<G> {
    fn serialize_with_flags<W: std::io::prelude::Write, Fl: ark_serialize::Flags>(
        &self,
        _writer: W,
        _flags: Fl,
    ) -> Result<(), ark_serialize::SerializationError> {
        todo!()
    }

    fn serialized_size_with_flags<Fl: ark_serialize::Flags>(&self) -> usize {
        todo!()
    }
}

impl<G: Group> CanonicalDeserializeWithFlags for SpdzSharedGroup<G> {
    fn deserialize_with_flags<R: std::io::prelude::Read, Fl: ark_serialize::Flags>(
        _reader: R,
    ) -> Result<(Self, Fl), ark_serialize::SerializationError> {
        todo!()
    }
}

impl<G: Group> CanonicalDeserialize for SpdzSharedGroup<G> {
    fn deserialize_with_mode<R: std::io::prelude::Read>(
        _reader: R,
        _compress: ark_serialize::Compress,
        _validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        todo!()
    }
}

impl<G: Group> Valid for SpdzSharedGroup<G> {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        todo!()
    }
}

// Distribution
impl<G: Group> Distribution<SpdzSharedGroup<G>> for Standard {
    fn sample<R: Rng + ?Sized>(&self, _rng: &mut R) -> SpdzSharedGroup<G> {
        todo!()
    }
}

// Affine

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum SpdzSharedAffine<G: AffineRepr> {
    Public{sh: G, mac: G},
    Shared{sh: G, mac: G},
}

impl<G: AffineRepr> SpdzSharedAffine<G> {
    pub fn new(value: G) -> Self {
        Self::Public{sh: value, mac: (value*mac_share::<G::ScalarField>()).into()}
    }

    pub fn get_share_group_val(self) -> G {
        match self{
            Self::Public{sh, mac} => sh,
            Self::Shared{sh, mac} => sh
        }
    }

    // fn reveal(self) -> self {
    //     match self {
    //         SpdzSharedAffine::Public { sh,mac } => self,
    //         SpdzSharedAffine::Shared{sh,mac} => {
    //             let shares: Vec<G> =
    //                 block_on(Network::exchange_elements::<G>(sh));
    //
    //             let sum = shares
    //                 .iter()
    //                 .fold(G::zero(), |acc, x| (acc + x).into());
    //
    //             let dx_t: G = sum * mac_share::<G::ScalarField>() - mac;
    //
    //             let all_dx_ts = block_on(Network::exchange_elements(dx_t));
    //
    //             let all_dx_ts_sum: G = all_dx_ts.iter().sum();
    //
    //             assert!(all_dx_ts_sum.is_zero());
    //
    //             SpdzSharedGroup::from_public(sum)
    //         }
    //     }
    // }
    //
    // fn from_public(value: G) -> SpdzSharedAffine<G> {
    //     SpdzSharedAffine::Public{sh:value, mac: (value*mac_share::<G::ScalarField>()).into()}
    // }
    //
    // fn from_shared(value: G) -> SpdzSharedAffine<G> {
    //     SpdzSharedAffine::Shared{sh:value, mac: (value*mac_cheat::<G::ScalarField>()).into()}
    // }
}

impl<G: AffineRepr> Default for SpdzSharedAffine<G> {
    fn default() -> Self {
        Self::Public{sh:G::default(), mac: (G::default()*mac_share::<G::ScalarField>()).into()}
    }
}

impl<G: AffineRepr> Mul<SpdzSharedField<G::ScalarField>> for SpdzSharedAffine<G> {
    type Output = SpdzSharedAffine<G>;

    fn mul(self, _rhs: SpdzSharedField<G::ScalarField>) -> Self::Output {
        todo!()
    }
}

impl<'a, G: AffineRepr> Mul<&'a G> for SpdzSharedAffine<G> {
    type Output = SpdzSharedAffine<G>;

    fn mul(self, _rhs: &'a G) -> Self::Output {
        todo!()
    }
}

impl<G: AffineRepr> Add<SpdzSharedAffine<G>> for SpdzSharedAffine<G> {
    type Output = SpdzSharedAffine<G>;

    fn add(self, _rhs: SpdzSharedAffine<G>) -> Self::Output {
        todo!();
    }
}

impl<'a, G: AffineRepr> Add<&'a SpdzSharedAffine<G>> for SpdzSharedAffine<G> {
    type Output = SpdzSharedAffine<G>;

    fn add(self, _rhs: &'a SpdzSharedAffine<G>) -> Self::Output {
        todo!();
    }
}

// Serialize
impl<G: AffineRepr> CanonicalSerialize for SpdzSharedAffine<G> {
    fn serialize_with_mode<W: std::io::prelude::Write>(
        &self,
        writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        let value = match self {
            Self::Public{sh:value, mac} => value,
            Self::Shared{sh:value, mac} => value,
        };

        value.serialize_with_mode(writer, compress)
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        let value = match self {
            Self::Public{sh:value, mac} => value,
            Self::Shared{sh:value, mac} => value,
        };

        value.serialized_size(compress)
    }
}

impl<G: AffineRepr> CanonicalDeserialize for SpdzSharedAffine<G> {
    fn deserialize_with_mode<R: std::io::prelude::Read>(
        reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let value = G::deserialize_with_mode(reader, compress, validate)?;

        Ok(Self::Public{sh:value, mac:(value*mac_share::<G::ScalarField>()).into()})
    }
}

// Valid
impl<G: AffineRepr> Valid for SpdzSharedAffine<G> {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        todo!()
    }
}
