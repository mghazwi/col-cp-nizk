use crate::globals::{get_party_id, increment_n_s_s_operations};
use crate::network::{ElementType, Net};
use ark_bls12_381::{FqConfig, FrConfig};
use ark_ff::{BigInt, FftField, Field, Fp, MontBackend, PrimeField};
use ark_ff::{LegendreSymbol, SqrtPrecomputation};
use ark_serialize::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags, Valid,
};
use ark_std::{One, Zero};
use derivative::Derivative;
use futures::executor::block_on;
use num_bigint::BigUint;
use rand::distributions::{Distribution, Standard};
use std::fmt::Debug;
use std::{
    fmt::{Display, Formatter},
    iter::{Product, Sum},
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
    str::FromStr,
};
use zeroize::Zeroize;
use crate::mpc::beaver::{BeaverSource, DummyFieldTripleSource, DummySpdzFieldTripleSource};

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

#[derive(Derivative)]
#[derivative(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum SpdzSharedField<F: Field> {
    Public{sh: F, mac: F},
    Shared{sh: F, mac: F},
}

pub trait SpdzSharedFieldTrait<F: Field>: PrimeField {
    fn from_public(value: F) -> Self;
    fn from_shared(value: F) -> Self;

    fn is_public(self) -> bool;
    fn is_shared(self) -> bool;

    fn reveal(self) -> Self;
}

impl<F: Field> SpdzSharedField<F> {
    //TODO: fix this
    pub const fn new(value: F) -> Self {
        Self::Public{sh:value, mac:value}
    }

    pub fn get_share_field_val(self) -> F {
        match self{
            Self::Public{sh, mac} => sh,
            Self::Shared{sh, mac} => sh
        }
    }
}

impl<F> SpdzSharedFieldTrait<F> for SpdzSharedField<F>
where
    F: PrimeField,

    <F as PrimeField>::BigInt: From<SpdzSharedField<F>>,
    BigUint: From<SpdzSharedField<F>>,
    SpdzSharedField<F>: From<<F as PrimeField>::BigInt>,

    <F as FromStr>::Err: Debug,
{
    fn from_public(value: F) -> Self {
        Self::Public{
            sh:value,
            mac:value*mac_share::<F>()
        }
    }

    fn from_shared(value: F) -> SpdzSharedField<F> {
        Self::Shared{sh:value, mac:value*mac_cheat::<F>()}
    }

    fn is_public(self) -> bool {
        match self {
            SpdzSharedField::Public{sh,mac} => true,
            SpdzSharedField::Shared{sh,mac} => false,
        }
    }
    fn is_shared(self) -> bool {
        match self {
            SpdzSharedField::Public{sh,mac} => false,
            SpdzSharedField::Shared{sh,mac} => true,
        }
    }

    fn reveal(self) -> Self {
        match self {
            SpdzSharedField::Public{sh,mac} => self,
            SpdzSharedField::Shared{sh,mac} => {
                let shares = Net::exchange_elements(sh, ElementType::Field);

                let sum: F = shares.iter().sum();
                // if get_party_id() != 0 { assert_eq!(F::zero(), mac); }

                let dx_t: F = mac_share::<F>() * sum - mac;

                let all_dx_ts = Net::exchange_elements(dx_t, ElementType::Field);

                let all_dx_ts_sum: F = all_dx_ts.iter().sum();

                // assert_eq!(all_dx_ts_sum, F::zero());

                SpdzSharedField::from_public(sum)
            }
        }
    }
}

// impl<F: Field> SpdzSharedField<F>
// {
//     //TODO: check this reveal again
//     fn reveal(self) -> Self {
//         match self {
//             SpdzSharedField::Public{sh,mac} => self,
//             SpdzSharedField::Shared{sh,mac} => {
//                 let shares = block_on(Network::exchange_elements(sh));
//
//                 let sum: F = shares.iter().sum();
//
//                 SpdzSharedField::Public{sh:sum,mac}
//             }
//         }
//     }
// }

impl<F: Field> Default for SpdzSharedField<F> {
    fn default() -> Self {
        Self::new(F::default())
    }
}

impl<F: PrimeField> Field for SpdzSharedField<F>
where
    SpdzSharedField<F>: From<<F as PrimeField>::BigInt>,
    <F as PrimeField>::BigInt: From<SpdzSharedField<F>>,
    BigUint: From<SpdzSharedField<F>>,

    <F as FromStr>::Err: Debug,
{
    type BasePrimeField = SpdzSharedField<F>;
    type BasePrimeFieldIter = std::iter::Empty<Self::BasePrimeField>;

    const SQRT_PRECOMP: Option<SqrtPrecomputation<Self>> = Self::SQRT_PRECOMP;
    const ZERO: Self = Self::ZERO;
    const ONE: Self = Self::ONE;

    fn extension_degree() -> u64 {
        todo!()
    }

    fn to_base_prime_field_elements(&self) -> Self::BasePrimeFieldIter {
        todo!()
    }

    fn from_base_prime_field_elems(_: &[Self::BasePrimeField]) -> Option<Self> {
        todo!()
    }

    fn from_base_prime_field(_: Self::BasePrimeField) -> Self {
        todo!()
    }

    fn double(&self) -> Self {
        todo!()
    }

    fn double_in_place(&mut self) -> &mut Self {
        todo!()
    }

    fn neg_in_place(&mut self) -> &mut Self {
        todo!()
    }

    fn from_random_bytes_with_flags<Fl: ark_serialize::Flags>(bytes: &[u8]) -> Option<(Self, Fl)> {
        let (v,f) = F::from_random_bytes_with_flags(bytes).unwrap();
        Some((Self::from_public(v), f))
    }

    fn legendre(&self) -> LegendreSymbol {
        todo!()
    }

    fn square(&self) -> Self {
        todo!()
    }

    //TODO: check this
    fn square_in_place(&mut self) -> &mut Self {
        match self {
            SpdzSharedField::Public{sh,mac} => {
                let sh = sh.square();
                let mac = mac.square();
                *self = SpdzSharedField::Public{sh,mac};

                self
            }
            SpdzSharedField::Shared{sh,mac} => {
                todo!();
            }
        }
    }

    //TODO: check this
    fn inverse(&self) -> Option<Self> {
        match self {
            SpdzSharedField::Public{sh,mac} => {
                let sh = sh.inverse();
                let mac_inv = mac.inverse();
                if sh.is_some() {
                    let sh = sh.unwrap();
                    // let mac = mac_inv.unwrap();
                    Some(SpdzSharedField::Public{sh,mac:mac.clone()})
                } else {
                    None
                }
            }
            SpdzSharedField::Shared{sh,mac} => {
                todo!();
            }
        }
    }

    fn inverse_in_place(&mut self) -> Option<&mut Self> {
        todo!()
    }

    fn frobenius_map_in_place(&mut self, _power: usize) {
        todo!()
    }
}

impl<F: PrimeField> FftField for SpdzSharedField<F>
where
    SpdzSharedField<F>: From<<F as PrimeField>::BigInt>,
    <F as PrimeField>::BigInt: From<SpdzSharedField<F>>,
    BigUint: From<SpdzSharedField<F>>,

    <F as FromStr>::Err: Debug,
{
    const GENERATOR: Self = Self::new(F::GENERATOR);
    const TWO_ADICITY: u32 = F::TWO_ADICITY;
    const TWO_ADIC_ROOT_OF_UNITY: Self = Self::new(F::TWO_ADIC_ROOT_OF_UNITY);
}

impl<F: PrimeField> PrimeField for SpdzSharedField<F>
where
    SpdzSharedField<F>: From<<F as PrimeField>::BigInt>,
    <F as PrimeField>::BigInt: From<SpdzSharedField<F>>,
    BigUint: From<SpdzSharedField<F>>,

    <F as FromStr>::Err: Debug,
{
    type BigInt = F::BigInt;

    const MODULUS: Self::BigInt = F::MODULUS;
    const MODULUS_MINUS_ONE_DIV_TWO: Self::BigInt = F::MODULUS_MINUS_ONE_DIV_TWO;
    const MODULUS_BIT_SIZE: u32 = F::MODULUS_BIT_SIZE;
    const TRACE: Self::BigInt = F::TRACE;
    const TRACE_MINUS_ONE_DIV_TWO: Self::BigInt = F::TRACE_MINUS_ONE_DIV_TWO;

    fn from_bigint(_repr: Self::BigInt) -> Option<Self> {
        todo!()
    }

    fn into_bigint(self) -> Self::BigInt {
        match self {
            SpdzSharedField::Public{sh,mac} => sh.into(),
            SpdzSharedField::Shared{sh,mac} => {
                // sh.into()
                panic!("Turning a shared value into a BigInt is not supported")
            }
        }
    }
}

// Display
impl<F: PrimeField> Display for SpdzSharedField<F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let (value, mac) = match self {
            SpdzSharedField::Public{sh,mac} => (sh,mac),
            SpdzSharedField::Shared{sh,mac} => (sh,mac),
        };

        write!(f, "sh = {}, mac = {}", value, mac)
    }
}

// DefaultIsZeroes
impl<F: PrimeField> Zeroize for SpdzSharedField<F> {
    fn zeroize(&mut self) {
        todo!()
    }
}

// Divide
impl<F: PrimeField> Div<SpdzSharedField<F>> for SpdzSharedField<F> {
    type Output = Self;

    fn div(self, _rhs: Self) -> Self::Output {
        todo!()
    }
}

impl<'a, F: PrimeField> Div<&'a mut SpdzSharedField<F>> for SpdzSharedField<F> {
    type Output = Self;

    fn div(self, _rhs: &'a mut Self) -> Self::Output {
        todo!()
    }
}

//TODO: check this
impl<'a, F: PrimeField> Div<&'a SpdzSharedField<F>> for SpdzSharedField<F> {
    type Output = Self;

    fn div(self, rhs: &'a SpdzSharedField<F>) -> Self::Output {
        let result = match (self, rhs) {
            (SpdzSharedField::Public{sh:lhs,mac:lmac}, SpdzSharedField::Public{sh:rhs, mac:rmac}) => {
                let sh = lhs / rhs;
                let mac = lmac/rmac;
                SpdzSharedField::Public{sh, mac}
            }
            (SpdzSharedField::Public{sh:_lhs, mac:_lmac}, SpdzSharedField::Shared{sh:_rhs, mac:_rmac}) => {
                todo!();
            }
            (SpdzSharedField::Shared{sh:_lhs, mac:_lmac}, SpdzSharedField::Public{sh:_rhs, mac:_rmac}) => {
                todo!();
            }
            (SpdzSharedField::Shared{sh:_lhs, mac:_lmac}, SpdzSharedField::Shared{sh:_rhs, mac:_rmac}) => {
                todo!();
            }
        };

        result
    }
}

// DivAssign
impl<F: PrimeField> DivAssign<SpdzSharedField<F>> for SpdzSharedField<F>
where
    <F as FromStr>::Err: Debug,
    <F as PrimeField>::BigInt: From<SpdzSharedField<F>>,
    BigUint: From<SpdzSharedField<F>>,
    SpdzSharedField<F>: From<<F as PrimeField>::BigInt>,
{
    fn div_assign(&mut self, _rhs: Self) {
        todo!();
    }
}

impl<'a, F: PrimeField> DivAssign<&'a mut SpdzSharedField<F>> for SpdzSharedField<F> {
    fn div_assign(&mut self, _rhs: &'a mut Self) {
        todo!()
    }
}

impl<'a, F: PrimeField> DivAssign<&'a SpdzSharedField<F>> for SpdzSharedField<F>
where
    <F as FromStr>::Err: Debug,
    <F as PrimeField>::BigInt: From<SpdzSharedField<F>>,
    BigUint: From<SpdzSharedField<F>>,
    SpdzSharedField<F>: From<<F as PrimeField>::BigInt>,
{
    fn div_assign(&mut self, _rhs: &'a SpdzSharedField<F>) {
        todo!();
    }
}

// Mul
impl<F: PrimeField> Mul<SpdzSharedField<F>> for SpdzSharedField<F>
where
    <F as FromStr>::Err: Debug,

    <F as PrimeField>::BigInt: From<SpdzSharedField<F>>,
    BigUint: From<SpdzSharedField<F>>,
    SpdzSharedField<F>: From<<F as PrimeField>::BigInt>,
{
    type Output = Self;

    fn mul(mut self, rhs: SpdzSharedField<F>) -> Self::Output {
        // let result = match (self, rhs) {
        //     (SpdzSharedField::Public{sh:lhs, mac:lmac}, SpdzSharedField::Public{sh:rhs, mac:rmac}) => {
        //         let sh = lhs * rhs;
        //         let mac = lmac * rmac;
        //         SpdzSharedField::Public{sh, mac}
        //     }
        //     (SpdzSharedField::Public{sh:lhs, mac:lmac}, SpdzSharedField::Shared{sh:rhs, mac:rmac}) => {
        //         let sh = lhs * rhs;
        //         let mac = lmac * rmac;
        //         SpdzSharedField::Shared{sh, mac}
        //     }
        //     (SpdzSharedField::Shared{sh:lhs, mac:lmac}, SpdzSharedField::Public{sh:rhs, mac:rmac}) => {
        //         // Each party multiplies the public value with the shared value
        //         let sh = lhs * rhs;
        //         let mac = lmac * rmac;
        //         SpdzSharedField::Shared{sh, mac}
        //     }
        //     (SpdzSharedField::Shared{sh:lhs, mac:lmac}, SpdzSharedField::Shared{sh:rhs, mac:rmac}) => {
        //         increment_n_s_s_operations();
        //             let mut dummy = DummySpdzFieldTripleSource::<F,Self>::default();
        //             let ( x, y, z) = dummy.triple();
        //         // let ( x, y, z) = (Self::one(), Self::one(), Self::one());
        //
        //         let s = self;
        //             let o = rhs;
        //
        //             let sx = {
        //                 (s - x).reveal()
        //             };
        //             let oy = {
        //                 (o - y).reveal()
        //             };
        //
        //             let mut result = sx * oy;
        //             result += (x * oy);
        //             result += (y * sx);
        //             result += z;
        //
        //             result
        //     }
        // };
        //
        // result

        self.mul(&rhs)

        // let mut val = self.clone();
        // let mut val2 = rhs.clone();
        // val.mul_assign(rhs);
        // val
        // self *= rhs;
        // self
        // todo!()
    }
}

impl<'a, F: PrimeField> Mul<&'a mut SpdzSharedField<F>> for SpdzSharedField<F> {
    type Output = Self;

    fn mul(self, _rhs: &'a mut Self) -> Self::Output {
        todo!()
    }
}

impl<'a, F: PrimeField> Mul<&'a SpdzSharedField<F>> for SpdzSharedField<F>
where
    <F as FromStr>::Err: Debug,

    <F as PrimeField>::BigInt: From<SpdzSharedField<F>>,
    BigUint: From<SpdzSharedField<F>>,
    SpdzSharedField<F>: From<<F as PrimeField>::BigInt>,
{
    type Output = Self;

    fn mul(self, rhs: &'a SpdzSharedField<F>) -> Self::Output {
        let result = match (self, rhs) {
            (SpdzSharedField::Public{sh:lhs_sh, mac:lhs_mac}, SpdzSharedField::Public{sh:rhs_sh, mac:rhs_mac}) => {
                let sh = lhs_sh * rhs_sh;
                let mac = lhs_mac * rhs_mac;
                SpdzSharedField::Public{sh, mac}
            }
            (SpdzSharedField::Public{sh:lhs_sh, mac:lhs_mac}, SpdzSharedField::Shared{sh:rhs_sh, mac:rhs_mac}) => {
                let sh = lhs_sh * rhs_sh;
                SpdzSharedField::from_shared(sh)
            }
            (SpdzSharedField::Shared{sh:lhs_sh, mac:lhs_mac}, SpdzSharedField::Public{sh:rhs_sh, mac:rhs_mac}) => {
                // Each party multiplies the public value with the shared value
                let sh = lhs_sh * rhs_sh;
                SpdzSharedField::from_shared(sh)
            }
            (SpdzSharedField::Shared{sh:lhs_sh, mac:lhs_mac}, SpdzSharedField::Shared{sh:rhs_sh, mac:rhs_mac}) => {
                increment_n_s_s_operations();
                let mut dummy = DummySpdzFieldTripleSource::<F,Self>::default();
                let ( x, y, z) = dummy.triple();

                let s = self;
                let o = *rhs;

                let sx = {
                    (s - x).reveal()
                };
                let oy = {
                    (o - y).reveal()
                };
                let mut result = sx * oy;
                result += (x * oy);
                result += (y * sx);
                result += z;

                result
            }
        };

        result
    }
}

// MulAssign
impl<F: PrimeField> MulAssign<SpdzSharedField<F>> for SpdzSharedField<F>
where
    <F as FromStr>::Err: Debug,
    <F as PrimeField>::BigInt: From<SpdzSharedField<F>>,
    BigUint: From<SpdzSharedField<F>>,
    SpdzSharedField<F>: From<<F as PrimeField>::BigInt>,
{
    fn mul_assign(&mut self, rhs: Self) {
        // let result = match self {
        //     SpdzSharedField::Public{sh,mac} => match rhs {
        //         SpdzSharedField::Public{sh,mac} => {
        //             let value = *self * rhs;
        //             *self = value;
        //         }
        //         SpdzSharedField::Shared{sh,mac} => {
        //             todo!();
        //         }
        //     },
        //     SpdzSharedField::Shared{sh,mac} => match rhs {
        //         SpdzSharedField::Public{sh,mac} => {
        //             let value = *self * rhs;
        //             *self = value;
        //         }
        //         SpdzSharedField::Shared{sh,mac} => {
        //             todo!();
        //         }
        //     },
        // };
        //
        // result
        self.mul_assign(&rhs);
    }
}

impl<'a, F: PrimeField> MulAssign<&'a mut SpdzSharedField<F>> for SpdzSharedField<F> where
    <F as FromStr>::Err: Debug,
    <F as PrimeField>::BigInt: From<SpdzSharedField<F>>,
    BigUint: From<SpdzSharedField<F>>,
    SpdzSharedField<F>: From<<F as PrimeField>::BigInt>,
{

    fn mul_assign(&mut self, _rhs: &'a mut Self) {
        todo!()
    }
}

impl<'a, F: PrimeField> MulAssign<&'a SpdzSharedField<F>> for SpdzSharedField<F>
where
    <F as FromStr>::Err: Debug,
    <F as PrimeField>::BigInt: From<SpdzSharedField<F>>,
    BigUint: From<SpdzSharedField<F>>,
    SpdzSharedField<F>: From<<F as PrimeField>::BigInt>,
{
    fn mul_assign(&mut self, rhs: &'a SpdzSharedField<F>) {
        // let result = match self {
        //     SpdzSharedField::Public{sh,mac} => match rhs {
        //         SpdzSharedField::Public{sh,mac} => {
        //             let value = *self * rhs;
        //             *self = value;
        //         }
        //         SpdzSharedField::Shared{sh,mac} => {
        //             let value = *self * rhs;
        //             *self = value;
        //         }
        //     },
        //     SpdzSharedField::Shared{sh,mac} => match rhs {
        //         SpdzSharedField::Public{sh,mac} => {
        //             let value = *self * rhs;
        //             *self = value;
        //         }
        //         SpdzSharedField::Shared{sh,mac} => {
        //             increment_n_s_s_operations();
        //             let mut dummy = DummySpdzFieldTripleSource::<F,Self>::default();
        //             let ( x, y, z) = dummy.triple();
        //
        //             let s = self;
        //             let o = rhs;
        //
        //             let sx = {
        //                 (*s - x).reveal()
        //             };
        //             let oy = {
        //                 (*o - y).reveal()
        //             };
        //
        //             let mut result = sx * oy;
        //             result += (x * oy);
        //             result += (y * sx);
        //             result += z;
        //
        //             *s = result;
        //         }
        //     },
        // };
        //
        // result
        let new_val = *self * rhs;
        *self = new_val;
    }
}

// Sub
// TODO: check this
impl<F: PrimeField> Sub<SpdzSharedField<F>> for SpdzSharedField<F> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.sub(&rhs)
    }
}

impl<'a, F: PrimeField> Sub<&'a mut SpdzSharedField<F>> for SpdzSharedField<F> {
    type Output = Self;

    fn sub(self, _rhs: &'a mut Self) -> Self::Output {
        todo!()
    }
}

impl<'a, F: PrimeField> Sub<&'a SpdzSharedField<F>> for SpdzSharedField<F> {
    type Output = Self;

    fn sub(self, rhs: &'a SpdzSharedField<F>) -> Self::Output {
        let result = match (self, rhs) {
            (SpdzSharedField::Public{sh:lhs, mac:lmac}, SpdzSharedField::Public{sh:rhs, mac:rmac}) => {
                let sh = lhs - rhs;
                let mac = lmac - rmac;
                SpdzSharedField::Public{sh, mac}
            }
            (SpdzSharedField::Public{sh:lhs_sh, mac:lhs_mac}, SpdzSharedField::Shared{sh:rhs_sh, mac:rhs_mac}) => {
                // let rhs_neg = rhs.neg();
                // self.add(rhs_neg)
                if get_party_id() == 0 {
                    let sh = lhs_sh - rhs_sh;
                    let mac = lhs_mac - rhs_mac;
                    SpdzSharedField::Shared{sh, mac}
                }else {
                    // let mac = lmac - rmac;
                    SpdzSharedField::Shared{sh:-rhs_sh.clone(), mac:-rhs_mac.clone()}
                }
            }
            (SpdzSharedField::Shared{sh:lhs, mac:lmac}, SpdzSharedField::Public{sh:rhs, mac:rmac}) => {
                if get_party_id() == 0 {
                    let sh = lhs - rhs;
                    let mac = lmac - rmac;
                    SpdzSharedField::Shared{sh, mac}
                }else {
                    // let mac = lmac - rmac;
                    SpdzSharedField::Shared{sh:lhs, mac:lmac}
                }

                // else {
                //     let mac = lmac - rmac;
                //     SpdzSharedField::Shared{sh:lhs, mac}
                // }
            }
            (SpdzSharedField::Shared{sh:lhs, mac:lmac}, SpdzSharedField::Shared{sh:rhs, mac:rmac}) => {
                let sh = lhs - rhs;
                let mac = lmac - rmac;
                SpdzSharedField::Shared { sh, mac }
            }
        };

        result
    }
}

// SubAssign
impl<F: PrimeField> SubAssign<SpdzSharedField<F>> for SpdzSharedField<F>
where
    <F as FromStr>::Err: Debug,
    <F as PrimeField>::BigInt: From<SpdzSharedField<F>>,
    BigUint: From<SpdzSharedField<F>>,
    SpdzSharedField<F>: From<<F as PrimeField>::BigInt>,
{
    fn sub_assign(&mut self, rhs: Self) {
        self.sub_assign(&rhs)
    }
}

impl<'a, F: PrimeField> SubAssign<&'a mut SpdzSharedField<F>> for SpdzSharedField<F> {
    fn sub_assign(&mut self, rhs: &'a mut Self) {
        todo!()
    }
}

impl<'a, F: PrimeField> SubAssign<&'a SpdzSharedField<F>> for SpdzSharedField<F>
where
    <F as FromStr>::Err: Debug,
    <F as PrimeField>::BigInt: From<SpdzSharedField<F>>,
    BigUint: From<SpdzSharedField<F>>,
    SpdzSharedField<F>: From<<F as PrimeField>::BigInt>,
{
    fn sub_assign(&mut self, rhs: &'a SpdzSharedField<F>) {
        let value = *self - rhs;
        *self = value;
    }
}

// Add
impl<F: PrimeField> Add<SpdzSharedField<F>> for SpdzSharedField<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.add(&rhs)
    }
}

impl<'a, F: PrimeField> Add<&'a mut SpdzSharedField<F>> for SpdzSharedField<F> {
    type Output = Self;

    fn add(self, _rhs: &'a mut Self) -> Self::Output {
        todo!()
    }
}

impl<'a, F: PrimeField> Add<&'a SpdzSharedField<F>> for SpdzSharedField<F> {
    type Output = Self;

    fn add(self, rhs: &'a SpdzSharedField<F>) -> Self::Output {
        let result = match (self, rhs) {
            (SpdzSharedField::Public{sh:lhs, mac:lmac}, SpdzSharedField::Public{sh:rhs, mac:rmac}) => {
                let sh = lhs + rhs;
                let mac = lmac + rmac;
                SpdzSharedField::Public { sh, mac }
            }
            (SpdzSharedField::Public{sh:lhs, mac:lmac}, SpdzSharedField::Shared{sh:rhs, mac:rmac}) => {
                // If we are party 0, we add the public value to the shared value. Otherwise we return the original value
                let am_first_party = get_party_id() == 0;

                if am_first_party {
                    let sh = lhs + rhs;
                    let mac = lmac + rmac;
                    SpdzSharedField::Shared{ sh, mac }
                } else {
                    // let mac = lmac + rmac;
                    SpdzSharedField::Shared{ sh:*rhs, mac:*rmac }
                }
                // else {
                //     let mac = lmac + rmac;
                //     SpdzSharedField::Shared{ sh:*rhs, mac }
                // }
            }
            (SpdzSharedField::Shared{sh:lhs, mac:lmac}, SpdzSharedField::Public{sh:rhs, mac:rmac}) => {
                // If we are party 0, we add the public value to the shared value. Otherwise we return the original value
                let am_first_party = get_party_id() == 0;

                if am_first_party {
                    let sh = lhs + rhs;
                    let mac = lmac + rmac;
                    SpdzSharedField::Shared { sh, mac }
                }else {
                    // let mac = lmac + rmac;
                    SpdzSharedField::Shared { sh:lhs, mac:lmac }
                }
                // else {
                //     let mac = lmac + rmac;
                //     SpdzSharedField::Shared { sh:lhs, mac }
                // }
            }
            (SpdzSharedField::Shared{sh:lhs, mac:lmac}, SpdzSharedField::Shared{sh:rhs, mac:rmac}) => {
                let sh = lhs + rhs;
                let mac = lmac + rmac;
                SpdzSharedField::Shared { sh, mac }
            }
        };

        result
    }
}

// AddAssign
impl<F: PrimeField> AddAssign<SpdzSharedField<F>> for SpdzSharedField<F>
where
    <F as FromStr>::Err: Debug,
    <F as PrimeField>::BigInt: From<SpdzSharedField<F>>,
    BigUint: From<SpdzSharedField<F>>,
    SpdzSharedField<F>: From<<F as PrimeField>::BigInt>,
{
    fn add_assign(&mut self, rhs: Self) {
        self.add_assign(&rhs)
    }
}

impl<'a, F: PrimeField> AddAssign<&'a mut SpdzSharedField<F>> for SpdzSharedField<F> {
    fn add_assign(&mut self, _rhs: &'a mut Self) {
        todo!()
    }
}

impl<'a, F: PrimeField> AddAssign<&'a SpdzSharedField<F>> for SpdzSharedField<F>
where
    <F as FromStr>::Err: Debug,
    <F as PrimeField>::BigInt: From<SpdzSharedField<F>>,
    BigUint: From<SpdzSharedField<F>>,
    SpdzSharedField<F>: From<<F as PrimeField>::BigInt>,
{
    fn add_assign(&mut self, rhs: &'a SpdzSharedField<F>) {
        let value = *self + rhs;
        *self = value;
    }
}

// Neg
impl<F: PrimeField> Neg for SpdzSharedField<F> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let result = match self {
            SpdzSharedField::Public{sh,mac} => {
                let sh = sh.neg();
                let mac = mac.neg();
                SpdzSharedField::Public { sh, mac }
            }
            SpdzSharedField::Shared{sh,mac} => {
                let sh = sh.neg();
                let mac = mac.neg();
                SpdzSharedField::Shared { sh, mac }
            }
        };

        result
    }
}

// PartialOrd
impl<F: PrimeField> PartialOrd for SpdzSharedField<F> {
    fn partial_cmp(&self, _other: &Self) -> Option<std::cmp::Ordering> {
        todo!()
    }
}

// Ord
impl<F: PrimeField> Ord for SpdzSharedField<F> {
    fn cmp(&self, _other: &Self) -> std::cmp::Ordering {
        todo!()
    }
}

// One
impl<F: PrimeField> One for SpdzSharedField<F>
    where
        <F as FromStr>::Err: Debug,
        <F as PrimeField>::BigInt: From<SpdzSharedField<F>>,
        BigUint: From<SpdzSharedField<F>>,
        SpdzSharedField<F>: From<<F as PrimeField>::BigInt>,
{
    fn one() -> Self {
        SpdzSharedField::Public { sh:F::one(), mac:F::one()*mac_share::<F>() }
    }
}

// Zero
impl<F: PrimeField> Zero for SpdzSharedField<F> {
    fn zero() -> Self {
        SpdzSharedField::Public { sh:F::zero(), mac:F::zero() }
    }

    fn is_zero(&self) -> bool {
        match self {
            SpdzSharedField::Public{sh, mac} => sh.is_zero(),
            SpdzSharedField::Shared{sh,mac} => {
                todo!();
            }
        }
    }
}

impl<F: PrimeField> FromStr for SpdzSharedField<F> {
    type Err = F::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let sh = F::from_str(s)?;
        let mac = mac_share::<F>();
        Ok(SpdzSharedField::Public { sh,mac })
    }
}

impl<F: PrimeField> From<num_bigint::BigUint> for SpdzSharedField<F> {
    fn from(_val: num_bigint::BigUint) -> Self {
        todo!()
    }
}

impl<F: PrimeField> From<u8> for SpdzSharedField<F>
    where
        <F as FromStr>::Err: Debug,
        <F as PrimeField>::BigInt: From<SpdzSharedField<F>>,
        BigUint: From<SpdzSharedField<F>>,
        SpdzSharedField<F>: From<<F as PrimeField>::BigInt>,
{
    fn from(val: u8) -> Self {
        <Self as SpdzSharedFieldTrait<F>>::from_public(F::from(val))
    }
}

impl<F: PrimeField> From<u16> for SpdzSharedField<F> {
    fn from(_val: u16) -> Self {
        todo!()
    }
}

impl<F: PrimeField> From<u32> for SpdzSharedField<F> {
    fn from(_val: u32) -> Self {
        todo!()
    }
}

impl<F: PrimeField> From<u64> for SpdzSharedField<F> {
    fn from(val: u64) -> Self {
        let sh = F::from(val);
        let mac = mac_share::<F>();
        SpdzSharedField::Public { sh, mac }
    }
}

impl<F: PrimeField> From<u128> for SpdzSharedField<F> {
    fn from(_val: u128) -> Self {
        todo!()
    }
}

impl<F: PrimeField> From<bool> for SpdzSharedField<F> {
    fn from(_b: bool) -> Self {
        todo!()
    }
}

// Iter Product
impl<'a, F: Field + PrimeField> Product<&'a SpdzSharedField<F>> for SpdzSharedField<F>
    where
        <F as FromStr>::Err: Debug,
        <F as PrimeField>::BigInt: From<SpdzSharedField<F>>,
        BigUint: From<SpdzSharedField<F>>,
        SpdzSharedField<F>: From<<F as PrimeField>::BigInt>,
{
    fn product<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(Self::one(), Mul::mul)
    }
}

impl<'a, F: Field + PrimeField> Product<SpdzSharedField<F>> for SpdzSharedField<F>
    where
        <F as FromStr>::Err: Debug,
        <F as PrimeField>::BigInt: From<SpdzSharedField<F>>,
        BigUint: From<SpdzSharedField<F>>,
        SpdzSharedField<F>: From<<F as PrimeField>::BigInt>,
{
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::one(), core::ops::Mul::mul)
    }
}

// Iter Sum
impl<'a, F: Field + PrimeField> Sum<&'a SpdzSharedField<F>> for SpdzSharedField<F>
where
    <F as FromStr>::Err: Debug,
    <F as PrimeField>::BigInt: From<SpdzSharedField<F>>,
    BigUint: From<SpdzSharedField<F>>,
    SpdzSharedField<F>: From<<F as PrimeField>::BigInt>,
{
    fn sum<I: Iterator<Item = &'a SpdzSharedField<F>>>(iter: I) -> Self {
        let mut iter = iter.peekable();

        let mut is_public = true;
        let mut is_shared = true;

        for item in iter.peek() {
            if item.is_shared() {
                is_public = false;
                break;
            }
        }

        for item in iter.peek() {
            if item.is_public() {
                is_shared = false;
                break;
            }
        }

        let result = if is_public {
            let mut value = SpdzSharedField::zero();

            while let Some(item) = iter.next() {
                value += item;
            }

            value
        } else if is_shared {
            todo!();
        } else {
            panic!("Cannot sum public and shared values")
        };

        result
    }
}

impl<F: Field + PrimeField> Sum<SpdzSharedField<F>> for SpdzSharedField<F>
where
    <F as FromStr>::Err: Debug,
    <F as PrimeField>::BigInt: From<SpdzSharedField<F>>,
    BigUint: From<SpdzSharedField<F>>,
    SpdzSharedField<F>: From<<F as PrimeField>::BigInt>,
{
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let mut iter = iter.peekable();

        let mut is_public = true;
        let mut is_shared = true;

        for item in iter.peek() {
            if item.is_shared() {
                is_public = false;
                break;
            }
        }

        for item in iter.peek() {
            if item.is_public() {
                is_shared = false;
                break;
            }
        }

        let result = if is_public {
            let mut value = SpdzSharedField::zero();

            while let Some(item) = iter.next() {
                value += item;
            }

            value
        } else if is_shared {
            todo!();
        } else {
            panic!("Cannot sum public and shared values")
        };

        result
    }
}

// Serialization
// TODO: fix serialization
impl<F: Field> CanonicalSerialize for SpdzSharedField<F> {
    fn serialize_with_mode<W: std::io::prelude::Write>(
        &self,
        writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        match self {
            SpdzSharedField::Public{sh,mac} => sh.serialize_with_mode(writer, compress),
            SpdzSharedField::Shared{sh,mac} => sh.serialize_with_mode(writer, compress),
        }
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        match self {
            SpdzSharedField::Public { sh, mac } => sh.serialized_size(compress),
            SpdzSharedField::Shared { sh, mac } => sh.serialized_size(compress),
        }
    }
}

impl<F: Field> CanonicalSerializeWithFlags for SpdzSharedField<F> {
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

impl<F: Field> CanonicalDeserializeWithFlags for SpdzSharedField<F> {
    fn deserialize_with_flags<R: std::io::prelude::Read, Fl: ark_serialize::Flags>(
        _reader: R,
    ) -> Result<(Self, Fl), ark_serialize::SerializationError> {
        todo!()
    }
}

impl<F: Field> CanonicalDeserialize for SpdzSharedField<F> {
    fn deserialize_with_mode<R: std::io::prelude::Read>(
        reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let value = F::deserialize_with_mode(reader, compress, validate)?;

        Ok(SpdzSharedField::Shared { sh:value,mac:value*mac_cheat::<F>() })
    }
}

impl<F: Field> Valid for SpdzSharedField<F> {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        todo!()
    }
}

// Distribution
impl<F: Field> Distribution<SpdzSharedField<F>> for Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> SpdzSharedField<F> {
        let value = F::rand(rng);

        SpdzSharedField::Public { sh:value, mac:value*mac_share::<F>() }
    }
}
// TODO: incorrect mac
impl From<BigInt<6>> for SpdzSharedField<Fp<MontBackend<FqConfig, 6>, 6>> {
    fn from(value: BigInt<6>) -> Self {
        SpdzSharedField::Public{sh:value.into(), mac:value.into()}
    }
}
// TODO: this is incorrect
impl From<SpdzSharedField<Fp<MontBackend<FqConfig, 6>, 6>>> for BigInt<6> {
    fn from(value: SpdzSharedField<Fp<MontBackend<FqConfig, 6>, 6>>) -> Self {
        let result = value.into();
        result
    }
}

impl From<SpdzSharedField<Fp<MontBackend<FqConfig, 6>, 6>>> for BigUint {
    fn from(value: SpdzSharedField<Fp<MontBackend<FqConfig, 6>, 6>>) -> Self {
        value.into()
    }
}

impl From<BigInt<4>> for SpdzSharedField<Fp<MontBackend<FrConfig, 4>, 4>> {
    fn from(value: BigInt<4>) -> Self {

        SpdzSharedField::Public {  sh:value.into(), mac:value.into()}
    }
}

// Field specific

impl From<SpdzSharedField<Fp<MontBackend<FrConfig, 4>, 4>>> for BigUint {
    fn from(_value: SpdzSharedField<Fp<MontBackend<FrConfig, 4>, 4>>) -> Self {
        todo!()
    }
}

impl From<SpdzSharedField<Fp<MontBackend<FrConfig, 4>, 4>>> for BigInt<4> {
    fn from(_value: SpdzSharedField<Fp<MontBackend<FrConfig, 4>, 4>>) -> Self {
        todo!()
    }
}

impl From<BigInt<4>> for SpdzSharedField<SpdzSharedField<Fp<MontBackend<FrConfig, 4>, 4>>> {
    fn from(_value: BigInt<4>) -> Self {
        todo!()
    }
}

impl From<SpdzSharedField<SpdzSharedField<Fp<MontBackend<FrConfig, 4>, 4>>>> for BigInt<4> {
    fn from(_value: SpdzSharedField<SpdzSharedField<Fp<MontBackend<FrConfig, 4>, 4>>>) -> Self {
        todo!()
    }
}

impl From<Fp<MontBackend<FrConfig, 4>, 4>> for SpdzSharedField<Fp<MontBackend<FrConfig, 4>, 4>> {
    fn from(value: Fp<MontBackend<FrConfig, 4>, 4>) -> Self {
        SpdzSharedField::Public{sh:value, mac:value.clone()}
    }
}

impl From<SpdzSharedField<SpdzSharedField<Fp<MontBackend<FrConfig, 4>, 4>>>> for BigUint {
    fn from(_value: SpdzSharedField<SpdzSharedField<Fp<MontBackend<FrConfig, 4>, 4>>>) -> Self {
        todo!()
    }
}

// <P as ark_ec::pairing::Pairing>::ScalarField: From<<P as mpc::pairing::MpcPairingTrait<B>>::ScalarField>` is not satisfied
// the trait `From<<P as mpc::pairing::MpcPairingTrait<B>>::ScalarField>` is not implemented for `<P as ark_ec::pairing::Pairing>::ScalarField

impl From<SpdzSharedField<Fp<MontBackend<FrConfig, 4>, 4>>>
    for SpdzSharedField<SpdzSharedField<Fp<MontBackend<FrConfig, 4>, 4>>>
{
    fn from(_value: SpdzSharedField<Fp<MontBackend<FrConfig, 4>, 4>>) -> Self {
        todo!()
    }
}
