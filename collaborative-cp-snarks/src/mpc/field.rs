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
use crate::mpc::beaver::{BeaverSource,DummyFieldTripleSource};

#[derive(Derivative)]
#[derivative(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum SharedField<F: Field> {
    Public(F),
    Shared(F),
}

pub trait SharedFieldTrait<F: Field>: PrimeField {
    fn from_public(value: F) -> Self;
    fn from_shared(value: F) -> Self;

    fn is_public(self) -> bool;
    fn is_shared(self) -> bool;

    fn reveal(self) -> Self;
}

impl<F: Field> SharedField<F> {
    pub const fn new(value: F) -> Self {
        Self::Public(value)
    }
}

impl<F> SharedFieldTrait<F> for SharedField<F>
where
    F: PrimeField,

    <F as PrimeField>::BigInt: From<SharedField<F>>,
    BigUint: From<SharedField<F>>,
    SharedField<F>: From<<F as PrimeField>::BigInt>,

    <F as FromStr>::Err: Debug,
{
    fn from_public(value: F) -> Self {
        Self::Public(value)
    }

    fn from_shared(value: F) -> SharedField<F> {
        Self::Shared(value)
    }

    fn is_public(self) -> bool {
        match self {
            SharedField::Public(_) => true,
            SharedField::Shared(_) => false,
        }
    }
    fn is_shared(self) -> bool {
        match self {
            SharedField::Public(_) => false,
            SharedField::Shared(_) => true,
        }
    }

    fn reveal(self) -> Self {
        match self {
            SharedField::Public(_) => self,
            SharedField::Shared(value) => {
                let shares = Net::exchange_elements(value, ElementType::Field);

                let sum: F = shares.iter().sum();

                SharedField::Public(sum)
            }
        }
    }
}

impl<F: Field> Default for SharedField<F> {
    fn default() -> Self {
        Self::Public(F::default())
    }
}

impl<F: PrimeField> Field for SharedField<F>
where
    SharedField<F>: From<<F as PrimeField>::BigInt>,
    <F as PrimeField>::BigInt: From<SharedField<F>>,
    BigUint: From<SharedField<F>>,

    <F as FromStr>::Err: Debug,
{
    type BasePrimeField = SharedField<F>;
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

    fn from_random_bytes_with_flags<Fl: ark_serialize::Flags>(_: &[u8]) -> Option<(Self, Fl)> {
        todo!()
    }

    fn legendre(&self) -> LegendreSymbol {
        todo!()
    }

    fn square(&self) -> Self {
        todo!()
    }

    fn square_in_place(&mut self) -> &mut Self {
        match self {
            SharedField::Public(value) => {
                let value = value.square();
                *self = SharedField::Public(value);

                self
            }
            SharedField::Shared(_value) => {
                todo!();
            }
        }
    }

    fn inverse(&self) -> Option<Self> {
        match self {
            SharedField::Public(value) => {
                let value = value.inverse();
                if value.is_some() {
                    let value = value.unwrap();
                    Some(SharedField::Public(value))
                } else {
                    None
                }
            }
            SharedField::Shared(_value) => {
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

impl<F: PrimeField> FftField for SharedField<F>
where
    SharedField<F>: From<<F as PrimeField>::BigInt>,
    <F as PrimeField>::BigInt: From<SharedField<F>>,
    BigUint: From<SharedField<F>>,

    <F as FromStr>::Err: Debug,
{
    const GENERATOR: Self = Self::new(F::GENERATOR);
    const TWO_ADICITY: u32 = F::TWO_ADICITY;
    const TWO_ADIC_ROOT_OF_UNITY: Self = Self::new(F::TWO_ADIC_ROOT_OF_UNITY);
}

impl<F: PrimeField> PrimeField for SharedField<F>
where
    SharedField<F>: From<<F as PrimeField>::BigInt>,
    <F as PrimeField>::BigInt: From<SharedField<F>>,
    BigUint: From<SharedField<F>>,

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
            SharedField::Public(value) => value.into(),
            SharedField::Shared(_value) => {
                panic!("Turning a shared value into a BigInt is not supported")
            }
        }
    }
}

// Display
impl<F: PrimeField> Display for SharedField<F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            SharedField::Public(value) => value,
            SharedField::Shared(value) => value,
        };

        write!(f, "{}", value)
    }
}

// DefaultIsZeroes
impl<F: PrimeField> Zeroize for SharedField<F> {
    fn zeroize(&mut self) {
        todo!()
    }
}

// Divide
impl<F: PrimeField> Div<SharedField<F>> for SharedField<F> {
    type Output = Self;

    fn div(self, _rhs: Self) -> Self::Output {
        todo!()
    }
}

impl<'a, F: PrimeField> Div<&'a mut SharedField<F>> for SharedField<F> {
    type Output = Self;

    fn div(self, _rhs: &'a mut Self) -> Self::Output {
        todo!()
    }
}

impl<'a, F: PrimeField> Div<&'a SharedField<F>> for SharedField<F> {
    type Output = Self;

    fn div(self, rhs: &'a SharedField<F>) -> Self::Output {
        let result = match (self, rhs) {
            (SharedField::Public(lhs), SharedField::Public(rhs)) => {
                let value = lhs / rhs;
                SharedField::Public(value)
            }
            (SharedField::Public(_lhs), SharedField::Shared(_rhs)) => {
                todo!();
            }
            (SharedField::Shared(_lhs), SharedField::Public(_rhs)) => {
                todo!();
            }
            (SharedField::Shared(_lhs), SharedField::Shared(_rhs)) => {
                todo!();
            }
        };

        result
    }
}

// DivAssign
impl<F: PrimeField> DivAssign<SharedField<F>> for SharedField<F>
where
    <F as FromStr>::Err: Debug,
    <F as PrimeField>::BigInt: From<SharedField<F>>,
    BigUint: From<SharedField<F>>,
    SharedField<F>: From<<F as PrimeField>::BigInt>,
{
    fn div_assign(&mut self, _rhs: Self) {
        todo!();
    }
}

impl<'a, F: PrimeField> DivAssign<&'a mut SharedField<F>> for SharedField<F> {
    fn div_assign(&mut self, _rhs: &'a mut Self) {
        todo!()
    }
}

impl<'a, F: PrimeField> DivAssign<&'a SharedField<F>> for SharedField<F>
where
    <F as FromStr>::Err: Debug,
    <F as PrimeField>::BigInt: From<SharedField<F>>,
    BigUint: From<SharedField<F>>,
    SharedField<F>: From<<F as PrimeField>::BigInt>,
{
    fn div_assign(&mut self, _rhs: &'a SharedField<F>) {
        todo!();
    }
}

// Mul
impl<F: PrimeField> Mul<SharedField<F>> for SharedField<F> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let result = match (self, rhs) {
            (SharedField::Public(lhs), SharedField::Public(rhs)) => {
                let value = lhs * rhs;
                SharedField::Public(value)
            }
            (SharedField::Public(_lhs), SharedField::Shared(_rhs)) => {
                todo!();
            }
            (SharedField::Shared(lhs), SharedField::Public(rhs)) => {
                // Each party multiplies the public value with the shared value
                let value = lhs * rhs;
                SharedField::Shared(value)
            }
            (SharedField::Shared(_lhs), SharedField::Shared(_rhs)) => {
                todo!();
            }
        };

        result
    }
}

impl<'a, F: PrimeField> Mul<&'a mut SharedField<F>> for SharedField<F> {
    type Output = Self;

    fn mul(self, _rhs: &'a mut Self) -> Self::Output {
        todo!()
    }
}

impl<'a, F: PrimeField> Mul<&'a SharedField<F>> for SharedField<F>
where
    <F as FromStr>::Err: Debug,

    <F as PrimeField>::BigInt: From<SharedField<F>>,
    BigUint: From<SharedField<F>>,
    SharedField<F>: From<<F as PrimeField>::BigInt>,
{
    type Output = Self;

    fn mul(self, rhs: &'a SharedField<F>) -> Self::Output {
        let result = match (self, rhs) {
            (SharedField::Public(lhs), SharedField::Public(rhs)) => {
                let value = lhs * rhs;
                SharedField::Public(value)
            }
            (SharedField::Public(lhs), SharedField::Shared(rhs)) => {
                let value = lhs * rhs;
                SharedField::Shared(value)
            }
            (SharedField::Shared(lhs), SharedField::Public(rhs)) => {
                let value = lhs * rhs;
                SharedField::Shared(value)
            }
            (SharedField::Shared(_lhs), SharedField::Shared(_rhs)) => {
                todo!();
            }
        };

        result
    }
}

// MulAssign
impl<F: PrimeField> MulAssign<SharedField<F>> for SharedField<F>
where
    <F as FromStr>::Err: Debug,
    <F as PrimeField>::BigInt: From<SharedField<F>>,
    BigUint: From<SharedField<F>>,
    SharedField<F>: From<<F as PrimeField>::BigInt>,
{
    fn mul_assign(&mut self, rhs: Self) {
        let result = match self {
            SharedField::Public(_) => match rhs {
                SharedField::Public(_) => {
                    let value = *self * rhs;
                    *self = value;
                }
                SharedField::Shared(_) => {
                    todo!();
                }
            },
            SharedField::Shared(_) => match rhs {
                SharedField::Public(_) => {
                    let value = *self * rhs;
                    *self = value;
                }
                SharedField::Shared(_) => {
                    todo!();
                }
            },
        };

        result
    }
}

impl<'a, F: PrimeField> MulAssign<&'a mut SharedField<F>> for SharedField<F> {
    fn mul_assign(&mut self, _rhs: &'a mut Self) {
        todo!()
    }
}

impl<'a, F: PrimeField> MulAssign<&'a SharedField<F>> for SharedField<F>
where
    <F as FromStr>::Err: Debug,
    <F as PrimeField>::BigInt: From<SharedField<F>>,
    BigUint: From<SharedField<F>>,
    SharedField<F>: From<<F as PrimeField>::BigInt>,
{
    fn mul_assign(&mut self, rhs: &'a SharedField<F>) {
        let result = match self {
            SharedField::Public(_) => match rhs {
                SharedField::Public(_) => {
                    let value = *self * rhs;
                    *self = value;
                }
                SharedField::Shared(_) => {
                    todo!();
                }
            },
            SharedField::Shared(_) => match rhs {
                SharedField::Public(_) => {
                    let value = *self * rhs;
                    *self = value;
                }
                SharedField::Shared(_) => {
                    increment_n_s_s_operations();
                    let mut dummy = DummyFieldTripleSource::<F,Self>::default();
                    let ( x, y, z) = dummy.triple();
                    //
                    let s = self.clone();
                    let o = rhs;

                    let sx = {
                        (s - x).reveal()
                    };
                    // let sx = SharedField::one();
                    let oy = {
                        (*o - y).reveal()
                    };

                    // let oy = SharedField::one();

                    let mut result = sx * oy;
                    // result += (x * oy);
                    // result += (y * sx);
                    // result += z;
                    //
                    *self = result.clone();
                    // let revealed_lhs = self.reveal();
                    //
                    //
                    //
                    // let result = revealed_lhs * rhs;



                    // *self = result;
                }
            },
        };

        result
    }
}

// Sub
impl<F: PrimeField> Sub<SharedField<F>> for SharedField<F> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let result = match (self, rhs) {
            (SharedField::Public(lhs), SharedField::Public(rhs)) => {
                let value = lhs - rhs;
                SharedField::Public(value)
            }
            (SharedField::Public(_lhs), SharedField::Shared(_rhs)) => {
                todo!()
            }
            (SharedField::Shared(lhs), SharedField::Public(rhs)) => {
                if get_party_id() == 0 {
                    let value = lhs - rhs;
                    SharedField::Shared(value)
                } else {
                    SharedField::Shared(lhs)
                }
            }
            (SharedField::Shared(lhs), SharedField::Shared(rhs)) => {
                let value = lhs - rhs;
                SharedField::Shared(value)
            }
        };

        result
    }
}

impl<'a, F: PrimeField> Sub<&'a mut SharedField<F>> for SharedField<F> {
    type Output = Self;

    fn sub(self, _rhs: &'a mut Self) -> Self::Output {
        todo!()
    }
}

impl<'a, F: PrimeField> Sub<&'a SharedField<F>> for SharedField<F> {
    type Output = Self;

    fn sub(self, rhs: &'a SharedField<F>) -> Self::Output {
        let result = match (self, rhs) {
            (SharedField::Public(lhs), SharedField::Public(rhs)) => {
                let value = lhs - rhs;
                SharedField::Public(value)
            }
            (SharedField::Public(_lhs), SharedField::Shared(_rhs)) => {
                todo!();
            }
            (SharedField::Shared(_lhs), SharedField::Public(_rhs)) => {
                todo!();
            }
            (SharedField::Shared(lhs), SharedField::Shared(rhs)) => {
                let value = lhs - rhs;
                SharedField::Shared(value)
            }
        };

        result
    }
}

// SubAssign
impl<F: PrimeField> SubAssign<SharedField<F>> for SharedField<F>
where
    <F as FromStr>::Err: Debug,
    <F as PrimeField>::BigInt: From<SharedField<F>>,
    BigUint: From<SharedField<F>>,
    SharedField<F>: From<<F as PrimeField>::BigInt>,
{
    fn sub_assign(&mut self, rhs: Self) {
        let result = match self {
            SharedField::Public(_) => match rhs {
                SharedField::Public(_) => {
                    let value = *self - rhs;
                    *self = value;
                }
                SharedField::Shared(_) => {
                    todo!();
                }
            },
            SharedField::Shared(_) => match rhs {
                SharedField::Public(_) => {
                    if get_party_id() == 0 {
                        let value = *self - rhs;
                        *self = value;
                    }
                }
                SharedField::Shared(_) => {
                    // Each party subtracts the shares locally
                    let value = *self - rhs;
                    *self = value;
                }
            },
        };

        result
    }
}

impl<'a, F: PrimeField> SubAssign<&'a mut SharedField<F>> for SharedField<F> {
    fn sub_assign(&mut self, _rhs: &'a mut Self) {
        todo!()
    }
}

impl<'a, F: PrimeField> SubAssign<&'a SharedField<F>> for SharedField<F>
where
    <F as FromStr>::Err: Debug,
    <F as PrimeField>::BigInt: From<SharedField<F>>,
    BigUint: From<SharedField<F>>,
    SharedField<F>: From<<F as PrimeField>::BigInt>,
{
    fn sub_assign(&mut self, rhs: &'a SharedField<F>) {
        let result = match self {
            SharedField::Public(_) => match rhs {
                SharedField::Public(_) => {
                    let value = *self - rhs;
                    *self = value;
                }
                SharedField::Shared(_) => {
                    todo!();
                }
            },
            SharedField::Shared(_) => match rhs {
                SharedField::Public(_) => {
                    todo!();
                }
                SharedField::Shared(_) => {
                    let value = *self - rhs;
                    *self = value;
                }
            },
        };

        result
    }
}

// Add
impl<F: PrimeField> Add<SharedField<F>> for SharedField<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let result = match (self, rhs) {
            (SharedField::Public(lhs), SharedField::Public(rhs)) => {
                let value = lhs + rhs;
                SharedField::Public(value)
            }
            (SharedField::Public(lhs), SharedField::Shared(rhs)) => {
                // If we are party 0, we add the public value to the shared value. Otherwise we return the original value
                let am_first_party = get_party_id() == 0;

                if am_first_party {
                    let value = lhs + rhs;
                    SharedField::Shared(value)
                } else {
                    SharedField::Shared(rhs)
                }
            }
            (SharedField::Shared(lhs), SharedField::Public(rhs)) => {
                // If we are party 0, we add the public value to the shared value. Otherwise we return the original value
                let am_first_party = get_party_id() == 0;

                if am_first_party {
                    let value = lhs + rhs;
                    SharedField::Shared(value)
                } else {
                    SharedField::Shared(lhs)
                }
            }
            (SharedField::Shared(lhs), SharedField::Shared(rhs)) => {
                let value = lhs + rhs;
                SharedField::Shared(value)
            }
        };

        result
    }
}

impl<'a, F: PrimeField> Add<&'a mut SharedField<F>> for SharedField<F> {
    type Output = Self;

    fn add(self, _rhs: &'a mut Self) -> Self::Output {
        todo!()
    }
}

impl<'a, F: PrimeField> Add<&'a SharedField<F>> for SharedField<F> {
    type Output = Self;

    fn add(self, rhs: &'a SharedField<F>) -> Self::Output {
        let result = match (self, rhs) {
            (SharedField::Public(lhs), SharedField::Public(rhs)) => {
                let value = lhs + rhs;
                SharedField::Public(value)
            }
            (SharedField::Public(lhs), SharedField::Shared(rhs)) => {
                let value =
                if get_party_id() == 0 {
                    lhs + rhs
                }else{
                    *rhs
                };
                SharedField::Shared(value)
            }
            (SharedField::Shared(lhs), SharedField::Public(rhs)) => {
                let value =
                    if get_party_id() == 0 {
                        lhs + rhs
                    }else{
                        lhs
                    };
                SharedField::Shared(value)
            }
            (SharedField::Shared(lhs), SharedField::Shared(rhs)) => {
                let value = lhs + rhs;
                SharedField::Public(value)
            }
        };

        result
    }
}

// AddAssign
impl<F: PrimeField> AddAssign<SharedField<F>> for SharedField<F>
where
    <F as FromStr>::Err: Debug,
    <F as PrimeField>::BigInt: From<SharedField<F>>,
    BigUint: From<SharedField<F>>,
    SharedField<F>: From<<F as PrimeField>::BigInt>,
{
    fn add_assign(&mut self, rhs: Self) {
        let result = match self {
            SharedField::Public(_) => match rhs {
                SharedField::Public(_) => {
                    let value = *self + rhs;
                    *self = value;
                }
                SharedField::Shared(_) => {
                    let am_first_party = get_party_id() == 0;

                    if am_first_party {
                        let value = rhs + *self;

                        // assert that value is SharedField::Shared
                        assert!(value.is_shared());
                        // Change self to be SharedField::Shared
                        *self = value;
                    } else {
                        // Do nothing
                        *self = rhs;
                    }
                }
            },
            SharedField::Shared(_) => match rhs {
                SharedField::Public(_) => {
                    // If we are the first party, add the public value to the shared value. Otherwise return the original value
                    let am_first_party = get_party_id() == 0;

                    if am_first_party {
                        let value = *self + rhs;
                        *self = value;
                    }
                }
                SharedField::Shared(_) => {
                    // Each party adds the shares locally
                    let value = *self + rhs;
                    *self = value;
                }
            },
        };

        result
    }
}

impl<'a, F: PrimeField> AddAssign<&'a mut SharedField<F>> for SharedField<F> {
    fn add_assign(&mut self, _rhs: &'a mut Self) {
        todo!()
    }
}

impl<'a, F: PrimeField> AddAssign<&'a SharedField<F>> for SharedField<F>
where
    <F as FromStr>::Err: Debug,
    <F as PrimeField>::BigInt: From<SharedField<F>>,
    BigUint: From<SharedField<F>>,
    SharedField<F>: From<<F as PrimeField>::BigInt>,
{
    fn add_assign(&mut self, rhs: &'a SharedField<F>) {
        let result = match self {
            SharedField::Public(_) => match rhs {
                SharedField::Public(_) => {
                    let value = *self + rhs;
                    *self = value;
                }
                SharedField::Shared(_) => {
                    todo!();
                }
            },
            SharedField::Shared(_) => match rhs {
                SharedField::Public(_) => {
                    todo!();
                }
                SharedField::Shared(_) => {
                    todo!();
                }
            },
        };

        result
    }
}

// Neg
impl<F: PrimeField> Neg for SharedField<F> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let result = match self {
            SharedField::Public(value) => {
                let value = value.neg();
                SharedField::Public(value)
            }
            SharedField::Shared(_value) => {
                todo!();
            }
        };

        result
    }
}

// PartialOrd
impl<F: PrimeField> PartialOrd for SharedField<F> {
    fn partial_cmp(&self, _other: &Self) -> Option<std::cmp::Ordering> {
        todo!()
    }
}

// Ord
impl<F: PrimeField> Ord for SharedField<F> {
    fn cmp(&self, _other: &Self) -> std::cmp::Ordering {
        todo!()
    }
}

// One
impl<F: PrimeField> One for SharedField<F> {
    fn one() -> Self {
        SharedField::Public(F::one())
    }
}

// Zero
impl<F: PrimeField> Zero for SharedField<F> {
    fn zero() -> Self {
        SharedField::Public(F::zero())
    }

    fn is_zero(&self) -> bool {
        match self {
            SharedField::Public(value) => value.is_zero(),
            SharedField::Shared(_value) => {
                todo!();
            }
        }
    }
}

impl<F: PrimeField> FromStr for SharedField<F> {
    type Err = F::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value = F::from_str(s)?;
        Ok(SharedField::Public(value))
    }
}

impl<F: PrimeField> From<num_bigint::BigUint> for SharedField<F> {
    fn from(_val: num_bigint::BigUint) -> Self {
        todo!()
    }
}

impl<F: PrimeField> From<u8> for SharedField<F> {
    fn from(_val: u8) -> Self {
        todo!()
    }
}

impl<F: PrimeField> From<u16> for SharedField<F> {
    fn from(_val: u16) -> Self {
        todo!()
    }
}

impl<F: PrimeField> From<u32> for SharedField<F> {
    fn from(_val: u32) -> Self {
        todo!()
    }
}

impl<F: PrimeField> From<u64> for SharedField<F> {
    fn from(val: u64) -> Self {
        let value = F::from(val);
        SharedField::Public(value)
    }
}

impl<F: PrimeField> From<u128> for SharedField<F> {
    fn from(_val: u128) -> Self {
        todo!()
    }
}

impl<F: PrimeField> From<bool> for SharedField<F> {
    fn from(_b: bool) -> Self {
        todo!()
    }
}

// Iter Product
impl<'a, F: Field> Product<&'a SharedField<F>> for SharedField<F> {
    fn product<I: Iterator<Item = &'a Self>>(_iter: I) -> Self {
        todo!()
    }
}

impl<'a, F: Field> Product<SharedField<F>> for SharedField<F> {
    fn product<I: Iterator<Item = Self>>(_iter: I) -> Self {
        todo!()
    }
}

// Iter Sum
impl<'a, F: Field + PrimeField> Sum<&'a SharedField<F>> for SharedField<F>
where
    <F as FromStr>::Err: Debug,
    <F as PrimeField>::BigInt: From<SharedField<F>>,
    BigUint: From<SharedField<F>>,
    SharedField<F>: From<<F as PrimeField>::BigInt>,
{
    fn sum<I: Iterator<Item = &'a SharedField<F>>>(iter: I) -> Self {
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
            let mut value = SharedField::Public(F::zero());

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

impl<F: Field + PrimeField> Sum<SharedField<F>> for SharedField<F>
where
    <F as FromStr>::Err: Debug,
    <F as PrimeField>::BigInt: From<SharedField<F>>,
    BigUint: From<SharedField<F>>,
    SharedField<F>: From<<F as PrimeField>::BigInt>,
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
            let mut value = SharedField::Public(F::zero());

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
impl<F: Field> CanonicalSerialize for SharedField<F> {
    fn serialize_with_mode<W: std::io::prelude::Write>(
        &self,
        writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        match self {
            SharedField::Public(value) => value.serialize_with_mode(writer, compress),
            SharedField::Shared(value) => value.serialize_with_mode(writer, compress),
        }
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        match self {
            SharedField::Public(value) => value.serialized_size(compress),
            SharedField::Shared(value) => value.serialized_size(compress),
        }
    }
}

impl<F: Field> CanonicalSerializeWithFlags for SharedField<F> {
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

impl<F: Field> CanonicalDeserializeWithFlags for SharedField<F> {
    fn deserialize_with_flags<R: std::io::prelude::Read, Fl: ark_serialize::Flags>(
        _reader: R,
    ) -> Result<(Self, Fl), ark_serialize::SerializationError> {
        todo!()
    }
}

impl<F: Field> CanonicalDeserialize for SharedField<F> {
    fn deserialize_with_mode<R: std::io::prelude::Read>(
        reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let value = F::deserialize_with_mode(reader, compress, validate)?;

        Ok(SharedField::Shared(value))
    }
}

impl<F: Field> Valid for SharedField<F> {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        todo!()
    }
}

// Distribution
impl<F: Field> Distribution<SharedField<F>> for Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> SharedField<F> {
        let value = F::rand(rng);

        SharedField::Public(value)
    }
}

impl From<BigInt<6>> for SharedField<Fp<MontBackend<FqConfig, 6>, 6>> {
    fn from(value: BigInt<6>) -> Self {
        SharedField::Public(value.into())
    }
}

impl From<SharedField<Fp<MontBackend<FqConfig, 6>, 6>>> for BigInt<6> {
    fn from(value: SharedField<Fp<MontBackend<FqConfig, 6>, 6>>) -> Self {
        let result = value.into();
        result
    }
}

impl From<SharedField<Fp<MontBackend<FqConfig, 6>, 6>>> for BigUint {
    fn from(value: SharedField<Fp<MontBackend<FqConfig, 6>, 6>>) -> Self {
        value.into()
    }
}

impl From<BigInt<4>> for SharedField<Fp<MontBackend<FrConfig, 4>, 4>> {
    fn from(value: BigInt<4>) -> Self {
        SharedField::Public(value.into())
    }
}

// Field specific

impl From<SharedField<Fp<MontBackend<FrConfig, 4>, 4>>> for BigUint {
    fn from(_value: SharedField<Fp<MontBackend<FrConfig, 4>, 4>>) -> Self {
        todo!()
    }
}

impl From<SharedField<Fp<MontBackend<FrConfig, 4>, 4>>> for BigInt<4> {
    fn from(_value: SharedField<Fp<MontBackend<FrConfig, 4>, 4>>) -> Self {
        todo!()
    }
}

impl From<BigInt<4>> for SharedField<SharedField<Fp<MontBackend<FrConfig, 4>, 4>>> {
    fn from(_value: BigInt<4>) -> Self {
        todo!()
    }
}

impl From<SharedField<SharedField<Fp<MontBackend<FrConfig, 4>, 4>>>> for BigInt<4> {
    fn from(_value: SharedField<SharedField<Fp<MontBackend<FrConfig, 4>, 4>>>) -> Self {
        todo!()
    }
}

impl From<Fp<MontBackend<FrConfig, 4>, 4>> for SharedField<Fp<MontBackend<FrConfig, 4>, 4>> {
    fn from(value: Fp<MontBackend<FrConfig, 4>, 4>) -> Self {
        SharedField::Public(value)
    }
}

impl From<SharedField<SharedField<Fp<MontBackend<FrConfig, 4>, 4>>>> for BigUint {
    fn from(_value: SharedField<SharedField<Fp<MontBackend<FrConfig, 4>, 4>>>) -> Self {
        todo!()
    }
}

// <P as ark_ec::pairing::Pairing>::ScalarField: From<<P as mpc::pairing::MpcPairingTrait<B>>::ScalarField>` is not satisfied
// the trait `From<<P as mpc::pairing::MpcPairingTrait<B>>::ScalarField>` is not implemented for `<P as ark_ec::pairing::Pairing>::ScalarField

impl From<SharedField<Fp<MontBackend<FrConfig, 4>, 4>>>
    for SharedField<SharedField<Fp<MontBackend<FrConfig, 4>, 4>>>
{
    fn from(_value: SharedField<Fp<MontBackend<FrConfig, 4>, 4>>) -> Self {
        todo!()
    }
}
