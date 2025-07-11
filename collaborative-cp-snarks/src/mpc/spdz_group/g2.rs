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
    g2_affine::SpdzSharedG2Affine,
    group::{SpdzSharedAffine, SpdzSharedGroup, SpdzSharedGroupTrait},
};

#[derive(Derivative)]
#[derivative(Copy, Clone, PartialEq, Eq, Debug, Hash, Default)]
pub struct SpdzSharedG2<P: Pairing> {
    pub value: SpdzSharedGroup<P::G2>,
}

impl<P: Pairing> SpdzSharedGroupTrait<P::G2> for SpdzSharedG2<P>
where
    SpdzSharedField<<P as Pairing>::ScalarField>:
        From<<<P as Pairing>::ScalarField as PrimeField>::BigInt>,
    <<P as Pairing>::ScalarField as PrimeField>::BigInt:
        From<SpdzSharedField<<P as Pairing>::ScalarField>>,
    BigUint: From<SpdzSharedField<<P as Pairing>::ScalarField>>,

    <<P as Pairing>::ScalarField as FromStr>::Err: Debug,
{
    fn as_base(_value: Self) -> P::G2 {
        todo!()
    }

    fn reveal(self) -> SpdzSharedG2<P> {
        SpdzSharedG2{
            value: self.value.reveal()
        }
    }

    fn from_public(value: P::G2) -> Self {
        SpdzSharedG2 {
            value: SpdzSharedGroup::from_public(value),
        }
    }

    fn from_shared(value: P::G2) -> Self {
        SpdzSharedG2 {
            value: SpdzSharedGroup::from_shared(value),
        }
    }
}

impl<P: Pairing> From<SpdzSharedG2Affine<P>> for SpdzSharedG2<P> {
    fn from(value: SpdzSharedG2Affine<P>) -> Self {
        let g2 = match value.value {
            SpdzSharedAffine::Public{sh,mac} => SpdzSharedGroup::Public {sh: P::G2::from(sh), mac: P::G2::from(mac)},
            SpdzSharedAffine::Shared{sh,mac} => SpdzSharedGroup::Shared {sh: P::G2::from(sh), mac: P::G2::from(mac)},
        };
        SpdzSharedG2 {
            value: g2,
        }
    }
}

impl<P: Pairing> Group for SpdzSharedG2<P>
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
        SpdzSharedG2::from_public(P::G2::generator())
    }

    fn double_in_place(&mut self) -> &mut Self {
        let new_value = match &self.value {
            SpdzSharedGroup::Public{sh:g2_value, mac:g2_mac} => {
                let mut g2 = g2_value.clone();
                let mut mac = g2_mac.clone();
                g2.double_in_place();
                mac.double_in_place();
                SpdzSharedGroup::Public{sh:g2, mac}
            }
            SpdzSharedGroup::Shared{sh:g2_value, mac:g2_mac} => {
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
impl<P: Pairing> Add<SpdzSharedG2<P>> for SpdzSharedG2<P> {
    type Output = Self;

    fn add(self, rhs: SpdzSharedG2<P>) -> Self::Output {
        self.add(&rhs)
    }
}

impl<'a, P: Pairing> Add<&'a SpdzSharedG2<P>> for SpdzSharedG2<P> {
    type Output = Self;

    fn add(self, rhs: &'a SpdzSharedG2<P>) -> Self::Output {
        let value = self.value.add(rhs.value);
        SpdzSharedG2 { value }
    }
}

impl<'a, P: Pairing> AddAssign<&'a SpdzSharedG2<P>> for SpdzSharedG2<P> {
    fn add_assign(&mut self, rhs: &'a SpdzSharedG2<P>) {
        let new_value = self.value.add(rhs.value);
        *self = SpdzSharedG2 {value: new_value,};
    }
}

impl<P: Pairing> AddAssign<SpdzSharedG2<P>> for SpdzSharedG2<P> {
    fn add_assign(&mut self, rhs: SpdzSharedG2<P>) {
        self.add_assign(&rhs)
    }
}

impl<'a, P: Pairing> AddAssign<&'a SpdzSharedG2Affine<P>> for SpdzSharedG2<P> {
    fn add_assign(&mut self, rhs: &'a SpdzSharedG2Affine<P>) {
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

impl<P: Pairing> AddAssign<SpdzSharedG2Affine<P>> for SpdzSharedG2<P> {
    fn add_assign(&mut self, rhs: SpdzSharedG2Affine<P>) {
        self.add_assign(&rhs)
    }
}

impl<P: Pairing> Add<SpdzSharedG2Affine<P>> for SpdzSharedG2<P> {
    type Output = Self;

    fn add(self, rhs: SpdzSharedG2Affine<P>) -> Self::Output {
        self.add(&rhs)
    }
}

impl<'a, P: Pairing> Add<&'a SpdzSharedG2Affine<P>> for SpdzSharedG2<P> {
    type Output = Self;

    fn add(self, rhs: &'a SpdzSharedG2Affine<P>) -> Self::Output {
        let mut new_value = self.clone();
        new_value.add_assign(rhs);
        new_value
    }
}

// Sub
impl<'a, P: Pairing> Sub<&'a SpdzSharedG2<P>> for SpdzSharedG2<P> {
    type Output = Self;

    fn sub(self, rhs: &'a SpdzSharedG2<P>) -> Self::Output {
        let new_value = self.value.sub(rhs.value);
        SpdzSharedG2 { value:new_value }
    }
}

impl<P: Pairing> Sub<SpdzSharedG2<P>> for SpdzSharedG2<P> {
    type Output = Self;

    fn sub(self, rhs: SpdzSharedG2<P>) -> Self::Output {
        self.sub(&rhs)
    }
}

impl<'a, P: Pairing> SubAssign<&'a SpdzSharedG2<P>> for SpdzSharedG2<P> {
    fn sub_assign(&mut self, rhs: &'a SpdzSharedG2<P>) {
        let new_value = self.value.sub(rhs.value);
        *self = SpdzSharedG2 {value: new_value,};
    }
}

impl<P: Pairing> SubAssign<SpdzSharedG2<P>> for SpdzSharedG2<P> {
    fn sub_assign(&mut self, rhs: SpdzSharedG2<P>) {
        self.sub_assign(&rhs)
    }
}

impl<'a, P: Pairing> SubAssign<&'a SpdzSharedG2Affine<P>> for SpdzSharedG2<P> {
    fn sub_assign(&mut self, rhs: &'a SpdzSharedG2Affine<P>) {
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

impl<P: Pairing> SubAssign<SpdzSharedG2Affine<P>> for SpdzSharedG2<P> {
    fn sub_assign(&mut self, rhs: SpdzSharedG2Affine<P>) {
        self.sub_assign(&rhs)
    }
}

impl<'a, P: Pairing> Sub<&'a SpdzSharedG2Affine<P>> for SpdzSharedG2<P> {
    type Output = Self;

    fn sub(self, rhs: &'a SpdzSharedG2Affine<P>) -> Self::Output {
        let mut new_value = self.clone();
        new_value.sub_assign(rhs);
        new_value
    }
}

impl<P: Pairing> Sub<SpdzSharedG2Affine<P>> for SpdzSharedG2<P> {
    type Output = Self;

    fn sub(self, rhs: SpdzSharedG2Affine<P>) -> Self::Output {
        self.sub(&rhs)
    }
}

// Mul
impl<'a, P: Pairing> Mul<&'a SpdzSharedField<P::ScalarField>> for SpdzSharedG2<P> {
    type Output = Self;

    fn mul(self, rhs: &'a SpdzSharedField<P::ScalarField>) -> Self::Output {
        // match (&self.value, &rhs) {
        //     (SpdzSharedGroup::Public{sh:lhs_sh, mac:lhs_mac}, SpdzSharedField::Public{sh: rhs_sh,mac:rhs_mac}) => {
        //         let sh = lhs_sh.mul(rhs_sh);
        //         let mac = lhs_mac.mul(rhs_mac);
        //         SpdzSharedG2 {
        //             value: SpdzSharedGroup::Public{sh,mac},
        //         }
        //     }
        //     (SpdzSharedGroup::Public{sh:lhs_sh, mac:lhs_mac}, SpdzSharedField::Shared{sh: rhs_sh,mac:rhs_mac}) => {
        //         todo!();
        //     }
        //     (SpdzSharedGroup::Shared{sh:lhs_sh, mac:lhs_mac}, SpdzSharedField::Public{sh: rhs_sh,mac:rhs_mac}) => {
        //         let sh = lhs_sh.mul(rhs_sh);
        //         let mac = lhs_mac.mul(rhs_mac);
        //         SpdzSharedG2 {
        //             value: SpdzSharedGroup::Shared{sh,mac},
        //         }
        //     }
        //     (SpdzSharedGroup::Shared{sh:lhs_sh, mac:lhs_mac}, SpdzSharedField::Shared{sh: rhs_sh,mac:rhs_mac}) => {
        //         todo!();
        //     }
        // }
        SpdzSharedG2 {
            value: self.value*rhs,
        }
    }
}

impl<'a, P: Pairing> MulAssign<&'a SpdzSharedField<P::ScalarField>> for SpdzSharedG2<P> {
    fn mul_assign(&mut self, rhs: &'a SpdzSharedField<P::ScalarField>) {
        *self = self.mul(rhs)
    }
}

impl<P: Pairing> MulAssign<SpdzSharedField<P::ScalarField>> for SpdzSharedG2<P> {
    fn mul_assign(&mut self, rhs: SpdzSharedField<P::ScalarField>) {
        *self = self.mul(rhs)
    }
}

impl<P: Pairing> Mul<SpdzSharedField<P::ScalarField>> for SpdzSharedG2<P> {
    type Output = Self;

    fn mul(self, rhs: SpdzSharedField<P::ScalarField>) -> Self::Output {
        self.mul(&rhs)
    }
}

// Div
impl<'a, P: Pairing> Div<&'a SpdzSharedField<P::ScalarField>> for SpdzSharedG2<P> {
    type Output = Self;

    fn div(self, _rhs: &'a SpdzSharedField<P::ScalarField>) -> Self::Output {
        todo!()
    }
}

// Sum
impl<'a, P: Pairing> Sum<&'a SpdzSharedG2<P>> for SpdzSharedG2<P> {
    fn sum<I: Iterator<Item = &'a SpdzSharedG2<P>>>(_iter: I) -> Self {
        todo!()
    }
}

impl<P: Pairing> Sum<SpdzSharedG2<P>> for SpdzSharedG2<P> {
    fn sum<I: Iterator<Item = SpdzSharedG2<P>>>(_iter: I) -> Self {
        todo!()
    }
}

impl<'a, P: Pairing> Sum<&'a SpdzSharedG2Affine<P>> for SpdzSharedG2<P> {
    fn sum<I: Iterator<Item = &'a SpdzSharedG2Affine<P>>>(_iter: I) -> Self {
        todo!()
    }
}

impl<P: Pairing> Sum<SpdzSharedG2Affine<P>> for SpdzSharedG2<P> {
    fn sum<I: Iterator<Item = SpdzSharedG2Affine<P>>>(_iter: I) -> Self {
        todo!()
    }
}

// Neg
impl<P: Pairing> Neg for SpdzSharedG2<P> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        // TODO: Can we do this?
        Self { value: -self.value }
    }
}

// Zero
impl<P: Pairing> Zero for SpdzSharedG2<P> {
    fn zero() -> Self {
        let g2 = P::G2::zero();
        SpdzSharedG2 {
            value: SpdzSharedGroup::new(g2),
        }
    }

    fn is_zero(&self) -> bool {
        todo!()
    }
}

impl<P: Pairing> DefaultIsZeroes for SpdzSharedG2<P> {}

// Display
impl<P: Pairing> Display for SpdzSharedG2<P> {
    fn fmt(&self, _f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

// Serialize
impl<P: Pairing> Valid for SpdzSharedG2<P> {
    fn check(&self) -> Result<(), SerializationError> {
        todo!()
    }
}

impl<P: Pairing> CanonicalSerialize for SpdzSharedG2<P> {
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

impl<P: Pairing> CanonicalDeserialize for SpdzSharedG2<P> {
    fn deserialize_with_mode<R: std::io::prelude::Read>(
        _reader: R,
        _compress: ark_serialize::Compress,
        _validate: ark_serialize::Validate,
    ) -> Result<Self, SerializationError> {
        todo!()
    }
}

// Standard
impl<P: Pairing> Distribution<SpdzSharedG2<P>> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> SpdzSharedG2<P> {
        let g2 = P::G2::rand(rng);
        SpdzSharedG2 {
            value: SpdzSharedGroup::new(g2),
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
        <<<P as Pairing>::G2 as CurveGroup>::Config as CurveConfig>::COFACTOR;

    const COFACTOR_INV: Self::ScalarField =
        SpdzSharedField::new(<<<P as Pairing>::G2 as CurveGroup>::Config as CurveConfig>::COFACTOR_INV);
}

// CurveGroup
impl<P: Pairing> CurveGroup for SpdzSharedG2<P>
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
    type Affine = SpdzSharedG2Affine<P>;
    type FullGroup = SpdzSharedG2Affine<P>;

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
impl<P: Pairing> ScalarMul for SpdzSharedG2<P>
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
    type MulBase = SpdzSharedG2Affine<P>;

    const NEGATION_IS_CHEAP: bool = true;

    fn batch_convert_to_mul_base(bases: &[Self]) -> Vec<Self::MulBase> {
        Self::normalize_batch(bases)
    }
}

impl<P: Pairing> VariableBaseMSM for SpdzSharedG2<P>
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
