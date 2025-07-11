use std::{
    fmt::{Debug, Display},
    iter::Sum,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};
use std::str::FromStr;

use ark_ec::{AffineRepr, Group, CurveConfig, CurveGroup,};
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_serialize::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags, Valid,
};
use ark_std::Zero;
use derivative::Derivative;
use num_bigint::BigUint;
use rand::{
    distributions::{Distribution, Standard},
    Rng,
};
use zeroize::DefaultIsZeroes;

use crate::{globals::get_party_id, mpc::field::SharedField};
use crate::globals::increment_n_s_s_operations;
use crate::mpc::beaver::{BeaverSource, DummyGroupTripleSource};

pub trait SharedGroupTrait<G: Group>: Group {
    fn as_base(value: Self) -> G;
    fn reveal(self) -> Self;
}

pub trait SharedAffineTrait<A: AffineRepr>: AffineRepr {
    type Base: AffineRepr;

    fn reveal(self) -> Self;
    fn from_public(value: A) -> Self;
    fn from_shared(value: A) -> Self;
}

pub trait SharedPreparedTrait<F>
where
    F: Default + Clone + Send + Sync + Debug + CanonicalSerialize + CanonicalDeserialize,
{
}

#[derive(Derivative)]
#[derivative(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum SharedGroup<G: Group> {
    Public(G),
    Shared(G),
}

impl<G: Group> SharedGroup<G> {
    pub fn new(value: G) -> Self {
        Self::Public(value)
    }
}

impl<G: Group> Default for SharedGroup<G> {
    fn default() -> Self {
        Self::Public(G::default())
    }
}

// Neg
impl<G: Group> Neg for SharedGroup<G> {
    type Output = SharedGroup<G>;

    fn neg(self) -> Self::Output {
        match self {
            Self::Public(value) => Self::Public(-value),
            Self::Shared(_value) => {
                todo!();
            }
        }
    }
}

// Zero
impl<G: Group> Zero for SharedGroup<G> {
    fn zero() -> Self {
        todo!();
    }

    fn is_zero(&self) -> bool {
        todo!();
    }
}

impl<G: Group> DefaultIsZeroes for SharedGroup<G> {}

// Display
impl<G: Group> Display for SharedGroup<G> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public(value) => write!(f, "{}", value),
            Self::Shared(value) => write!(f, "{}", value),
        }
    }
}

// Mul
impl<G: Group> Mul<SharedField<G::ScalarField>> for SharedGroup<G> {
    type Output = SharedGroup<G>;

    fn mul(self, rhs: SharedField<G::ScalarField>) -> Self::Output {
        todo!()
    }
}

impl<'a, G: Group> Mul<&'a G> for SharedGroup<G> {
    type Output = SharedGroup<G>;

    fn mul(self, _rhs: &'a G) -> Self::Output {
        todo!()
    }
}

impl<'a, G: Group> Mul<&'a SharedField<G::ScalarField>> for SharedGroup<G> {
    type Output = SharedGroup<G>;

    fn mul(self, _rhs: &'a SharedField<G::ScalarField>) -> Self::Output {
        todo!()
    }
}

// MulAssign
impl<'a, G: Group> MulAssign<&'a G> for SharedGroup<G> {
    fn mul_assign(&mut self, _rhs: &'a G) {
        todo!()
    }
}

// cannot multiply-assign `SharedGroup<G>` by `mpc::field::SharedField<<G as Group>::ScalarField>`
impl<G: Group> MulAssign<SharedField<G::ScalarField>> for SharedGroup<G> {
    fn mul_assign(&mut self, _rhs: SharedField<G::ScalarField>) {
        todo!()
    }
}

impl<'a, G: Group> MulAssign<&'a SharedField<G::ScalarField>> for SharedGroup<G> {
    fn mul_assign(&mut self, _rhs: &'a SharedField<G::ScalarField>) {
        todo!()
    }
}

// Sub
impl<G: Group> Sub<SharedGroup<G>> for SharedGroup<G> {
    type Output = SharedGroup<G>;

    fn sub(self, rhs: SharedGroup<G>) -> Self::Output {
        self.sub(&rhs)
    }
}

impl<'a, G: Group> Sub<&'a SharedGroup<G>> for SharedGroup<G> {
    type Output = SharedGroup<G>;

    fn sub(self, rhs: &'a SharedGroup<G>) -> Self::Output {
        match self {
            Self::Public(value) => match rhs {
                Self::Public(rhs_value) => Self::Public(value - rhs_value),
                Self::Shared(rhs_value) => {
                    let am_first_party = get_party_id() == 0;

                    if am_first_party {
                        let result = value - rhs_value;
                        Self::Shared(result)
                    } else {
                        Self::Shared(rhs_value.clone())
                    }
                }
            },
            Self::Shared(value) => match rhs {
                Self::Public(rhs_value) => {
                    let am_first_party = get_party_id() == 0;

                    if am_first_party {
                        let result = value - rhs_value;
                        Self::Shared(result)
                    } else {
                        Self::Shared(value)
                    }
                }
                Self::Shared(rhs_value) => Self::Shared(value - rhs_value),
            },
        }
        // let mut new_value = self.clone();
        // new_value.sub_assign(rhs);
        // new_value
    }
}

// SubAssign
impl<'a, G: Group> SubAssign<&'a SharedGroup<G>> for SharedGroup<G> {
    fn sub_assign(&mut self, rhs: &'a SharedGroup<G>) {
        match self {
            Self::Public(value) => match rhs {
                Self::Public(rhs_value) => {value.sub_assign(rhs_value);},
                Self::Shared(rhs_value) => {
                    let am_first_party = get_party_id() == 0;
                    if am_first_party {
                        let new_value = value.sub(rhs_value);
                        *self = SharedGroup::Shared(new_value);
                    } else {
                        *self = rhs.clone();
                    }
                }
            },
            Self::Shared(value) => match rhs {
                Self::Public(rhs_value) => {
                    let am_first_party = get_party_id() == 0;
                    if am_first_party {
                        let new_value = value.sub(rhs_value);
                        *self = SharedGroup::Shared(new_value);
                    } else {
                        *self = rhs.clone();
                    }
                }
                Self::Shared(rhs_value) => {value.sub_assign(rhs_value);},
            },
        }
    }
}

impl<G: Group> SubAssign<SharedGroup<G>> for SharedGroup<G> {
    fn sub_assign(&mut self, rhs: SharedGroup<G>) {
        self.sub_assign(&rhs)
    }
}

// Add
impl<G: Group> Add<SharedGroup<G>> for SharedGroup<G> {
    type Output = SharedGroup<G>;

    fn add(self, rhs: SharedGroup<G>) -> Self::Output {
        self.add(&rhs)
    }
}

impl<'a, G: Group> Add<&'a SharedGroup<G>> for SharedGroup<G> {
    type Output = SharedGroup<G>;

    fn add(self, rhs: &'a SharedGroup<G>) -> Self::Output {
        match self {
            Self::Public(value) => match rhs {
                Self::Public(rhs_value) => Self::Public(value + rhs_value),
                Self::Shared(rhs_value) => {
                    let am_first_party = get_party_id() == 0;

                    if am_first_party {
                        let result = value + rhs_value;
                        Self::Shared(result)
                    } else {
                        Self::Shared(rhs_value.clone())
                    }
                }
            },
            Self::Shared(value) => match rhs {
                Self::Public(rhs_value) => {
                    let am_first_party = get_party_id() == 0;

                    if am_first_party {
                        let result = value + rhs_value;
                        Self::Shared(result)
                    } else {
                        Self::Shared(value)
                    }
                }
                Self::Shared(rhs_value) => Self::Shared(value + rhs_value),
            },
        }
    }
}

// AddAssign
impl<G: Group> AddAssign<SharedGroup<G>> for SharedGroup<G> {
    fn add_assign(&mut self, rhs: SharedGroup<G>) {
        match self {
            Self::Public(value) => match rhs {
                Self::Public(rhs_value) => {value.add_assign(rhs_value);},
                Self::Shared(rhs_value) => {
                    let am_first_party = get_party_id() == 0;
                    if am_first_party {
                        let new_value = value.add(rhs_value);
                        *self = SharedGroup::Shared(new_value);
                    } else {
                        *self = rhs;
                    }
                }
            },
            Self::Shared(value) => match rhs {
                Self::Public(rhs_value) => {
                    let am_first_party = get_party_id() == 0;
                    if am_first_party {
                        let new_value = value.add(rhs_value);
                        *self = SharedGroup::Shared(new_value);
                    } else {
                        *self = rhs;
                    }
                }
                Self::Shared(rhs_value) => {value.add_assign(rhs_value);},
            },
        }
    }
}

impl<'a, G: Group> AddAssign<&'a SharedField<G::ScalarField>> for SharedGroup<G> {
    fn add_assign(&mut self, rhs: &'a SharedField<G::ScalarField>) {
        todo!()
    }
}

impl<G: Group> AddAssign<SharedField<G::ScalarField>> for SharedGroup<G> {
    fn add_assign(&mut self, _rhs: SharedField<G::ScalarField>) {
        todo!()
    }
}

// cannot add-assign `&'a SharedGroup<G>` to `SharedGroup<G>`
impl<'a, G: Group> AddAssign<&'a SharedGroup<G>> for SharedGroup<G> {
    fn add_assign(&mut self, rhs: &'a SharedGroup<G>) {
        todo!()
    }
}

// Sum
impl<'a, G: Group> Sum<&'a SharedGroup<G>> for SharedGroup<G> {
    fn sum<I: Iterator<Item = &'a SharedGroup<G>>>(_iter: I) -> Self {
        todo!();
    }
}
impl<G: Group> Sum<SharedGroup<G>> for SharedGroup<G> {
    fn sum<I: Iterator<Item = SharedGroup<G>>>(_iter: I) -> Self {
        todo!();
    }
}

// Serialization
impl<G: Group> CanonicalSerialize for SharedGroup<G> {
    fn serialize_with_mode<W: std::io::prelude::Write>(
        &self,
        _writer: W,
        _compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        todo!()
    }

    fn serialized_size(&self, _compress: ark_serialize::Compress) -> usize {
        todo!()
    }
}

impl<G: Group> CanonicalSerializeWithFlags for SharedGroup<G> {
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

impl<G: Group> CanonicalDeserializeWithFlags for SharedGroup<G> {
    fn deserialize_with_flags<R: std::io::prelude::Read, Fl: ark_serialize::Flags>(
        _reader: R,
    ) -> Result<(Self, Fl), ark_serialize::SerializationError> {
        todo!()
    }
}

impl<G: Group> CanonicalDeserialize for SharedGroup<G> {
    fn deserialize_with_mode<R: std::io::prelude::Read>(
        _reader: R,
        _compress: ark_serialize::Compress,
        _validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        todo!()
    }
}

impl<G: Group> Valid for SharedGroup<G> {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        todo!()
    }
}

// Distribution
impl<G: Group> Distribution<SharedGroup<G>> for Standard {
    fn sample<R: Rng + ?Sized>(&self, _rng: &mut R) -> SharedGroup<G> {
        todo!()
    }
}

// Affine

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum SharedAffine<G: AffineRepr> {
    Public(G),
    Shared(G),
}

impl<G: AffineRepr> SharedAffine<G> {
    pub fn new(value: G) -> Self {
        Self::Public(value)
    }

    pub fn get_share_group_val(self) -> G {
        match self{
            Self::Public(sh) => sh,
            Self::Shared(sh) => sh
        }
    }
}

impl<G: AffineRepr> Default for SharedAffine<G> {
    fn default() -> Self {
        Self::Public(G::default())
    }
}

impl<G: AffineRepr> Mul<SharedField<G::ScalarField>> for SharedAffine<G> {
    type Output = SharedAffine<G>;

    fn mul(self, _rhs: SharedField<G::ScalarField>) -> Self::Output {
        todo!()
    }
}

impl<'a, G: AffineRepr> Mul<&'a G> for SharedAffine<G> {
    type Output = SharedAffine<G>;

    fn mul(self, _rhs: &'a G) -> Self::Output {
        todo!()
    }
}

impl<G: AffineRepr> Add<SharedAffine<G>> for SharedAffine<G> {
    type Output = SharedAffine<G>;

    fn add(self, _rhs: SharedAffine<G>) -> Self::Output {
        todo!();
    }
}

impl<'a, G: AffineRepr> Add<&'a SharedAffine<G>> for SharedAffine<G> {
    type Output = SharedAffine<G>;

    fn add(self, _rhs: &'a SharedAffine<G>) -> Self::Output {
        todo!();
    }
}

// Serialize
impl<G: AffineRepr> CanonicalSerialize for SharedAffine<G> {
    fn serialize_with_mode<W: std::io::prelude::Write>(
        &self,
        writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        let value = match self {
            Self::Public(value) => value,
            Self::Shared(value) => value,
        };

        value.serialize_with_mode(writer, compress)
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        let value = match self {
            Self::Public(value) => value,
            Self::Shared(value) => value,
        };

        value.serialized_size(compress)
    }
}

impl<G: AffineRepr> CanonicalDeserialize for SharedAffine<G> {
    fn deserialize_with_mode<R: std::io::prelude::Read>(
        reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let value = G::deserialize_with_mode(reader, compress, validate)?;

        Ok(Self::Public(value))
    }
}

// Valid
impl<G: AffineRepr> Valid for SharedAffine<G> {
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        todo!()
    }
}
