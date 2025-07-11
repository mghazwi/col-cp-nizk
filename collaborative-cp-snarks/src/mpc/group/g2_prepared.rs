use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError, Valid, Write};
use derivative::Derivative;

use super::{
    g2::SharedG2,
    g2_affine::SharedG2Affine,
    group::{SharedAffine, SharedPreparedTrait},
};

#[derive(Derivative)]
#[derivative(Clone, Debug, Default)]
pub struct SharedG2Prepared<P: Pairing> {
    pub value: P::G2Prepared,
}

impl<P: Pairing> SharedPreparedTrait<P::G2Prepared> for SharedG2Prepared<P> {}

impl<P: Pairing> From<SharedG2Affine<P>> for SharedG2Prepared<P> {
    fn from(value: SharedG2Affine<P>) -> Self {
        SharedG2Prepared {
            value: match value.value {
                SharedAffine::Public(value) => value.into(),
                SharedAffine::Shared(value) => value.into(),
            },
        }
    }
}

// the trait bound `for<'a> SharedG2Prepared<P>: From<&'a SharedG2Affine<P>>` is not satisfied
impl<'a, P: Pairing> From<&'a SharedG2Affine<P>> for SharedG2Prepared<P> {
    fn from(_: &'a SharedG2Affine<P>) -> Self {
        unimplemented!()
    }
}

impl<P: Pairing> From<SharedG2<P>> for SharedG2Prepared<P> {
    fn from(_: SharedG2<P>) -> Self {
        unimplemented!()
    }
}

impl<'a, P: Pairing> From<&'a SharedG2<P>> for SharedG2Prepared<P> {
    fn from(_: &'a SharedG2<P>) -> Self {
        unimplemented!()
    }
}

// Serialize
impl<P: Pairing> Valid for SharedG2Prepared<P> {
    fn check(&self) -> Result<(), SerializationError> {
        todo!()
    }
}

impl<P: Pairing> CanonicalSerialize for SharedG2Prepared<P> {
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

impl<P: Pairing> CanonicalDeserialize for SharedG2Prepared<P> {
    fn deserialize_with_mode<R: std::io::prelude::Read>(
        _reader: R,
        _compress: ark_serialize::Compress,
        _validate: ark_serialize::Validate,
    ) -> Result<Self, SerializationError> {
        todo!()
    }
}
