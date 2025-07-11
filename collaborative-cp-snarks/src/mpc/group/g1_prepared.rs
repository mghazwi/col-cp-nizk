use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError, Valid, Write};
use derivative::Derivative;

use super::{
    g1::SharedG1,
    g1_affine::SharedG1Affine,
    group::{SharedAffine, SharedPreparedTrait},
};

#[derive(Derivative)]
#[derivative(Clone, Debug, Default)]
pub struct SharedG1Prepared<P: Pairing> {
    pub value: P::G1Prepared,
}

impl<P: Pairing> SharedPreparedTrait<P::G1Prepared> for SharedG1Prepared<P> {}

impl<P: Pairing> From<SharedG1Affine<P>> for SharedG1Prepared<P> {
    fn from(value: SharedG1Affine<P>) -> Self {
        SharedG1Prepared {
            value: match value.value {
                SharedAffine::Public(value) => value.into(),
                SharedAffine::Shared(value) => value.into(),
            },
        }
    }
}

// the trait bound `for<'a> SharedG1Prepared<P>: From<&'a SharedG1Affine<P>>` is not satisfied
impl<'a, P: Pairing> From<&'a SharedG1Affine<P>> for SharedG1Prepared<P> {
    fn from(_: &'a SharedG1Affine<P>) -> Self {
        todo!()
    }
}

impl<P: Pairing> From<SharedG1<P>> for SharedG1Prepared<P> {
    fn from(_: SharedG1<P>) -> Self {
        todo!()
    }
}

impl<'a, P: Pairing> From<&'a SharedG1<P>> for SharedG1Prepared<P> {
    fn from(_: &'a SharedG1<P>) -> Self {
        todo!()
    }
}

// Serialize
impl<P: Pairing> Valid for SharedG1Prepared<P> {
    fn check(&self) -> Result<(), SerializationError> {
        todo!()
    }
}

impl<P: Pairing> CanonicalSerialize for SharedG1Prepared<P> {
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

impl<P: Pairing> CanonicalDeserialize for SharedG1Prepared<P> {
    fn deserialize_with_mode<R: std::io::prelude::Read>(
        _reader: R,
        _compress: ark_serialize::Compress,
        _validate: ark_serialize::Validate,
    ) -> Result<Self, SerializationError> {
        todo!()
    }
}
