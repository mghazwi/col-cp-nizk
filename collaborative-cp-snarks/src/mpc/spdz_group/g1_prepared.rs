use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError, Valid, Write};
use derivative::Derivative;

use super::{
    g1::SpdzSharedG1,
    g1_affine::SpdzSharedG1Affine,
    group::{SpdzSharedAffine, SpdzSharedPreparedTrait},
};

#[derive(Derivative)]
#[derivative(Clone, Debug, Default)]
pub struct SpdzSharedG1Prepared<P: Pairing> {
    pub value: P::G1Prepared,
}

impl<P: Pairing> SpdzSharedPreparedTrait<P::G1Prepared> for SpdzSharedG1Prepared<P> {}

impl<P: Pairing> From<SpdzSharedG1Affine<P>> for SpdzSharedG1Prepared<P> {
    fn from(value: SpdzSharedG1Affine<P>) -> Self {
        SpdzSharedG1Prepared {
            value: match value.value {
                SpdzSharedAffine::Public{sh,mac} => sh.into(),
                SpdzSharedAffine::Shared{sh,mac} => sh.into(),
            },
        }
    }
}

// the trait bound `for<'a> SharedG1Prepared<P>: From<&'a SharedG1Affine<P>>` is not satisfied
impl<'a, P: Pairing> From<&'a SpdzSharedG1Affine<P>> for SpdzSharedG1Prepared<P> {
    fn from(_: &'a SpdzSharedG1Affine<P>) -> Self {
        todo!()
    }
}

impl<P: Pairing> From<SpdzSharedG1<P>> for SpdzSharedG1Prepared<P> {
    fn from(_: SpdzSharedG1<P>) -> Self {
        todo!()
    }
}

impl<'a, P: Pairing> From<&'a SpdzSharedG1<P>> for SpdzSharedG1Prepared<P> {
    fn from(_: &'a SpdzSharedG1<P>) -> Self {
        todo!()
    }
}

// Serialize
impl<P: Pairing> Valid for SpdzSharedG1Prepared<P> {
    fn check(&self) -> Result<(), SerializationError> {
        todo!()
    }
}

impl<P: Pairing> CanonicalSerialize for SpdzSharedG1Prepared<P> {
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

impl<P: Pairing> CanonicalDeserialize for SpdzSharedG1Prepared<P> {
    fn deserialize_with_mode<R: std::io::prelude::Read>(
        _reader: R,
        _compress: ark_serialize::Compress,
        _validate: ark_serialize::Validate,
    ) -> Result<Self, SerializationError> {
        todo!()
    }
}
