use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError, Valid, Write};
use derivative::Derivative;

use super::{
    g2::SpdzSharedG2,
    g2_affine::SpdzSharedG2Affine,
    group::{SpdzSharedAffine, SpdzSharedPreparedTrait},
};

#[derive(Derivative)]
#[derivative(Clone, Debug, Default)]
pub struct SpdzSharedG2Prepared<P: Pairing> {
    pub value: P::G2Prepared,
}

impl<P: Pairing> SpdzSharedPreparedTrait<P::G2Prepared> for SpdzSharedG2Prepared<P> {}

impl<P: Pairing> From<SpdzSharedG2Affine<P>> for SpdzSharedG2Prepared<P> {
    fn from(value: SpdzSharedG2Affine<P>) -> Self {
        SpdzSharedG2Prepared {
            value: match value.value {
                SpdzSharedAffine::Public{sh,mac} => sh.into(),
                SpdzSharedAffine::Shared{sh,mac} => sh.into(),
            },
        }
    }
}

// the trait bound `for<'a> SharedG2Prepared<P>: From<&'a SharedG2Affine<P>>` is not satisfied
impl<'a, P: Pairing> From<&'a SpdzSharedG2Affine<P>> for SpdzSharedG2Prepared<P> {
    fn from(_: &'a SpdzSharedG2Affine<P>) -> Self {
        unimplemented!()
    }
}

impl<P: Pairing> From<SpdzSharedG2<P>> for SpdzSharedG2Prepared<P> {
    fn from(_: SpdzSharedG2<P>) -> Self {
        unimplemented!()
    }
}

impl<'a, P: Pairing> From<&'a SpdzSharedG2<P>> for SpdzSharedG2Prepared<P> {
    fn from(_: &'a SpdzSharedG2<P>) -> Self {
        unimplemented!()
    }
}

// Serialize
impl<P: Pairing> Valid for SpdzSharedG2Prepared<P> {
    fn check(&self) -> Result<(), SerializationError> {
        todo!()
    }
}

impl<P: Pairing> CanonicalSerialize for SpdzSharedG2Prepared<P> {
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

impl<P: Pairing> CanonicalDeserialize for SpdzSharedG2Prepared<P> {
    fn deserialize_with_mode<R: std::io::prelude::Read>(
        _reader: R,
        _compress: ark_serialize::Compress,
        _validate: ark_serialize::Validate,
    ) -> Result<Self, SerializationError> {
        todo!()
    }
}
