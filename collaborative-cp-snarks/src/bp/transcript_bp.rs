//! Defines a generic `TranscriptProtocol` trait over Group "G" for using a Merlin transcript.
use merlin::Transcript;
use super::errors::ProofError;
use ark_ec::{AffineRepr, Group, CurveConfig,};
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_std::{
    marker::PhantomData,
};

pub trait TranscriptProtocol<G: Group> {
    /// Append a domain separator for an `n`-bit, `m`-party range proof.
    fn rangeproof_domain_sep(&mut self, n: u64, m: u64);

    /// Append a domain separator for a length-`n` inner product proof.
    fn innerproduct_domain_sep(&mut self, n: u64);

    /// Append a domain separator for a constraint system.
    fn r1cs_domain_sep(&mut self);

    /// Commit a domain separator for a CS without randomized constraints.
    fn r1cs_1phase_domain_sep(&mut self);

    /// Commit a domain separator for a CS with randomized constraints.
    fn r1cs_2phase_domain_sep(&mut self);

    /// Append a `scalar` with the given `label`.
    fn append_scalar(&mut self, label: &'static [u8], scalar: &G::ScalarField);

    /// Append a `point` with the given `label`.
    fn append_point(&mut self, label: &'static [u8], point: &G);

    /// Check that a point is not the identity, then append it to the
    /// transcript.  Otherwise, return an error.
    fn validate_and_append_point(
        &mut self,
        label: &'static [u8],
        point: &G,
    ) -> Result<(), ProofError>;

    /// Compute a `label`ed challenge variable.
    fn challenge_scalar(&mut self, label: &'static [u8]) -> G::ScalarField;

    // fn new(value: &[u8]) -> Self;
}
#[derive(Clone)]
pub struct BPTranscript< G:Group>{
    _group: PhantomData<G>,
    pub transcript: Transcript,
}

impl<G:Group> BPTranscript<G>{
    pub fn new(t: Transcript) -> Self{
        Self{
            _group: Default::default(),
            transcript: t,
        }
    }
}

impl<G:Group> TranscriptProtocol<G> for BPTranscript< G> {

    fn rangeproof_domain_sep(&mut self, n: u64, m: u64) {
        self.transcript.append_message(b"dom-sep", b"rangeproof v1");
        self.transcript.append_u64(b"n", n);
        self.transcript.append_u64(b"m", m);
    }

    fn innerproduct_domain_sep(&mut self, n: u64) {
        self.transcript.append_message(b"dom-sep", b"ipp v1");
        self.transcript.append_u64(b"n", n);
    }

    fn r1cs_domain_sep(&mut self) {
        self.transcript.append_message(b"dom-sep", b"r1cs v1");
    }

    fn r1cs_1phase_domain_sep(&mut self) {
        self.transcript.append_message(b"dom-sep", b"r1cs-1phase");
    }

    fn r1cs_2phase_domain_sep(&mut self) {
        self.transcript.append_message(b"dom-sep", b"r1cs-2phase");
    }

    fn append_scalar(&mut self, label: &'static [u8], scalar: &G::ScalarField) {
        let mut p_ser = Vec::new();
        scalar.serialize_uncompressed(&mut p_ser);
        self.transcript.append_message(label,&p_ser);
    }

    fn append_point(&mut self, label: &'static [u8], point: &G) {
        let mut p_ser = Vec::new();
        point.serialize_uncompressed(&mut p_ser);
        self.transcript.append_message(label,  &p_ser);
    }

    fn validate_and_append_point(
        &mut self,
        label: &'static [u8],
        point: &G,
    ) -> Result<(), ProofError> {
            let mut p_ser = Vec::new();
            point.serialize_uncompressed(&mut p_ser);
            Ok(self.transcript.append_message(label, &p_ser))
    }

    fn challenge_scalar(&mut self, label: &'static [u8]) -> G::ScalarField {
        let mut buf = [0u8; 64];
        self.transcript.challenge_bytes(label, &mut buf);

        G::ScalarField::from_le_bytes_mod_order(&buf)
    }
}
