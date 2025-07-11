#![allow(non_snake_case)]

extern crate alloc;
use core::iter;
use merlin::Transcript;

use crate::bp::errors::ProofError;
use crate::bp::generators::{BulletproofGens, PedersenGens};
use crate::bp::inner_product_proof::InnerProductProof;
use crate::bp::transcript_bp::{BPTranscript, TranscriptProtocol};
use crate::bp::util;

use ark_std::{cfg_iter, rand::RngCore, vec::Vec, UniformRand};
use serde::de::Visitor;
use serde::{self, Deserialize, Deserializer, Serialize, Serializer};
use ark_std::rand::{prelude::StdRng, SeedableRng};

use ark_ec::{AffineRepr, Group, CurveConfig, CurveGroup, ScalarMul, VariableBaseMSM};
use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField, batch_inversion, Zero, One};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use tokio::time::Instant;

// Modules for MPC protocol

pub mod dealer;
pub mod messages;
pub mod party;

/// The `RangeProof` struct represents a proof that one or more values
/// are in a range.
///
/// The `RangeProof` struct contains functions for creating and
/// verifying aggregated range proofs.  The single-value case is
/// implemented as a special case of aggregated range proofs.
///
/// The bitsize of the range, as well as the list of commitments to
/// the values, are not included in the proof, and must be known to
/// the verifier.
///
/// This implementation requires that both the bitsize `n` and the
/// aggregation size `m` be powers of two, so that `n = 8, 16, 32, 64`
/// and `m = 1, 2, 4, 8, 16, ...`.  Note that the aggregation size is
/// not given as an explicit parameter, but is determined by the
/// number of values or commitments passed to the prover or verifier.
///
/// # Note
///
/// For proving, these functions run the multiparty aggregation
/// protocol locally.  That API is exposed in the [`aggregation`](::range_proof_mpc)
/// module and can be used to perform online aggregation between
/// parties without revealing secret values to each other.
#[derive(Clone, Debug)]
pub struct RangeProof<G:Group> {
    /// Commitment to the bits of the value
    A: G,
    /// Commitment to the blinding factors
    S: G,
    /// Commitment to the \\(t_1\\) coefficient of \\( t(x) \\)
    T_1: G,
    /// Commitment to the \\(t_2\\) coefficient of \\( t(x) \\)
    T_2: G,
    /// Evaluation of the polynomial \\(t(x)\\) at the challenge point \\(x\\)
    t_x: G::ScalarField,
    /// Blinding factor for the synthetic commitment to \\(t(x)\\)
    t_x_blinding: G::ScalarField,
    /// Blinding factor for the synthetic commitment to the inner-product arguments
    e_blinding: G::ScalarField,
    /// Proof data for the inner-product argument.
    ipp_proof: InnerProductProof<G>,
}

impl<G: Group> RangeProof<G> {

    /// Create a rangeproof for a set of values.
    pub fn prove_multiple_with_rng<R: RngCore>(
        bp_gens: &BulletproofGens<G>,
        pc_gens: &PedersenGens<G>,
        transcript: &mut BPTranscript<G>,
        values: &[u64],
        blindings: &[G::ScalarField],
        n: usize,
        rng: &mut R,
    ) -> Result<(RangeProof<G>, Vec<G>), ProofError> {
        use self::dealer::*;
        use self::party::*;

        if values.len() != blindings.len() {
            return Err(ProofError::WrongNumBlindingFactors);
        }

        let t = Instant::now();

        let dealer = Dealer::new(bp_gens, pc_gens, transcript, n, values.len())?;

        let parties: Vec<_> = values
            .iter()
            .zip(blindings.iter())
            .map(|(&v, &v_blinding)| Party::new(bp_gens, pc_gens, v, v_blinding, n))
            // Collect the iterator of Results into a Result<Vec>, then unwrap it
            .collect::<Result<Vec<_>, _>>()?;

        let (parties, bit_commitments): (Vec<_>, Vec<_>) = parties
            .into_iter()
            .enumerate()
            .map(|(j, p)| {
                p.assign_position_with_rng(j, rng)
                    .expect("We already checked the parameters, so this should never happen")
            })
            .unzip();

        let value_commitments: Vec<_> = bit_commitments.iter().map(|c| c.V_j).collect();

        let (dealer, bit_challenge) = dealer.receive_bit_commitments(bit_commitments)?;

        let (parties, poly_commitments): (Vec<_>, Vec<_>) = parties
            .into_iter()
            .map(|p| p.apply_challenge_with_rng(&bit_challenge, rng))
            .unzip();

        let (dealer, poly_challenge) = dealer.receive_poly_commitments(poly_commitments)?;

        let proof_shares: Vec<_> = parties
            .into_iter()
            .map(|p| p.apply_challenge(&poly_challenge))
            // Collect the iterator of Results into a Result<Vec>, then unwrap it
            .collect::<Result<Vec<_>, _>>()?;

        let proof = dealer.receive_trusted_shares(&proof_shares)?;

        let d = t.elapsed();
        println!("prove time = {:?}",d);

        Ok((proof, value_commitments))
    }

    /// Verifies an aggregated rangeproof for the given value commitments.
    pub fn verify_multiple_with_rng<R: RngCore>(
        &self,
        bp_gens: &BulletproofGens<G>,
        pc_gens: &PedersenGens<G>,
        transcript: &mut BPTranscript<G>,
        value_commitments: &[G],
        n: usize,
        rng: &mut R,
    ) -> Result<(), ProofError> {
        let m = value_commitments.len();

        // First, replay the "interactive" protocol using the proof
        // data to recompute all challenges.
        if !(n == 8 || n == 16 || n == 32 || n == 64) {
            return Err(ProofError::InvalidBitsize);
        }
        if bp_gens.gens_capacity < n {
            return Err(ProofError::InvalidGeneratorsLength);
        }
        if bp_gens.party_capacity < m {
            return Err(ProofError::InvalidGeneratorsLength);
        }

        transcript.rangeproof_domain_sep(n as u64, m as u64);

        for V in value_commitments.iter() {
            transcript.append_point(b"V", V);
        }

        transcript.validate_and_append_point(b"A", &self.A)?;
        transcript.validate_and_append_point(b"S", &self.S)?;

        let y = transcript.challenge_scalar(b"y");
        let z = transcript.challenge_scalar(b"z");
        let zz = z * z;
        let minus_z = -z;

        transcript.validate_and_append_point(b"T_1", &self.T_1)?;
        transcript.validate_and_append_point(b"T_2", &self.T_2)?;

        let x = transcript.challenge_scalar(b"x");

        transcript.append_scalar(b"t_x", &self.t_x);
        transcript.append_scalar(b"t_x_blinding", &self.t_x_blinding);
        transcript.append_scalar(b"e_blinding", &self.e_blinding);

        let w = transcript.challenge_scalar(b"w");

        // Challenge value for batching statements to be verified
        let c = G::ScalarField::rand(rng);

        let (x_sq, x_inv_sq, s) = self.ipp_proof.verification_scalars(n * m, transcript)?;
        let s_inv = s.iter().rev();

        let a = self.ipp_proof.a;
        let b = self.ipp_proof.b;

        // Construct concat_z_and_2, an iterator of the values of
        // z^0 * \vec(2)^n || z^1 * \vec(2)^n || ... || z^(m-1) * \vec(2)^n
        let powers_of_2: Vec<G::ScalarField> = util::exp_iter(G::ScalarField::from(2u64)).take(n).collect();
        let concat_z_and_2: Vec<G::ScalarField> = util::exp_iter(z)
            .take(m)
            .flat_map(|exp_z| powers_of_2.iter().map(move |exp_2| *exp_2 * exp_z))
            .collect();

        let g = s.iter().map(|s_i| minus_z - a * s_i);
        let h = s_inv
            .zip(util::exp_iter(y.inverse().unwrap()))
            .zip(concat_z_and_2.iter())
            .map(|((s_i_inv, exp_y_inv), z_and_2)| z + exp_y_inv * (zz * z_and_2 - b * s_i_inv));

        let value_commitment_scalars = util::exp_iter(z).take(m).map(|z_exp| c * zz * z_exp);
        let basepoint_scalar = w * (self.t_x - a * b) + c * (delta(n, m, &y, &z) - self.t_x);

        let scalars = iter::once(G::ScalarField::one())
            .chain(iter::once(x))
            .chain(iter::once(c * x))
            .chain(iter::once(c * x * x))
            .chain(x_sq.iter().cloned())
            .chain(x_inv_sq.iter().cloned())
            .chain(iter::once(-self.e_blinding - c * self.t_x_blinding))
            .chain(iter::once(basepoint_scalar))
            .chain(g)
            .chain(h)
            .chain(value_commitment_scalars);
        let bases = iter::once(self.A)
            .chain(iter::once(self.S))
            .chain(iter::once(self.T_1))
            .chain(iter::once(self.T_2))
            .chain(self.ipp_proof.L_vec.iter().map(|L| *L))
            .chain(self.ipp_proof.R_vec.iter().map(|R| *R))
            .chain(iter::once(pc_gens.B_blinding))
            .chain(iter::once(pc_gens.B))
            .chain(bp_gens.G(n, m).map(|&x| x))
            .chain(bp_gens.H(n, m).map(|&x| x))
            .chain(value_commitments.iter().map(|V| *V));

        // TODO: replace this with call to msm
        let mut acc = G::zero();

        for (base, scalar) in bases.zip(scalars) {
            acc += base.mul(scalar);
        }
        let mega_check = acc.clone();

        if mega_check.is_zero() {
            Ok(())
        } else {
            Err(ProofError::VerificationError)
        }
    }

}

// /// Compute
// /// \\[
// /// \delta(y,z) = (z - z^{2}) \langle \mathbf{1}, {\mathbf{y}}^{n \cdot m} \rangle - \sum_{j=0}^{m-1} z^{j+3} \cdot \langle \mathbf{1}, {\mathbf{2}}^{n \cdot m} \rangle
// /// \\]
fn delta<F: Field>(n: usize, m: usize, y: &F, z: &F) -> F {
    let sum_y = util::sum_of_powers(y, n * m);
    let sum_2 = util::sum_of_powers(&F::from(2u64), n);
    let sum_z = util::sum_of_powers(z, m);
    let z_2 = *z*z;
    let z_3 = z_2*z;

    (*z - z_2) * sum_y - z_3 * sum_2 * sum_z
}
//
#[cfg(test)]
mod tests {
    use super::*;

    use crate::bp::generators::PedersenGens;
    use ark_bls12_381::Fr;
    use ark_bls12_381::G1Projective;
    use ark_std::rand::rngs::StdRng;
    use rand::Rng;

    #[test]
    fn test_delta() {
        let mut rng = StdRng::seed_from_u64(5u64);
        let y = Fr::rand(&mut rng);
        let z = Fr::rand(&mut rng);

        // Choose n = 256 to ensure we overflow the group order during
        // the computation, to check that that's done correctly
        let n = 256;

        // code copied from previous implementation
        let z2 = z * z;
        let z3 = z2 * z;
        let mut power_g = Fr::zero();
        let mut exp_y = Fr::one(); // start at y^0 = 1
        let mut exp_2 = Fr::one(); // start at 2^0 = 1
        for _ in 0..n {
            power_g += (z - z2) * exp_y - z3 * exp_2;

            exp_y = exp_y * y; // y^i -> y^(i+1)
            exp_2 = exp_2 + exp_2; // 2^i -> 2^(i+1)
        }

        assert_eq!(power_g, delta(n, 1, &y, &z),);
    }

    /// Given a bitsize `n`, test the following:
    ///
    /// 1. Generate `m` random values and create a proof they are all in range;
    /// 4. Verify the proof.
    fn singleparty_create_and_verify_helper(n: usize, m: usize) {
        let mut ark_rng = StdRng::seed_from_u64(5u64);

        // Both prover and verifier have access to the generators and the proof
        let max_bitsize = 64;
        let max_parties = 8;
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(max_bitsize, max_parties);

        // Prover's scope
        let (proof, value_commitments) = {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            // 0. Create witness data
            let (min, max) = (0u64, ((1u128 << n) - 1) as u64);
            let values: Vec<u64> = (0..m).map(|_| rng.gen_range(min..max)).collect();
            let blindings: Vec<Fr> = (0..m).map(|_| Fr::rand(&mut ark_rng)).collect();

            // 1. Create the proof
            let mut transcript = Transcript::new(b"AggregatedRangeProofTest");
            let mut bp_transcript = BPTranscript::<G1Projective>::new(transcript);

            let (proof, value_commitments) = RangeProof::prove_multiple_with_rng(
                &bp_gens,
                &pc_gens,
                &mut bp_transcript,
                &values,
                &blindings,
                n,
                &mut ark_rng
            )
                .unwrap();

            // 2. Return serialized proof and value commitments
            (proof, value_commitments)
        };

        // Verifier's scope
        {
            // 3. Deserialize
            // let proof: RangeProof = bincode::deserialize(&proof_bytes).unwrap();

            // 4. Verify with the same customization label as above
            let mut transcript = Transcript::new(b"AggregatedRangeProofTest");
            let mut bp_transcript = BPTranscript::<G1Projective>::new(transcript);
            assert!(proof
                .verify_multiple_with_rng(&bp_gens, &pc_gens, &mut bp_transcript, &value_commitments, n, &mut ark_rng)
                .is_ok());
        }
    }

    #[test]
    fn create_and_verify_n_32_m_1() {
        singleparty_create_and_verify_helper(32, 1);
    }

    #[test]
    fn create_and_verify_n_32_m_2() {
        singleparty_create_and_verify_helper(32, 2);
    }

    #[test]
    fn create_and_verify_n_32_m_4() {
        singleparty_create_and_verify_helper(32, 4);
    }

    #[test]
    fn create_and_verify_n_32_m_8() {
        singleparty_create_and_verify_helper(32, 8);
    }

    #[test]
    fn create_and_verify_n_64_m_1() {
        singleparty_create_and_verify_helper(64, 1);
    }

    #[test]
    fn create_and_verify_n_64_m_2() {
        singleparty_create_and_verify_helper(64, 2);
    }

    #[test]
    fn create_and_verify_n_64_m_4() {
        singleparty_create_and_verify_helper(64, 4);
    }

    #[test]
    fn create_and_verify_n_64_m_8() {
        singleparty_create_and_verify_helper(64, 8);
    }
}

