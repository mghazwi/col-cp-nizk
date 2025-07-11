#![allow(non_snake_case)]
extern crate alloc;
use alloc::borrow::Borrow;
use alloc::vec::Vec;
use core::iter;
use std::ops::Mul;
use std::time::Instant;
use ark_bls12_381::Fr;
use merlin::Transcript;
use super::errors::ProofError;
use super::transcript_bp::{BPTranscript, TranscriptProtocol};
use ark_ec::{AffineRepr, Group, CurveConfig, CurveGroup, ScalarMul, VariableBaseMSM};
use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField, batch_inversion, Zero};
use ark_std::iterable::Iterable;
use crate::mpc::{
    spdz_pairing::{MpcPairingTrait,MpcPairing},
    spdz_field::{SpdzSharedField,SpdzSharedFieldTrait},
    spdz_group::{
        group::{
            SpdzSharedGroupTrait, SpdzSharedGroup,SpdzSharedAffine, SpdzSharedAffineTrait
        },
        g1::{
            SpdzSharedG1
        }
    }
};

#[derive(Clone, Debug)]
pub struct InnerProductProof<G: Group> {
    pub(crate) L_vec: Vec<G>,
    pub(crate) R_vec: Vec<G>,
    pub(crate) a: G::ScalarField,
    pub(crate) b: G::ScalarField,
}

impl<GR: Group> InnerProductProof<GR> {
    /// Create an inner-product proof.
    ///
    /// The proof is created with respect to the bases \\(G\\), \\(H'\\),
    /// where \\(H'\_i = H\_i \cdot \texttt{Hprime\\_factors}\_i\\).
    ///
    /// The `verifier` is passed in as a parameter so that the
    /// challenges depend on the *entire* transcript (including parent
    /// protocols).
    ///
    /// The lengths of the vectors must all be the same, and must all be
    /// either 0 or a power of 2.
    pub fn create(
        transcript: &mut BPTranscript<GR>,
        Q: &GR,
        G_factors: &[GR::ScalarField],
        H_factors: &[GR::ScalarField],
        mut G_vec: Vec<GR>,
        mut H_vec: Vec<GR>,
        mut a_vec: Vec<GR::ScalarField>,
        mut b_vec: Vec<GR::ScalarField>,
    ) -> InnerProductProof<GR> {

        let mut G = &mut G_vec[..];
        let mut H = &mut H_vec[..];
        let mut a = &mut a_vec[..];
        let mut b = &mut b_vec[..];

        let mut n = G.len();

        // All of the input vectors must have the same length.
        assert_eq!(G.len(), n);
        assert_eq!(H.len(), n);
        assert_eq!(a.len(), n);
        assert_eq!(b.len(), n);
        assert_eq!(G_factors.len(), n);
        assert_eq!(H_factors.len(), n);

        // All of the input vectors must have a length that is a power of two.
        assert!(n.is_power_of_two());

        // <Transcript as TranscriptProtocol<GR>>::innerproduct_domain_sep(transcript,n as u64);
        transcript.innerproduct_domain_sep(n as u64);

        let lg_n = n.next_power_of_two().trailing_zeros() as usize;
        let mut L_vec = Vec::with_capacity(lg_n);
        let mut R_vec = Vec::with_capacity(lg_n);

        // If it's the first iteration, unroll the Hprime = H*y_inv scalar mults
        // into multiscalar muls, for performance.
        if n != 1 {
            n = n / 2;
            let (a_L, a_R) = a.split_at_mut(n);
            let (b_L, b_R) = b.split_at_mut(n);
            let (G_L, G_R) = G.split_at_mut(n);
            let (H_L, H_R) = H.split_at_mut(n);

            let c_L = inner_product(&a_L, &b_R);
            let c_R = inner_product(&a_R, &b_L);

            let scalars = a_L.iter()
                .zip(G_factors[n..2 * n].into_iter())
                .map(|(a_L_i, g)| *a_L_i * g)
                .chain(
                    b_R.iter()
                        .zip(H_factors[0..n].into_iter())
                        .map(|(b_R_i, h)| *b_R_i * h),
                )
                .chain(iter::once(c_L));//.collect();

            let bases = G_R.iter().chain(H_L.iter()).chain(iter::once(Q));

            // TODO: replace this with call to msm
            let mut acc = GR::zero();

            for (base, scalar) in bases.zip(scalars) {
                acc += base.mul(scalar);
            }

            let L = acc.clone();

            // let R = custom_msm_iter(
            let scalars =  a_R.iter()
                    .zip(G_factors[0..n].into_iter())
                    .map(|(a_R_i, g)| *a_R_i * g)
                    .chain(
                        b_L.iter()
                            .zip(H_factors[n..2 * n].into_iter())
                            .map(|(b_L_i, h)| *b_L_i * h),
                    )
                    .chain(iter::once(c_R));

            let bases = G_L.iter().chain(H_R.iter()).chain(iter::once(Q));
            // TODO: replace this with call to msm
            let mut acc = GR::zero();

            for (base, scalar) in bases.zip(scalars) {
                acc += base.mul(scalar);
            }

            let R = acc.clone();

            L_vec.push(L);
            R_vec.push(R);

            transcript.append_point(b"L", &L);
            transcript.append_point(b"R", &R);

            // let u:GR::ScalarField = <Transcript as TranscriptProtocol<GR>>::challenge_scalar(transcript, b"u");
            let u = transcript.challenge_scalar(b"u");
            let u_inv = <GR::ScalarField as Field>::inverse(&u).unwrap() ;// u.invert();

            for i in 0..n {
                a_L[i] = a_L[i] * u + u_inv * a_R[i];
                b_L[i] = b_L[i] * u_inv + u * b_R[i];
                G_L[i] = custom_msm(
                    &[u_inv * G_factors[i], u * G_factors[n + i]],
                    &[G_L[i], G_R[i]],
                );
                H_L[i] = custom_msm(
                    &[u * H_factors[i], u_inv * H_factors[n + i]],
                    &[H_L[i], H_R[i]],
                )
            }

            a = a_L;
            b = b_L;
            G = G_L;
            H = H_L;
        }

        while n != 1 {
            n = n / 2;
            let (a_L, a_R) = a.split_at_mut(n);
            let (b_L, b_R) = b.split_at_mut(n);
            let (G_L, G_R) = G.split_at_mut(n);
            let (H_L, H_R) = H.split_at_mut(n);

            let c_L = inner_product(&a_L, &b_R);
            let c_R = inner_product(&a_R, &b_L);

            let scalars =
                a_L.iter().chain(b_R.iter()).chain(iter::once(&c_L));
            let bases =
                G_R.iter().chain(H_L.iter()).chain(iter::once(Q));
            // TODO: replace this with call to msm
            let mut acc = GR::zero();

            for (base, scalar) in bases.zip(scalars) {
                acc += base.mul(scalar);
            }
            let L = acc.clone();

            // let R = custom_msm_iter(
            let scalars =
                a_R.iter().chain(b_L.iter()).chain(iter::once(&c_R));
            let bases =
                G_L.iter().chain(H_R.iter()).chain(iter::once(Q));

            // TODO: replace this with call to msm
            let mut acc = GR::zero();

            for (base, scalar) in bases.zip(scalars) {
                acc += base.mul(scalar);
            }
            let R = acc.clone();

            L_vec.push(L);
            R_vec.push(R);

            transcript.append_point(b"L", &L);
            transcript.append_point(b"R", &R);

            // let u:GR::ScalarField = <Transcript as TranscriptProtocol<GR>>::challenge_scalar(transcript, b"u");
            let u = transcript.challenge_scalar(b"u");
            let u_inv = <GR::ScalarField as Field>::inverse(&u).unwrap() ;

            for i in 0..n {
                a_L[i] = a_L[i] * u + u_inv * a_R[i];
                b_L[i] = b_L[i] * u_inv + u * b_R[i];
                G_L[i] = custom_msm(&[u_inv, u], &[G_L[i], G_R[i]]);
                H_L[i] = custom_msm(&[u, u_inv], &[H_L[i], H_R[i]]);
            }

            a = a_L;
            b = b_L;
            G = G_L;
            H = H_L;
        }

        InnerProductProof {
            L_vec: L_vec,
            R_vec: R_vec,
            a: a[0],
            b: b[0],
        }
    }

    /// Computes three vectors of verification scalars \\([u\_{i}^{2}]\\), \\([u\_{i}^{-2}]\\) and \\([s\_{i}]\\) for combined multiscalar multiplication
    /// in a parent protocol. See [inner product protocol notes](index.html#verification-equation) for details.
    /// The verifier must provide the input length \\(n\\) explicitly to avoid unbounded allocation within the inner product proof.
    pub(crate) fn verification_scalars(
        &self,
        n: usize,
        transcript: &mut BPTranscript<GR>,
    ) -> Result<(Vec<GR::ScalarField>, Vec<GR::ScalarField>, Vec<GR::ScalarField>), ProofError> {
        let lg_n = self.L_vec.len();
        if lg_n >= 32 {
            // 4 billion multiplications should be enough for anyone
            // and this check prevents overflow in 1<<lg_n below.
            return Err(ProofError::VerificationError);
        }
        if n != (1 << lg_n) {
            return Err(ProofError::VerificationError);
        }

        // <Transcript as TranscriptProtocol<GR>>::innerproduct_domain_sep(transcript,n as u64);
        transcript.innerproduct_domain_sep(n as u64);

        // 1. Recompute x_k,...,x_1 based on the proof transcript

        let mut challenges = Vec::with_capacity(lg_n);
        for (L, R) in self.L_vec.iter().zip(self.R_vec.iter()) {
            // <Transcript as TranscriptProtocol<GR>>::validate_and_append_point(transcript, b"L", L)?;
            // <Transcript as TranscriptProtocol<GR>>::validate_and_append_point(transcript, b"R", R)?;
            transcript.validate_and_append_point(b"L", L);
            transcript.validate_and_append_point(b"R", R);
            // let u:GR::ScalarField = <Transcript as TranscriptProtocol<GR>>::challenge_scalar(transcript, b"u");
            let u = transcript.challenge_scalar(b"u");

            challenges.push(u);
        }

        // 2. Compute 1/(u_k...u_1) and 1/u_k, ..., 1/u_1

        let mut challenges_inv = challenges.clone();
        batch_inversion(&mut challenges_inv);
        let allinv = challenges_inv.iter().copied().product();

        // 3. Compute u_i^2 and (1/u_i)^2

        for i in 0..lg_n {
            // XXX missing square fn upstream
            challenges[i] = challenges[i] * challenges[i];
            challenges_inv[i] = challenges_inv[i] * challenges_inv[i];
        }
        let challenges_sq = challenges;
        let challenges_inv_sq = challenges_inv;

        // 4. Compute s values inductively.

        let mut s = Vec::with_capacity(n);
        s.push(allinv);
        for i in 1..n {
            let lg_i = (32 - 1 - (i as u32).leading_zeros()) as usize;
            let k = 1 << lg_i;
            // The challenges are stored in "creation order" as [u_k,...,u_1],
            // so u_{lg(i)+1} = is indexed by (lg_n-1) - lg_i
            let u_lg_i_sq = challenges_sq[(lg_n - 1) - lg_i];
            s.push(s[i - k] * u_lg_i_sq);
        }

        Ok((challenges_sq, challenges_inv_sq, s))
    }

    /// This method is for testing that proof generation work,
    /// but for efficiency the actual protocols would use `verification_scalars`
    /// method to combine inner product verification with other checks
    /// in a single multiscalar multiplication.
    #[allow(dead_code)]
    pub fn verify<IG, IH>(
        &self,
        n: usize,
        transcript: &mut BPTranscript<GR>,
        G_factors: IG,
        H_factors: IH,
        P: &GR,
        Q: &GR,
        G: &[GR],
        H: &[GR],
    ) -> Result<(), ProofError>
    where
        IG: IntoIterator,
        IG::Item: Borrow<GR::ScalarField>,
        IH: IntoIterator,
        IH::Item: Borrow<GR::ScalarField>,
    {
        let (u_sq, u_inv_sq, s) = self.verification_scalars(n, transcript)?;

        let g_times_a_times_s = G_factors
            .into_iter()
            .zip(s.iter())
            .map(|(g_i, s_i)| (self.a * s_i) * g_i.borrow())
            .take(G.len());

        // 1/s[i] is s[!i], and !i runs from n-1 to 0 as i runs from 0 to n-1
        let inv_s = s.iter().rev();

        let h_times_b_div_s = H_factors
            .into_iter()
            .zip(inv_s)
            .map(|(h_i, s_i_inv)| (self.b * s_i_inv) * h_i.borrow());

        let neg_u_sq = u_sq.iter().map(|ui| -(*ui));
        let neg_u_inv_sq = u_inv_sq.iter().map(|ui| -(*ui));

        let scalars =
            iter::once(self.a * self.b)
                .chain(g_times_a_times_s)
                .chain(h_times_b_div_s)
                .chain(neg_u_sq)
                .chain(neg_u_inv_sq);
        let bases =
            iter::once(Q)
                .chain(G.iter())
                .chain(H.iter())
                .chain(self.L_vec.iter())
                .chain(self.R_vec.iter());

        // TODO: replace this with call to msm
        let mut acc = GR::zero();

        for (base, scalar) in bases.zip(scalars) {
            acc += base.mul(scalar);
        }
        let expect_P = acc.clone();

        if expect_P == *P {
            Ok(())
        } else {
            Err(ProofError::VerificationError)
        }
    }

    /// Returns the size in bytes required to serialize the inner
    /// product proof.
    ///
    /// For vectors of length `n` the proof size is
    /// \\(32 \cdot (2\lg n+2)\\) bytes.
    pub fn serialized_size(&self) -> usize {
        (self.L_vec.len() * 2 + 2) * 32
    }

    // TODO: add serialize and deserialize

}

/// Computes an inner product of two vectors
/// \\[
///    {\langle {\mathbf{a}}, {\mathbf{b}} \rangle} = \sum\_{i=0}^{n-1} a\_i \cdot b\_i.
/// \\]
/// Panics if the lengths of \\(\mathbf{a}\\) and \\(\mathbf{b}\\) are not equal.
pub fn inner_product<F:Field>(a: &[F], b: &[F]) -> F {
    let mut out = F::zero();
    if a.len() != b.len() {
        panic!("inner_product(a,b): lengths of vectors do not match");
    }
    for i in 0..a.len() {
        out += a[i] * b[i];
    }
    out
}

pub fn custom_msm<G: Group>(scalars: &[G::ScalarField], bases: &[G]) -> G {
    assert_eq!(bases.len(), scalars.len());

    let mut acc = G::zero();

    for (base, scalar) in bases.iter().zip(scalars.iter()) {
        acc += base.mul(*scalar);
    }
    acc
}


#[cfg(test)]
mod tests {
    use std::env;
    use std::ops::AddAssign;
    // use std::intrinsics::mir::Field;
    use super::*;

    use crate::bp::util;
    // use sha3::Sha3_512;
    type bls = ark_bls12_381::G1Projective;
    // type fr = ark_bls12_381::fr::Fr::;
    use ark_bls12_381::{Fr};
    // use ark_std::UniformRand;
    use ark_ff::{One, UniformRand};
    // use ark_std::test_rng;
    // use rand::SeedableRng;
    // use ark_std::{end_timer, start_timer, test_rng};
    use ark_std::rand::RngCore;
    use ark_std::rand::SeedableRng;
    use crate::globals::set_experiment_name;
    use crate::mpc::spdz_field::SpdzSharedFieldTrait;
    use crate::mpc::spdz_pairing::{MpcPairing, MpcPairingTrait};
    use crate::mpc::spdz_field::SpdzSharedField;
    use crate::network::Net;
    use crate::mpc::spdz_group::{group::SpdzSharedGroup, group::SpdzSharedGroupTrait, g1::SpdzSharedG1};
    // use rand::SeedableRng;

    fn test_helper_create(n: usize) {
        // let mut rng = rand::thread_rng();
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(5u64);

        use crate::bp::generators::BulletproofGens;
        let bp_gens = BulletproofGens::new(n, 1);
        let G: Vec<bls> = bp_gens.share(0).G(n).cloned().collect();
        let H: Vec<bls> = bp_gens.share(0).H(n).cloned().collect();

        // Q would be determined upstream in the protocol, so we pick a random one.
        // let Q = RistrettoPoint::hash_from_bytes::<Sha3_512>(b"test point");
        let Q= bls::rand(&mut rng);

        // a and b are the vectors for which we want to prove c = <a,b>
        let a: Vec<_> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let b: Vec<_> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        // let false_c = Fr::rand(&mut rng);
        let c = inner_product(&a, &b);
        // let c = false_c;

        let G_factors: Vec<Fr> = iter::repeat(Fr::one()).take(n).collect();

        // y_inv is (the inverse of) a random challenge
        let y_inv = Fr::rand(&mut rng);
        let H_factors: Vec<Fr> = util::exp_iter(y_inv).take(n).collect();

        // P would be determined upstream, but we need a correct P to check the proof.
        //
        // To generate P = <a,G> + <b,H'> + <a,b> Q, compute
        //             P = <a,G> + <b',H> + <a,b> Q,
        // where b' = b \circ y^(-n)
        let b_prime = b.iter().zip(util::exp_iter(y_inv)).map(|(bi, yi)| bi * &yi);
        // a.iter() has Item=&Scalar, need Item=Scalar to chain with b_prime
        let a_prime = a.iter().cloned();

        // let P = custom_msm_iter(
        let scalars =
            a_prime.chain(b_prime).chain(iter::once(c));
        let bases =
            G.iter().chain(H.iter()).chain(iter::once(&Q));

        // TODO: replace this with call to msm
        let mut acc = bls::zero();

        for (base, scalar) in bases.zip(scalars) {
            acc += base.mul(scalar);
        }
        let P = acc.clone();

        let mut verifier = Transcript::new(b"innerproducttest");
        let mut bp_verifier = BPTranscript::new(verifier);
        let proof = InnerProductProof::create(
            &mut bp_verifier,
            &Q,
            &G_factors,
            &H_factors,
            G.clone(),
            H.clone(),
            a.clone(),
            b.clone(),
        );

        let mut verifier = Transcript::new(b"innerproducttest");
        let mut bp_verifier = BPTranscript::new(verifier);
        assert!(proof
            .verify(
                n,
                &mut bp_verifier,
                iter::repeat(Fr::one()).take(n),
                util::exp_iter(y_inv).take(n),
                &P,
                &Q,
                &G,
                &H
            )
            .is_ok());
    }

    #[test]
    fn shared_test_helper_create() {
        let n = 1;


        // type B = ark_bls12_381::Bls12_381;
        // type P = MpcPairing<B>;
        // type SF = <B as Pairing>::ScalarField;

        let args: Vec<String> = env::args().collect();

        // Parse arguments
        let party_id = args[4].parse::<usize>().unwrap();
        let n_parties = args[5].parse::<usize>().unwrap();

        // Experiment setup
        let experiment_name = String::from("groth/")
            + n_parties.to_string().as_str()
            + "/";
        set_experiment_name(&experiment_name);

        Net::init_network(party_id, n_parties);

        // let mut rng = rand::thread_rng();
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(5u64);
        type B = ark_bls12_381::Bls12_381;
        type EG = <B as Pairing>::G1;

        type SG1 = SpdzSharedG1<B>;
        type SF = SpdzSharedField<Fr>;

        use crate::bp::generators::BulletproofGens;
        let bp_gens = BulletproofGens::new(n, 1);
        let G_1: Vec<bls> = bp_gens.share(0).G(n).cloned().collect();
        let H_1: Vec<bls> = bp_gens.share(0).H(n).cloned().collect();

        let mut G: Vec<SpdzSharedG1<B>> = vec![];
        for gen in G_1 {
            G.push(<SpdzSharedG1<B> as SpdzSharedGroupTrait<EG>>::from_public(gen));
        }

        let mut H: Vec<SpdzSharedG1<B>> = vec![];
        for gen in H_1 {
            H.push(<SpdzSharedG1<B> as SpdzSharedGroupTrait<EG>>::from_public(gen));
        }

        // Q would be determined upstream in the protocol, so we pick a random one.
        // let Q = RistrettoPoint::hash_from_bytes::<Sha3_512>(b"test point");
        let Q= <SG1 as SpdzSharedGroupTrait<EG>>::from_public(bls::rand(&mut rng));

        // a and b are the vectors for which we want to prove c = <a,b>
        let a: Vec<_> = (0..n).map(|_| <SF as SpdzSharedFieldTrait<Fr>>::from_public(Fr::rand(&mut rng))).collect();
        let b: Vec<_> = (0..n).map(|_| <SF as SpdzSharedFieldTrait<Fr>>::from_public(Fr::rand(&mut rng))).collect();
        let c = inner_product(&a, &b);

        let G_factors: Vec<SF> = iter::repeat(SF::one()).take(n).collect();

        // y_inv is (the inverse of) a random challenge
        let y_inv = SF::rand(&mut rng);
        let H_factors: Vec<SF> = util::exp_iter(y_inv).take(n).collect();

        // P would be determined upstream, but we need a correct P to check the proof.
        //
        // To generate P = <a,G> + <b,H'> + <a,b> Q, compute
        //             P = <a,G> + <b',H> + <a,b> Q,
        // where b' = b \circ y^(-n)
        let b_prime = b.iter().zip(util::exp_iter(y_inv)).map(|(bi, yi)| *bi * &yi);
        // a.iter() has Item=&Scalar, need Item=Scalar to chain with b_prime
        let a_prime = a.iter().cloned();

        // let P = custom_msm_iter(
        let scalars =
            a_prime.chain(b_prime).chain(iter::once(c));
        let bases =
            G.iter().chain(H.iter()).chain(iter::once(&Q));

        // TODO: replace this with call to msm
        let mut acc = SG1::zero();

        for (base, scalar) in bases.zip(scalars) {
            // acc.add_assign(base.mul(scalar));
            let temp = base.mul(scalar);
            acc += base.mul(scalar);
        }
        let P = acc.clone();

        let mut verifier = Transcript::new(b"innerproducttest");
        let mut bp_verifier = BPTranscript::new(verifier);
        let proof = InnerProductProof::create(
            &mut bp_verifier,
            &Q,
            &G_factors,
            &H_factors,
            G.clone(),
            H.clone(),
            a.clone(),
            b.clone(),
        );

        let mut verifier = Transcript::new(b"innerproducttest");
        let mut bp_verifier = BPTranscript::new(verifier);
        assert!(proof
            .verify(
                n,
                &mut bp_verifier,
                iter::repeat(SF::one()).take(n),
                util::exp_iter(y_inv).take(n),
                &P,
                &Q,
                &G,
                &H
            )
            .is_ok());
    }

    #[test]
    fn make_ipp_1() {
        test_helper_create(1);
    }

    #[test]
    fn make_ipp_2() {
        test_helper_create(2);
    }

    #[test]
    fn make_ipp_4() {
        test_helper_create(4);
    }

    #[test]
    fn make_ipp_32() {
        test_helper_create(32);
    }

    #[test]
    fn make_ipp_64() {
        test_helper_create(64);
    }

    #[test]
    fn test_inner_product() {
        let a = vec![
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        ];
        let b = vec![
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
            Fr::from(5u64),
        ];
        assert_eq!(Fr::from(40u64), inner_product(&a, &b));
    }

    #[test]
    fn shared_test_inner_product() {
        type B = ark_bls12_381::Bls12_381;
        type P = MpcPairing<B>;
        type SF = <B as Pairing>::ScalarField;

        let args: Vec<String> = env::args().collect();

        // Parse arguments
        let party_id = args[4].parse::<usize>().unwrap();
        let n_parties = args[5].parse::<usize>().unwrap();

        // Experiment setup
        let experiment_name = String::from("groth/")
            + n_parties.to_string().as_str()
            + "/";
        set_experiment_name(&experiment_name);

        Net::init_network(party_id, n_parties);

        let a = vec![
            // <P as MpcPairingTrait<B>>::ScalarField::from_public(Fr::from(1u64)),
            // <P as MpcPairingTrait<B>>::ScalarField::from_public(Fr::from(2u64)),
            // <P as MpcPairingTrait<B>>::ScalarField::from_public(Fr::from(3u64)),
            // <P as MpcPairingTrait<B>>::ScalarField::from_public(Fr::from(4u64)),
            <SpdzSharedField<Fr> as SpdzSharedFieldTrait<Fr>>::from_public(Fr::from(1u64)),
            <SpdzSharedField<Fr> as SpdzSharedFieldTrait<Fr>>::from_public(Fr::from(2u64)),
            <SpdzSharedField<Fr> as SpdzSharedFieldTrait<Fr>>::from_public(Fr::from(3u64)),
            <SpdzSharedField<Fr> as SpdzSharedFieldTrait<Fr>>::from_public(Fr::from(4u64)),
        ];
        let b = vec![
            // <P as MpcPairingTrait<B>>::ScalarField::from_public(Fr::from(2u64)),
            // <P as MpcPairingTrait<B>>::ScalarField::from_public(Fr::from(3u64)),
            // <P as MpcPairingTrait<B>>::ScalarField::from_public(Fr::from(4u64)),
            // <P as MpcPairingTrait<B>>::ScalarField::from_public(Fr::from(5u64)),
            <SpdzSharedField<Fr> as SpdzSharedFieldTrait<Fr>>::from_public(Fr::from(2u64)),
            <SpdzSharedField<Fr> as SpdzSharedFieldTrait<Fr>>::from_public(Fr::from(3u64)),
            <SpdzSharedField<Fr> as SpdzSharedFieldTrait<Fr>>::from_public(Fr::from(4u64)),
            <SpdzSharedField<Fr> as SpdzSharedFieldTrait<Fr>>::from_public(Fr::from(5u64)),
        ];

        let res = <SpdzSharedField<Fr> as SpdzSharedFieldTrait<Fr>>::from_public(Fr::from(40u64));

        assert_eq!(res, inner_product(&a, &b));
    }
}
