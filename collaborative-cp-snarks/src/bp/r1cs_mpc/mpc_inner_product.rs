
extern crate alloc;

use alloc::vec::Vec;
use futures::future::join_all;

use core::iter;
use std::ops::Mul;
use crate::bp::errors::MPCError;
use crate::bp::inner_product_proof_381::InnerProductProof;
use crate::bp::transcript_381::TranscriptProtocol;
use merlin::Transcript;

use ark_bls12_381::Fr;
use ark_bls12_381::Bls12_381 as G;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, Zero};

use crate::mpc::spdz_field::{SpdzSharedField as SF, SpdzSharedFieldTrait};
use crate::mpc::spdz_group::g1_affine::SpdzSharedG1Affine as SG;
use crate::mpc::spdz_group::group::SpdzSharedAffineTrait;
use crate::mpc::group::g1_affine::SharedG1Affine;
use crate::bp::inner_product_proof_381::custom_msm;

#[derive(Clone, Debug)]
pub struct SharedInnerProductProof {
    pub(crate) L_vec: Vec<SG<G>>,
    pub(crate) R_vec: Vec<SG<G>>,
    pub(crate) a: SF<Fr>,
    pub(crate) b: SF<Fr>,
}

#[allow(clippy::too_many_arguments)]
impl SharedInnerProductProof {

    pub fn create(
        transcript: &mut Transcript,
        Q: SG<G>,
        G_factors: &[SF<Fr>],
        H_factors: &[SF<Fr>],
        mut G_vec: Vec<SG<G>>,
        mut H_vec: Vec<SG<G>>,
        mut a_vec: Vec<SF<Fr>>,
        mut b_vec: Vec<SF<Fr>>,
    ) -> Result<SharedInnerProductProof, MPCError> {
        let G = &mut G_vec[..];
        let H = &mut H_vec[..];
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

        transcript.innerproduct_domain_sep(n as u64);

        let lg_n = n.next_power_of_two().trailing_zeros() as usize;
        let mut L_vec = Vec::with_capacity(lg_n);
        let mut R_vec = Vec::with_capacity(lg_n);

        // If it's the first iteration, unroll the Hprime = H*y_inv scalar multiplications
        // into multiscalar muls, for performance.
        let mut G_res = Vec::with_capacity(n / 2);
        let mut H_res = Vec::with_capacity(n / 2);
        if n != 1 {
            n /= 2;
            let (a_L, a_R) = a.split_at_mut(n);
            let (b_L, b_R) = b.split_at_mut(n);
            let (G_L, G_R) = G.split_at_mut(n);
            let (H_L, H_R) = H.split_at_mut(n);

            let c_L = shared_inner_product(a_L, b_R);
            let c_R = shared_inner_product(a_R, b_L);

            let scalars = a_L.iter()
                .zip(G_factors[n..2 * n].iter())
                .map(|(a_L_i, g)| *a_L_i * g)
                .chain(
                    b_R.iter()
                        .zip(H_factors[0..n].iter())
                        .map(|(b_R_i, h)| *b_R_i * h),
                );
            let bases = G_R.iter().chain(H_L.iter()).copied();

            // TODO: replace this with call to msm
            let mut acc = SG::zero();

            for (base, scalar) in bases.zip(scalars) {
                acc = (acc + base.mul(scalar)).into_affine();
            }

            let L = acc.clone();

            let scalars = a_R.iter()
                .zip(G_factors[0..n].iter())
                .map(|(a_R_i, g)| *a_R_i * g)
                .chain(
                    b_L.iter()
                        .zip(H_factors[n..2 * n].iter())
                        .map(|(b_L_i, h)| *b_L_i * h),
                );
            let bases = G_L.iter().chain(H_R.iter()).copied();

            // TODO: replace this with call to msm
            let mut acc = SG::zero();

            for (base, scalar) in bases.zip(scalars) {
                acc = (acc + base.mul(scalar)).into_affine();
            }
            let cRQ = (Q*c_R).into_affine();

            let R = (acc.clone()+ cRQ).into_affine();

            let (L_open, R_open) = (L.reveal(), R.reveal());

            transcript.append_point(b"L", &L_open.get_share_group_val());
            transcript.append_point(b"R", &R_open.get_share_group_val());

            L_vec.push(L_open);
            R_vec.push(R_open);

            let u = SF::from_public(transcript.challenge_scalar(b"u"));
            let u_inv = u.inverse().unwrap();

            for i in 0..n {
                a_L[i] = a_L[i] * &u + u_inv * &a_R[i];
                b_L[i] = b_L[i] * &u_inv + u * &b_R[i];

                G_res.push(shared_custom_msm(
                    &[u_inv * &G_factors[i], u * &G_factors[n + i]],
                    &[G_L[i], G_R[i]],
                ));
                H_res.push(shared_custom_msm(
                    &[u * &H_factors[i], u_inv * &H_factors[n + i]],
                    &[H_L[i], H_R[i]],
                ));
            }

            a = a_L;
            b = b_L;
        }

        let mut G_res = &mut G_res[..];
        let mut H_res = &mut H_res[..];
        while n != 1 {
            n /= 2;
            let (a_L, a_R) = a.split_at_mut(n);
            let (b_L, b_R) = b.split_at_mut(n);
            let (G_L, G_R) = G_res.split_at_mut(n);
            let (H_L, H_R) = H_res.split_at_mut(n);

            let c_L = shared_inner_product(a_L, b_R);
            let c_R = shared_inner_product(a_R, b_L);


            let scalars = a_L.iter()
                .chain(b_R.iter())
                .chain(iter::once(&c_L))
                .cloned();
            let bases = G_R.iter().chain(H_L.iter()).chain(iter::once(&Q)).cloned();

            // TODO: replace this with call to msm
            let mut acc = SG::zero();

            for (base, scalar) in bases.zip(scalars) {
                acc = (acc + base.mul(scalar)).into_affine();
            }

            let L = acc.clone();


            let scalars = a_R.iter()
                .chain(b_L.iter())
                .chain(iter::once(&c_R))
                .cloned();
            let bases = G_L.iter().chain(H_R.iter()).chain(iter::once(&Q)).cloned();

            // TODO: replace this with call to msm
            let mut acc = SG::zero();

            for (base, scalar) in bases.zip(scalars) {
                acc = (acc + base.mul(scalar)).into_affine();
            }

            let R = acc.clone();

            let (L_open, R_open) = (L.reveal(), R.reveal());

            transcript.append_point(b"L", &L_open.get_share_group_val());
            transcript.append_point(b"R", &R_open.get_share_group_val());

            L_vec.push(L_open);
            R_vec.push(R_open);

            let u = SF::from_public(transcript.challenge_scalar(b"u"));
            let u_inv = u.inverse().unwrap();

            for i in 0..n {
                a_L[i] = a_L[i] * &u + u_inv * &a_R[i];
                b_L[i] = b_L[i] * &u_inv + u * &b_R[i];

                G_L[i] = shared_custom_msm(
                    &[u_inv.clone(), u.clone()],
                    &[G_L[i].clone(), G_R[i].clone()],
                );
                H_L[i] = shared_custom_msm(
                    &[u.clone(), u_inv.clone()],
                    &[H_L[i].clone(), H_R[i].clone()],
                );
            }

            a = a_L;
            b = b_L;
            G_res = G_L;
            H_res = H_L;
        }

        Ok(SharedInnerProductProof {
            L_vec,
            R_vec,
            a: a[0].clone(),
            b: b[0].clone(),
        })
    }

    pub fn reveal(&self) -> Result<InnerProductProof, MPCError> {

        let a = self
            .a
            .reveal().get_share_field_val();

        let b = self
            .b
            .reveal().get_share_field_val();

        let L_vec =
            self.L_vec.iter().cloned()
                .map(|l|SpdzSharedAffineTrait::reveal(l).get_share_group_val())
                .collect();
        let R_vec =
            self.R_vec.iter().cloned()
            .map(|l|SpdzSharedAffineTrait::reveal(l).get_share_group_val())
            .collect();

        Ok(InnerProductProof { L_vec, R_vec, a, b })
    }
}

/// Computes an inner product of two vectors
/// \\[
///    {\langle {\mathbf{a}}, {\mathbf{b}} \rangle} = \sum\_{i=0}^{n-1} a\_i \cdot b\_i.
/// \\]
/// Panics if the lengths of \\(\mathbf{a}\\) and \\(\mathbf{b}\\) are not equal.
pub fn inner_product(a: &[Fr], b: &[Fr]) -> Fr {
    let mut out = Fr::zero();
    if a.len() != b.len() {
        panic!("inner_product(a,b): lengths of vectors do not match");
    }
    for i in 0..a.len() {
        out += a[i] * b[i];
    }
    out
}

pub fn shared_inner_product(
    a: &[SF<Fr>],
    b: &[SF<Fr>],
) -> SF<Fr> {
    let mut out = SF::zero();
    if a.len() != b.len() {
        panic!("inner_product(a,b): lengths of vectors do not match");
    }
    for i in 0..a.len() {
        out = out + a[i] * &b[i];
    }
    out
}

pub fn shared_custom_msm( scalars: &[SF<Fr>], bases: &[SG<G>]) -> SG<G> {
    assert_eq!(bases.len(), scalars.len());

    let mut acc = SG::zero();

    for (base, scalar) in bases.iter().zip(scalars.iter()) {
        acc = (acc + base.mul(*scalar)).into_affine();
    }
    acc
}
