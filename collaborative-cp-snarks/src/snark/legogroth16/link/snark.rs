use core::ops::{Mul, Neg};

use crate::mpc::spdz_pairing::MpcPairingTrait;
use crate::snark::legogroth16::link::matrix::*;
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};

use ark_ff::{One, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use ark_std::{marker::PhantomData, rand::Rng, vec, vec::Vec};

use super::{SparseLinAlgebra, SparseMatrix};

/// Configuration for proof
#[derive(Clone, Default, PartialEq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PP<
    G1: Clone + Default + CanonicalSerialize + CanonicalDeserialize,
    G2: Clone + Default + CanonicalSerialize + CanonicalDeserialize,
> {
    /// # of rows
    pub l: usize,
    /// # of cols
    pub t: usize,
    /// G1 element
    pub g1: G1,
    /// G2 element
    pub g2: G2,
}

impl<
    G1: Clone + Default + CanonicalSerialize + CanonicalDeserialize,
    G2: Clone + Default + CanonicalSerialize + CanonicalDeserialize,
> PP<G1, G2>
{
    /// Create a new PP
    pub fn new(l: usize, t: usize, g1: &G1, g2: &G2) -> PP<G1, G2> {
        PP {
            l,
            t,
            g1: g1.clone(),
            g2: g2.clone(),
        }
    }
}

/// Proving key
#[derive(Clone, Default, PartialEq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SubspaceSnarkProvingKey<G1: Clone + Default + CanonicalSerialize + CanonicalDeserialize>
{
    ///
    pub p: Vec<G1>,
}

#[derive(Clone, Default, PartialEq, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SubspaceSnarkVerificationKey<
    G2: Clone + Default + CanonicalSerialize + CanonicalDeserialize,
> {
    pub c: Vec<G2>,
    pub a: G2,
}

pub trait SubspaceSnark {
    type KMtx;
    type InVec;
    type OutVec;

    type PP;

    type EK;
    type VK;

    type Proof;

    fn keygen<R: Rng>(rng: &mut R, pp: &Self::PP, m: Self::KMtx) -> (Self::EK, Self::VK);
    fn prove(pp: &Self::PP, ek: &Self::EK, x: &[Self::InVec]) -> Self::Proof;
    fn verify(pp: &Self::PP, vk: &Self::VK, y: &[Self::OutVec], pi: &Self::Proof) -> bool;
}

fn vec_to_g2<B, P>(
    pp: &PP<<P as MpcPairingTrait<B>>::G1Affine, <P as MpcPairingTrait<B>>::G2Affine>,
    v: &Vec<<P as MpcPairingTrait<B>>::ScalarField>,
) -> Vec<<P as MpcPairingTrait<B>>::G2Affine>
    where
        B: Pairing,
        P: MpcPairingTrait<B>,
{
    v.iter()
        .map(|x| pp.g2.mul(*x).into_affine())
        .collect::<Vec<_>>()
}

pub struct PESubspaceSnark<B, P>
    where
        B: Pairing,
        P: MpcPairingTrait<B>,
{
    pairing_engine_type: PhantomData<(B, P)>,
}

// NB: Now the system is for y = Mx
impl<B, P> SubspaceSnark for PESubspaceSnark<B, P>
    where
        B: Pairing,
        P: MpcPairingTrait<B>,
{
    type KMtx = SparseMatrix<<P as MpcPairingTrait<B>>::G1Affine>;
    type InVec = <P as MpcPairingTrait<B>>::ScalarField;
    type OutVec = <P as MpcPairingTrait<B>>::G1Affine;

    type PP = PP<<P as MpcPairingTrait<B>>::G1Affine, <P as MpcPairingTrait<B>>::G2Affine>;

    type EK = SubspaceSnarkProvingKey<<P as MpcPairingTrait<B>>::G1Affine>;
    type VK = SubspaceSnarkVerificationKey<<P as MpcPairingTrait<B>>::G2Affine>;

    type Proof = <P as MpcPairingTrait<B>>::G1Affine;

    fn keygen<R: Rng>(rng: &mut R, pp: &Self::PP, m: Self::KMtx) -> (Self::EK, Self::VK) {
        let mut k: Vec<<P as MpcPairingTrait<B>>::ScalarField> = Vec::with_capacity(pp.l);
        for _ in 0..pp.l {
            k.push(<P as MpcPairingTrait<B>>::ScalarField::rand(rng));
        }

        let a = <P as MpcPairingTrait<B>>::ScalarField::rand(rng);

        let p = SparseLinAlgebra::<B, P>::sparse_vector_matrix_mult(&k, &m, pp.t);

        let c = scalar_vector_mult::<B, P>(&a, &k, pp.l);
        let ek = SubspaceSnarkProvingKey::<<P as MpcPairingTrait<B>>::G1Affine> { p };
        let vk = SubspaceSnarkVerificationKey::<<P as MpcPairingTrait<B>>::G2Affine> {
            c: vec_to_g2::<B, P>(pp, &c),
            a: pp.g2.mul(a).into_affine(),
        };
        (ek, vk)
    }

    fn prove(pp: &Self::PP, ek: &Self::EK, x: &[Self::InVec]) -> Self::Proof {
        assert_eq!(pp.t, x.len());
        inner_product::<B, P>(x, &ek.p)
    }

    fn verify(pp: &Self::PP, vk: &Self::VK, y: &[Self::OutVec], pi: &Self::Proof) -> bool {
        assert_eq!(pp.l, y.len());

        // check that [x]1T · [C]2 = [π]1 · [a]2

        let mut g1_elements = vec![];
        let mut g2_elements = vec![];

        for i in 0..y.len() {
            g1_elements.push(<P as MpcPairingTrait<B>>::G1Prepared::from(y[i]));
            g2_elements.push(<P as MpcPairingTrait<B>>::G2Prepared::from(vk.c[i]));
        }

        g1_elements.push(<P as MpcPairingTrait<B>>::G1Prepared::from(*pi));
        g2_elements.push(<P as MpcPairingTrait<B>>::G2Prepared::from(
            vk.a.into_group().neg().into_affine(),
        ));

        let lhs = <P as MpcPairingTrait<B>>::TargetField::one();
        let rhs = <P as MpcPairingTrait<B>>::my_multi_pairing(g1_elements, g2_elements);

        // take two references to element iterators instead of an iterator of tuples.

        lhs == rhs
    }
}
