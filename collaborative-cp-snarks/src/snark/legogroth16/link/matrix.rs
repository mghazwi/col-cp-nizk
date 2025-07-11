use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_std::marker::PhantomData;
use ark_std::ops::{AddAssign, Mul};
use ark_std::vec;
use ark_std::vec::Vec;

use ark_ff::Zero;

use crate::mpc::spdz_pairing::MpcPairingTrait;

/// CoeffPos: A struct to help build sparse matrices.
#[derive(Clone, Debug)]
pub struct CoeffPos<T> {
    val: T,
    pos: usize,
}

// a column is a vector of CoeffPos-s
type Col<T> = Vec<CoeffPos<T>>;

/* TODO: One could consider a cache-friendlier implementation for the 2-row case*/

/// Column-Major Sparse Matrix
#[derive(Clone, Debug)]
pub struct SparseMatrix<T> {
    cols: Vec<Col<T>>, // a vector of columns
    /// Number of rows
    pub nr: usize,
    /// Number of columns
    pub nc: usize,
}

impl<T: Copy> SparseMatrix<T> {
    /// NB: Given column by column
    pub fn new(nr: usize, nc: usize) -> SparseMatrix<T> {
        SparseMatrix {
            cols: vec![vec![]; nc],
            nr,
            nc,
        }
    }

    /// Insert a value at row r and column c
    pub fn insert_val(&mut self, r: usize, c: usize, v: &T) {
        let coeff_pos = CoeffPos { pos: r, val: *v };
        self.cols[c].push(coeff_pos);
    }

    /// insert a continuous sequence of values at row r starting from c_offset
    pub fn insert_row_slice(&mut self, r: usize, c_offset: usize, vs: &[T]) {
        // NB: could be improved in efficiency by first extending the vector
        for (i, x) in vs.iter().enumerate() {
            self.insert_val(r, c_offset + i, x);
        }
    }

    /// get the column c
    pub fn get_col(&self, c: usize) -> &Col<T> {
        &self.cols[c]
    }
}

/// Sparse linear algebra
pub struct SparseLinAlgebra<B, P>
    where
        B: Pairing,
        P: MpcPairingTrait<B>,
{
    pairing_engine_type: PhantomData<(B, P)>,
}

impl<B, P> SparseLinAlgebra<B, P>
    where
        B: Pairing,
        P: MpcPairingTrait<B>,
{
    /// this is basically a multi-exp
    pub fn sparse_inner_product(
        v: &Vec<<P as MpcPairingTrait<B>>::ScalarField>,
        w: &Col<<P as MpcPairingTrait<B>>::G1Affine>,
    ) -> <P as MpcPairingTrait<B>>::G1Affine {
        let mut res: <P as MpcPairingTrait<B>>::G1 = <P as MpcPairingTrait<B>>::G1::zero();
        for coeffpos in w {
            let g = coeffpos.val;
            let i = coeffpos.pos;
            // XXX: Should this be optimized for special cases
            //         (e.g. 0 or 1) or is this already in .mul?
            let tmp = g.mul(v[i]);

            res.add_assign(&tmp);
        }
        res.into_affine()
    }

    /// Vector matrix multiplication
    pub fn sparse_vector_matrix_mult(
        v: &Vec<<P as MpcPairingTrait<B>>::ScalarField>,
        m: &SparseMatrix<<P as MpcPairingTrait<B>>::G1Affine>,
        t: usize,
    ) -> Vec<<P as MpcPairingTrait<B>>::G1Affine> {
        // the result should contain every column of m multiplied by v
        let mut res: Vec<<P as MpcPairingTrait<B>>::G1Affine> = Vec::with_capacity(t);
        for c in 0..m.nc {
            res.push(Self::sparse_inner_product(&v, &m.get_col(c)));
        }
        res
    }
}

/// Matrix multiplication
pub fn inner_product<B, P>(
    v: &[<P as MpcPairingTrait<B>>::ScalarField],
    w: &[<P as MpcPairingTrait<B>>::G1Affine],
) -> <P as MpcPairingTrait<B>>::G1Affine
    where
        B: Pairing,
        P: MpcPairingTrait<B>,
{
    assert_eq!(v.len(), w.len());
    let mut res: <P as MpcPairingTrait<B>>::G1 = <P as MpcPairingTrait<B>>::G1::zero();
    for i in 0..v.len() {
        let tmp = w[i].mul(v[i]);
        res.add_assign(&tmp);
    }
    res.into_affine()
}

/// Matrix multiplication
pub fn scalar_vector_mult<B, P>(
    a: &<P as MpcPairingTrait<B>>::ScalarField,
    v: &[<P as MpcPairingTrait<B>>::ScalarField],
    l: usize,
) -> Vec<<P as MpcPairingTrait<B>>::ScalarField>
    where
        B: Pairing,
        P: MpcPairingTrait<B>,
{
    let mut res: Vec<<P as MpcPairingTrait<B>>::ScalarField> = Vec::with_capacity(l);
    for i in 0..v.len() {
        let x: <P as MpcPairingTrait<B>>::ScalarField = a.mul(&v[i]);
        res.push(x);
    }
    res
}
