#![allow(non_snake_case)]
extern crate alloc;
use ark_ec::{AffineRepr, Group, CurveConfig, CurveGroup,};
use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField};
use ark_std::{
    rand::{prelude::StdRng, RngCore, SeedableRng},
    UniformRand,
};
use ark_std::{One, Zero};
use alloc::vec;
use alloc::vec::Vec;
use std::time::Instant;
use ark_bls12_381::Fr;

use super::inner_product_proof::inner_product;

/// Represents a degree-1 vector polynomial \\(\mathbf{a} + \mathbf{b} \cdot x\\).
pub struct VecPoly1<F:Field>(pub Vec<F>, pub Vec<F>);

/// Represents a degree-3 vector polynomial
/// \\(\mathbf{a} + \mathbf{b} \cdot x + \mathbf{c} \cdot x^2 + \mathbf{d} \cdot x^3 \\).
pub struct VecPoly3<F:Field>(
    pub Vec<F>,
    pub Vec<F>,
    pub Vec<F>,
    pub Vec<F>,
);

/// Represents a degree-2 scalar polynomial \\(a + b \cdot x + c \cdot x^2\\)
pub struct Poly2<F:Field>(pub F, pub F, pub F);

/// Represents a degree-6 scalar polynomial, without the zeroth degree
/// \\(a \cdot x + b \cdot x^2 + c \cdot x^3 + d \cdot x^4 + e \cdot x^5 + f \cdot x^6\\)
pub struct Poly6<F:Field> {
    pub t1: F,
    pub t2: F,
    pub t3: F,
    pub t4: F,
    pub t5: F,
    pub t6: F,
}

/// Provides an iterator over the powers of a `Scalar`.
///
/// This struct is created by the `exp_iter` function.
pub struct ScalarExp<F: Field> {
    x: F,
    next_exp_x: F,
}

impl<F: Field> Iterator for ScalarExp<F> {
    type Item = F;

    fn next(&mut self) -> Option<F> {
        let exp_x = self.next_exp_x;
        self.next_exp_x *= self.x;
        Some(exp_x)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (usize::max_value(), None)
    }
}

/// Return an iterator of the powers of `x`.
pub fn exp_iter<F: Field>(x: F) -> ScalarExp<F> {
    let next_exp_x = F::one();
    ScalarExp { x, next_exp_x }
}

pub fn add_vec<F:Field>(a: &[F], b: &[F]) -> Vec<F> {
    if a.len() != b.len() {
        // throw some error
        //println!("lengths of vectors don't match for vector addition");
    }
    let mut out = vec![F::zero(); b.len()];
    for i in 0..a.len() {
        out[i] = a[i] + b[i];
    }
    out
}

impl<F:Field> VecPoly1<F> {
    pub fn zero(n: usize) -> Self {
        VecPoly1(vec![F::zero(); n], vec![F::zero(); n])
    }

    pub fn inner_product(&self, rhs: &VecPoly1<F>) -> Poly2<F> {
        // Uses Karatsuba's method
        let l = self;
        let r = rhs;

        let t0 = inner_product(&l.0, &r.0);
        let t2 = inner_product(&l.1, &r.1);

        let l0_plus_l1 = add_vec(&l.0, &l.1);
        let r0_plus_r1 = add_vec(&r.0, &r.1);

        let t1 = inner_product(&l0_plus_l1, &r0_plus_r1) - t0 - t2;

        Poly2(t0, t1, t2)
    }

    pub fn eval(&self, x: F) -> Vec<F> {
        let n = self.0.len();
        let mut out = vec![F::zero(); n];
        for i in 0..n {
            out[i] = self.0[i] + self.1[i] * x;
        }
        out
    }
}

impl<F:Field> VecPoly3<F> {
    pub fn zero(n: usize) -> Self {
        VecPoly3(
            vec![F::zero(); n],
            vec![F::zero(); n],
            vec![F::zero(); n],
            vec![F::zero(); n],
        )
    }

    /// Compute an inner product of `lhs`, `rhs` which have the property that:
    /// - `lhs.0` is zero;
    /// - `rhs.2` is zero;
    /// This is the case in the constraint system proof.
    pub fn special_inner_product(lhs: &Self, rhs: &Self) -> Poly6<F> {

        let t1 = inner_product(&lhs.1, &rhs.0);
        let t2 = inner_product(&lhs.1, &rhs.1) + inner_product(&lhs.2, &rhs.0);
        let t3 = inner_product(&lhs.2, &rhs.1) + inner_product(&lhs.3, &rhs.0);
        let t4 = inner_product(&lhs.1, &rhs.3) + inner_product(&lhs.3, &rhs.1);
        let t5 = inner_product(&lhs.2, &rhs.3);
        let t6 = inner_product(&lhs.3, &rhs.3);

        Poly6 {
            t1,
            t2,
            t3,
            t4,
            t5,
            t6,
        }
    }

    pub fn eval(&self, x: F) -> Vec<F> {
        let n = self.0.len();
        let mut out = vec![F::zero(); n];
        for i in 0..n {
            out[i] = self.0[i] + x * (self.1[i] + x * (self.2[i] + x * self.3[i]));
        }
        out
    }
}

impl<F:Field> Poly2<F> {
    pub fn eval(&self, x: F) -> F {
        self.0 + x * (self.1 + x * self.2)
    }
}

impl<F:Field> Poly6<F> {
    pub fn eval(&self, x: F) -> F {
        x * (self.t1 + x * (self.t2 + x * (self.t3 + x * (self.t4 + x * (self.t5 + x * self.t6)))))
    }
}

/// Return a result that is the exponentiation chain of the result `x` to the power `n`
pub fn exp_iter_result<F:Field>(x: F, n: usize) -> Vec<F> {
    let mut res = Vec::with_capacity(n);
    res.push(F::one());

    let mut curr_exp = x.clone();
    for _ in 1..n {
        res.push(curr_exp.clone());
        curr_exp = curr_exp * &x;
    }

    res
}

/// Raises `x` to the power `n` using binary exponentiation,
/// with (1 to 2)*lg(n) scalar multiplications.
/// TODO: a consttime version of this would be awfully similar to a Montgomery ladder.
pub fn scalar_exp_vartime<F: Field>(x: &F, mut n: u64) -> F {
    let mut result = F::one();
    let mut aux = *x; // x, x^2, x^4, x^8, ...
    while n > 0 {
        let bit = n & 1;
        if bit == 1 {
            result = result * aux;
        }
        n = n >> 1;
        aux = aux * aux; // FIXME: one unnecessary mult at the last step here!
    }
    result
}
//
/// Takes the sum of all the powers of `x`, up to `n`
/// If `n` is a power of 2, it uses the efficient algorithm with `2*lg n` multiplications and additions.
/// If `n` is not a power of 2, it uses the slow algorithm with `n` multiplications and additions.
/// In the Bulletproofs case, all calls to `sum_of_powers` should have `n` as a power of 2.
pub fn sum_of_powers<F: Field>(x: &F, n: usize) -> F {
    if !n.is_power_of_two() {
        return sum_of_powers_slow::<F>(x, n);
    }
    if n == 0 || n == 1 {
        return F::from(n as u64);
    }
    let mut m = n;
    let mut result = F::one() + x;
    let mut factor = *x;
    while m > 2 {
        factor = factor * factor;
        result = result + factor * result;
        m = m / 2;
    }
    result
}

// takes the sum of all of the powers of x, up to n
fn sum_of_powers_slow<F: Field>(x: &F, n: usize) -> F {
    exp_iter(*x).take(n).sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;

    #[test]
    fn exp_2_is_powers_of_2() {
        let exp_2: Vec<_> = exp_iter(Fr::from(2u64)).take(4).collect();

        assert_eq!(exp_2[0], Fr::from(1u64));
        assert_eq!(exp_2[1], Fr::from(2u64));
        assert_eq!(exp_2[2], Fr::from(4u64));
        assert_eq!(exp_2[3], Fr::from(8u64));
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

    /// Raises `x` to the power `n`.
    fn scalar_exp_vartime_slow<F: Field>(x: &F, n: u64) -> F {
        let mut result = F::one();
        for _ in 0..n {
            result = result * x;
        }
        result
    }

    #[test]
    fn test_sum_of_powers() {
        let x = Fr::from(10u64);
        assert_eq!(sum_of_powers_slow(&x, 0), sum_of_powers(&x, 0));
        assert_eq!(sum_of_powers_slow(&x, 1), sum_of_powers(&x, 1));
        assert_eq!(sum_of_powers_slow(&x, 2), sum_of_powers(&x, 2));
        assert_eq!(sum_of_powers_slow(&x, 4), sum_of_powers(&x, 4));
        assert_eq!(sum_of_powers_slow(&x, 8), sum_of_powers(&x, 8));
        assert_eq!(sum_of_powers_slow(&x, 16), sum_of_powers(&x, 16));
        assert_eq!(sum_of_powers_slow(&x, 32), sum_of_powers(&x, 32));
        assert_eq!(sum_of_powers_slow(&x, 64), sum_of_powers(&x, 64));
    }

    #[test]
    fn test_sum_of_powers_slow() {
        let x = Fr::from(10u64);
        assert_eq!(sum_of_powers_slow(&x, 0), Fr::zero());
        assert_eq!(sum_of_powers_slow(&x, 1), Fr::one());
        assert_eq!(sum_of_powers_slow(&x, 2), Fr::from(11u64));
        assert_eq!(sum_of_powers_slow(&x, 3), Fr::from(111u64));
        assert_eq!(sum_of_powers_slow(&x, 4), Fr::from(1111u64));
        assert_eq!(sum_of_powers_slow(&x, 5), Fr::from(11111u64));
        assert_eq!(sum_of_powers_slow(&x, 6), Fr::from(111111u64));
    }
}
