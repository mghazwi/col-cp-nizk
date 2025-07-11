// beaver source
use std::marker::PhantomData;
use ark_ec::Group;
use derivative::Derivative;
use crate::globals::{get_party_id, increment_n_s_s_operations};
use crate::mpc::field::SharedFieldTrait;
use ark_ff::{BigInt, FftField, Field, Fp, MontBackend, PrimeField};
use ark_ff::prelude::*;
use crate::mpc::group::group::SharedGroupTrait;
use crate::mpc::spdz_field::SpdzSharedFieldTrait;
use crate::mpc::spdz_group::group::SpdzSharedGroupTrait;

pub trait BeaverSource<A, B, C>: Clone {
    fn triple(&mut self) -> (A, B, C);
    fn triples(&mut self, n: usize) -> (Vec<A>, Vec<B>, Vec<C>) {
        let mut xs = Vec::new();
        let mut ys = Vec::new();
        let mut zs = Vec::new();
        for _ in 0..n {
            let (x, y, z) = self.triple();
            xs.push(x);
            ys.push(y);
            zs.push(z);
        }
        (xs, ys, zs)
    }
    fn inv_pair(&mut self) -> (B, B);
    fn inv_pairs(&mut self, n: usize) -> (Vec<B>, Vec<B>) {
        let mut xs = Vec::new();
        let mut ys = Vec::new();
        for _ in 0..n {
            let (x, y) = self.inv_pair();
            xs.push(x);
            ys.push(y);
        }
        (xs, ys)
    }
}

#[derive(Derivative)]
#[derivative(Default(bound = ""), Clone(bound = ""), Copy(bound = ""))]
pub struct DummyFieldTripleSource<T, S> {
    _scalar: PhantomData<T>,
    _share: PhantomData<S>,
}

impl<T: Field, S: SharedFieldTrait<T>> BeaverSource<S, S, S> for DummyFieldTripleSource<T, S> {

    #[inline]
    fn triple(&mut self) -> (S, S, S) {
        let am_first_party = get_party_id() == 0;
        (S::from_shared(
            if am_first_party {
                T::one()
            } else {
                T::zero()
            }
        ), S::from_shared(
            if am_first_party {
                T::one()
            } else {
                T::zero()
            }
        ), S::from_shared(
            if am_first_party {
                T::one()
            } else {
                T::zero()
            }
        )
        )
    }
    #[inline]
    fn inv_pair(&mut self) -> (S, S) {
        let am_first_party = get_party_id() == 0;
        ( S::from_shared(
            if am_first_party {
                T::one()
            } else {
                T::zero()
            }
        ), S::from_shared(
            if am_first_party {
                T::one()
            } else {
                T::zero()
            }
        )
        )
    }
}

#[derive(Derivative)]
#[derivative(Default(bound = ""), Clone(bound = ""), Copy(bound = ""))]
pub struct DummyGroupTripleSource<T, S> {
    _scalar: PhantomData<T>,
    _share: PhantomData<S>,
}

impl<T: Group, S: SharedGroupTrait<T>> BeaverSource<S, T::ScalarField, S> for DummyGroupTripleSource<T, S> {

    #[inline]
    fn triple(&mut self) -> (S, T::ScalarField, S) {
        let am_first_party = get_party_id() == 0;
        (
            S::zero(),
            if am_first_party {
                T::ScalarField::one()
            } else {
                T::ScalarField::zero()
            },
            S::zero(),
        )
    }
    #[inline]
    fn inv_pair(&mut self) -> (T::ScalarField, T::ScalarField) {
        let am_first_party = get_party_id() == 0;
        (
            if am_first_party {
                T::ScalarField::one()
            } else {
                T::ScalarField::zero()
            },
            if am_first_party {
                T::ScalarField::one()
            } else {
                T::ScalarField::zero()
            },
        )
    }
}

#[derive(Derivative)]
#[derivative(Default(bound = ""), Clone(bound = ""), Copy(bound = ""))]
pub struct DummySpdzFieldTripleSource<T, S> {
    _scalar: PhantomData<T>,
    _share: PhantomData<S>,
}

impl<T: Field, S: SpdzSharedFieldTrait<T>> BeaverSource<S, S, S> for DummySpdzFieldTripleSource<T, S> {

    #[inline]
    fn triple(&mut self) -> (S, S, S) {
        let am_first_party = get_party_id() == 0;
        (S::from_shared(
            if am_first_party {
                T::one()
            } else {
                T::zero()
            }
        ), S::from_shared(
            if am_first_party {
                T::one()
            } else {
                T::zero()
            }
        ), S::from_shared(
            if am_first_party {
                T::one()
            } else {
                T::zero()
            }
        )
        )
    }
    #[inline]
    fn inv_pair(&mut self) -> (S, S) {
        let am_first_party = get_party_id() == 0;
        ( S::from_shared(
            if am_first_party {
                T::one()
            } else {
                T::zero()
            }
        ), S::from_shared(
            if am_first_party {
                T::one()
            } else {
                T::zero()
            }
        )
        )
    }
}

#[derive(Derivative)]
#[derivative(Default(bound = ""), Clone(bound = ""), Copy(bound = ""))]
pub struct DummySpdzGroupTripleSource<T, S> {
    _scalar: PhantomData<T>,
    _share: PhantomData<S>,
}

impl<T: Group, S: SpdzSharedGroupTrait<T>> BeaverSource<S, T::ScalarField, S> for DummySpdzGroupTripleSource<T, S> {

    #[inline]
    fn triple(&mut self) -> (S, T::ScalarField, S) {
        let am_first_party = get_party_id() == 0;
        (
            S::from_shared(T::zero()),
            if am_first_party {
                T::ScalarField::one()
            } else {
                T::ScalarField::zero()
            },
            S::from_shared(T::zero()),
        )
    }
    #[inline]
    fn inv_pair(&mut self) -> (T::ScalarField, T::ScalarField) {
        let am_first_party = get_party_id() == 0;
        (
            if am_first_party {
                T::ScalarField::one()
            } else {
                T::ScalarField::zero()
            },
            if am_first_party {
                T::ScalarField::one()
            } else {
                T::ScalarField::zero()
            },
        )
    }
}

