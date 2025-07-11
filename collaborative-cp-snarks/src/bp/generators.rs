//! The `generators` module contains API for producing a
//! set of generators
//! generic generators
#![allow(non_snake_case)]

extern crate alloc;

use alloc::vec::Vec;
use std::marker::PhantomData;
use ark_ec::{AffineRepr, Group, CurveConfig, CurveGroup,};
use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField};
use ark_std::{
    rand::{prelude::StdRng, RngCore, SeedableRng},
    UniformRand,
};

/// Represents a pair of base points for Pedersen commitments.
///
/// The Bulletproofs implementation and API is designed to support
/// pluggable bases for Pedersen commitments, so that the choice of
/// bases is not hard-coded.
///
/// The default generators are:
///
/// * `B`: the `ristretto255` basepoint;
/// * `B_blinding`: the result of `ristretto255` SHA3-512
/// hash-to-group on input `B_bytes`.
#[derive(Copy, Clone)]
pub struct PedersenGens<G: Group> {
    /// Base for the committed value
    pub B: G,
    /// Base for the blinding factor
    pub B_blinding: G,
}

impl<G: Group> PedersenGens<G> {
    /// Creates a Pedersen commitment using the value scalar and a blinding factor.
    pub fn commit(&self, value: G::ScalarField, blinding: G::ScalarField) -> G {
        self.B * value + self.B_blinding * blinding
    }
}
//TODO: change default() to generator()
impl<G: Group> Default for PedersenGens<G> {
    fn default() -> Self {
        PedersenGens {
            B: G::default(),
            B_blinding: G::default(),
        }
    }
}

/// The `GeneratorsChain` creates an arbitrary-long sequence of
/// orthogonal generators.  The sequence can be deterministically
/// produced starting with an arbitrary point.
struct GeneratorsChain<G: Group> {
    seed: u64,
    _elem: PhantomData<G>,
}

impl<G: Group> GeneratorsChain<G> {
    /// Creates a chain of generators, determined by the hash of `label`.
    fn new(label: u64) -> Self {
        GeneratorsChain {
            seed: label,
            _elem: Default::default(),
        }
    }
}

impl<G:Group> Default for GeneratorsChain<G> {
    fn default() -> Self {
        Self::new(0u64)
    }
}

impl<G:Group> Iterator for GeneratorsChain<G> {
    type Item = G;

    fn next(&mut self) -> Option<Self::Item> {
        //FIXME: not safe
        let mut rng = StdRng::seed_from_u64(self.seed);
        let s = G::ScalarField::rand(&mut rng);

        Some(G::generator()*s)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (usize::max_value(), None)
    }
}

/// The `BulletproofGens` struct contains all the generators needed
/// for aggregating up to `m` range proofs of up to `n` bits each.
///
/// # Extensible Generator Generation
///
/// Instead of constructing a single vector of size `m*n`, as
/// described in the Bulletproofs paper, we construct each party's
/// generators separately.
///
/// To construct an arbitrary-length chain of generators, we apply
/// SHAKE256 to a domain separator label, and feed each 64 bytes of
/// XOF output into the `ristretto255` hash-to-group function.
/// Each of the `m` parties' generators are constructed using a
/// different domain separation label, and proving and verification
/// uses the first `n` elements of the arbitrary-length chain.
///
/// This means that the aggregation size (number of
/// parties) is orthogonal to the rangeproof size (number of bits),
/// and allows using the same `BulletproofGens` object for different
/// proving parameters.
///
/// This construction is also forward-compatible with constraint
/// system proofs, which use a much larger slice of the generator
/// chain, and even forward-compatible to multiparty aggregation of
/// constraint system proofs, since the generators are namespaced by
/// their party index.
#[derive(Clone)]
pub struct BulletproofGens<G:Group> {
    /// The maximum number of usable generators for each party.
    pub gens_capacity: usize,
    /// Number of values or parties
    pub party_capacity: usize,
    /// Precomputed \\(\mathbf G\\) generators for each party.
    pub G_vec: Vec<Vec<G>>,
    /// Precomputed \\(\mathbf H\\) generators for each party.
    pub H_vec: Vec<Vec<G>>,
}

impl<G:Group> BulletproofGens<G> {
    /// Create a new `BulletproofGens` object.
    ///
    /// # Inputs
    ///
    /// * `gens_capacity` is the number of generators to precompute
    ///    for each party.  For rangeproofs, it is sufficient to pass
    ///    `64`, the maximum bitsize of the rangeproofs.  For circuit
    ///    proofs, the capacity must be greater than the number of
    ///    multipliers, rounded up to the next power of two.
    ///
    /// * `party_capacity` is the maximum number of parties that can
    ///    produce an aggregated proof.
    pub fn new(gens_capacity: usize, party_capacity: usize) -> Self {
        let mut gens = BulletproofGens {
            gens_capacity: 0,
            party_capacity,
            G_vec: (0..party_capacity).map(|_| Vec::new()).collect(),
            H_vec: (0..party_capacity).map(|_| Vec::new()).collect(),
        };
        gens.increase_capacity(gens_capacity);
        gens
    }

    /// Returns j-th share of generators, with an appropriate
    /// slice of vectors G and H for the j-th range proof.
    pub fn share(&self, j: usize) -> BulletproofGensShare<'_, G> {
        BulletproofGensShare {
            gens: &self,
            share: j,
        }
    }

    /// Increases the generators' capacity to the amount specified.
    /// If less than or equal to the current capacity, does nothing.
    pub fn increase_capacity(&mut self, new_capacity: usize) {
        use byteorder::{ByteOrder, LittleEndian};

        if self.gens_capacity >= new_capacity {
            return;
        }

        for i in 0..self.party_capacity {
            let party_index = i as u64;
            // let mut label = [b'G', 0, 0, 0, 0];
            // LittleEndian::write_u32(&mut label[1..5], party_index);
            self.G_vec[i].extend(
                &mut GeneratorsChain::<G>::new(party_index)
                    // .fast_forward(self.gens_capacity)
                    .take(new_capacity - self.gens_capacity),
            );

            // label[0] = b'H';
            self.H_vec[i].extend(
                &mut GeneratorsChain::<G>::new(party_index)
                    // .fast_forward(self.gens_capacity)
                    .take(new_capacity - self.gens_capacity),
            );
        }
        self.gens_capacity = new_capacity;
    }

    /// Return an iterator over the aggregation of the parties' G generators with given size `n`.
    pub(crate) fn G(&self, n: usize, m: usize) -> impl Iterator<Item = &G> {
        AggregatedGensIter {
            n,
            m,
            array: &self.G_vec,
            party_idx: 0,
            gen_idx: 0,
        }
    }

    /// Return an iterator over the aggregation of the parties' H generators with given size `n`.
    pub(crate) fn H(&self, n: usize, m: usize) -> impl Iterator<Item = &G> {
        AggregatedGensIter {
            n,
            m,
            array: &self.H_vec,
            party_idx: 0,
            gen_idx: 0,
        }
    }
}

struct AggregatedGensIter<'a, G:Group> {
    array: &'a Vec<Vec<G>>,
    n: usize,
    m: usize,
    party_idx: usize,
    gen_idx: usize,
}

impl<'a, G:Group> Iterator for AggregatedGensIter<'a, G> {
    type Item = &'a G;

    fn next(&mut self) -> Option<Self::Item> {
        if self.gen_idx >= self.n {
            self.gen_idx = 0;
            self.party_idx += 1;
        }

        if self.party_idx >= self.m {
            None
        } else {
            let cur_gen = self.gen_idx;
            self.gen_idx += 1;
            Some(&self.array[self.party_idx][cur_gen])
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let size = self.n * (self.m - self.party_idx) - self.gen_idx;
        (size, Some(size))
    }
}

/// Represents a view of the generators used by a specific party in an
/// aggregated proof.
///
/// The `BulletproofGens` struct represents generators for an aggregated
/// range proof `m` proofs of `n` bits each; the `BulletproofGensShare`
/// provides a view of the generators for one of the `m` parties' shares.
///
/// The `BulletproofGensShare` is produced by [`BulletproofGens::share()`].
#[derive(Copy, Clone)]
pub struct BulletproofGensShare<'a, G:Group> {
    /// The parent object that this is a view into
    gens: &'a BulletproofGens<G>,
    /// Which share we are
    share: usize,
}

impl<'a, G:Group> BulletproofGensShare<'a, G> {
    /// Return an iterator over this party's G generators with given size `n`.
    pub fn G(&self, n: usize) -> impl Iterator<Item = &'a G> {
        self.gens.G_vec[self.share].iter().take(n)
    }

    /// Return an iterator over this party's H generators with given size `n`.
    pub(crate) fn H(&self, n: usize) -> impl Iterator<Item = &'a G> {
        self.gens.H_vec[self.share].iter().take(n)
    }
}

#[cfg(test)]
mod tests {
    // use collaborative_cp_snarks::mpc381::spdz_group::g1::SpdzSharedG1;
    // use collaborative_cp_snarks::mpc381::spdz_group::group::SpdzSharedGroupTrait;
    use crate::mpc::spdz_pairing::{MpcPairing, MpcPairingTrait};
    use super::*;

    #[test]
    fn aggregated_gens_iter_matches_flat_map() {
        let gens = BulletproofGens::new(64, 8);

        type G = ark_bls12_381::G1Projective;
        let helper = |n: usize, m: usize| {
            let agg_G: Vec<G> = gens.G(n, m).cloned().collect();
            let flat_G: Vec<G> = gens
                .G_vec
                .iter()
                .take(m)
                .flat_map(move |G_j| G_j.iter().take(n))
                .cloned()
                .collect();

            let agg_H: Vec<G> = gens.H(n, m).cloned().collect();
            let flat_H: Vec<G> = gens
                .H_vec
                .iter()
                .take(m)
                .flat_map(move |H_j| H_j.iter().take(n))
                .cloned()
                .collect();

            assert_eq!(agg_G, flat_G);
            assert_eq!(agg_H, flat_H);
        };

        helper(64, 8);
        helper(64, 4);
        helper(64, 2);
        helper(64, 1);
        helper(32, 8);
        helper(32, 4);
        helper(32, 2);
        helper(32, 1);
        helper(16, 8);
        helper(16, 4);
        helper(16, 2);
        helper(16, 1);
    }

    #[test]
    fn resizing_small_gens_matches_creating_bigger_gens() {
        let gens = BulletproofGens::new(64, 8);
        type G = ark_bls12_381::G1Projective;

        let mut gen_resized = BulletproofGens::new(32, 8);
        gen_resized.increase_capacity(64);

        let helper = |n: usize, m: usize| {
            let gens_G: Vec<G> = gens.G(n, m).cloned().collect();
            let gens_H: Vec<G> = gens.H(n, m).cloned().collect();

            let resized_G: Vec<G> = gen_resized.G(n, m).cloned().collect();
            let resized_H: Vec<G> = gen_resized.H(n, m).cloned().collect();

            assert_eq!(gens_G, resized_G);
            assert_eq!(gens_H, resized_H);
        };

        helper(64, 8);
        helper(32, 8);
        helper(16, 8);
    }

    #[test]
    fn mpc_aggregated_gens_iter_matches_flat_map() {
        let gens = BulletproofGens::new(64, 8);

        type B = ark_bls12_381::Bls12_381;
        type P = MpcPairing<B>;
        type EG = <B as Pairing>::G1;

        let helper = |n: usize, m: usize| {
            let agg_G: Vec<EG> = gens.G(n, m).cloned().collect();
            let flat_G: Vec<EG> = gens
                .G_vec
                .iter()
                .take(m)
                .flat_map(move |G_j| G_j.iter().take(n))
                .cloned()
                .collect();

            let agg_H: Vec<EG> = gens.H(n, m).cloned().collect();
            let flat_H: Vec<EG> = gens
                .H_vec
                .iter()
                .take(m)
                .flat_map(move |H_j| H_j.iter().take(n))
                .cloned()
                .collect();

            assert_eq!(agg_G, flat_G);
            assert_eq!(agg_H, flat_H);
        };

        helper(64, 8);
        helper(64, 4);
        helper(64, 2);
        helper(64, 1);
        helper(32, 8);
        helper(32, 4);
        helper(32, 2);
        helper(32, 1);
        helper(16, 8);
        helper(16, 4);
        helper(16, 2);
        helper(16, 1);
    }

    #[test]
    fn mpc_resizing_small_gens_matches_creating_bigger_gens() {
        let gens = BulletproofGens::new(64, 8);
        type G = ark_bls12_381::G1Projective;
        let mut gen_resized = BulletproofGens::new(32, 8);
        gen_resized.increase_capacity(64);

        let helper = |n: usize, m: usize| {
            let gens_G: Vec<G> = gens.G(n, m).cloned().collect();
            let gens_H: Vec<G> = gens.H(n, m).cloned().collect();

            let resized_G: Vec<G> = gen_resized.G(n, m).cloned().collect();
            let resized_H: Vec<G> = gen_resized.H(n, m).cloned().collect();

            assert_eq!(gens_G, resized_G);
            assert_eq!(gens_H, resized_H);
        };

        helper(64, 8);
        helper(32, 8);
        helper(16, 8);
    }
}
