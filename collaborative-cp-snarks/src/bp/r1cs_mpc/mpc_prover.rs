//! Groups definitions for the MPC prover

use core::{borrow::BorrowMut, iter};
use std::ops::Mul;
use std::time::Instant;

use crate::bp::{errors::{MPCError, R1CSError}, transcript_381::TranscriptProtocol, util, ProofError};
use super::mpc_generators::{PedersenGens, BulletproofGens};
use itertools::Itertools;
use merlin::Transcript;

use ark_bls12_381::Fr;
use ark_bls12_381::Bls12_381 as P;
use ark_bls12_381::G1Affine as GA;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, One, Zero};

use crate::mpc::spdz_field::{SpdzSharedField as SF, SpdzSharedFieldTrait};
use crate::mpc::spdz_group::g1_affine::SpdzSharedG1Affine as SG;
use crate::mpc::spdz_group::group::SpdzSharedAffineTrait;
use super::{
    mpc_constraint_system::{
        ConstraintSystem,
    },
    mpc_inner_product::SharedInnerProductProof,
    mpc_linear_combination::{LinearCombination, Variable},
    proof::SharedR1CSProof,
};
use ark_std::{cfg_iter, rand::RngCore, vec::Vec, UniformRand};
use ark_std::rand::{prelude::StdRng, SeedableRng};
use crate::globals::get_party_id;
use crate::network::Net;

#[allow(dead_code, non_snake_case)]
pub struct MpcProver <'t, 'g>{
    /// The protocol transcript, used for constructing Fiat-Shamir challenges
    transcript: &'t mut Transcript,
    /// Generators used for Pedersen commitments
    pc_gens: &'g PedersenGens,
    /// Teh constraints accumulated so far.
    constraints: Vec<LinearCombination>,
    /// Stores assignments to the "left" of multiplication gates.
    a_L: Vec<SF<Fr>>,
    /// Stores assignments to the "right" of multiplication gates.
    a_R: Vec<SF<Fr>>,
    /// Stores assignments to the "output" of multiplication gates.
    a_O: Vec<SF<Fr>>,
    /// High-level witness assignments (value openings to V commitments)
    /// where we use a pedersen commitment `value * G + blinding * H`
    v: Vec<SF<Fr>>,
    /// High-level public variables that are allocated in hte constraint system
    v_public: Vec<SF<Fr>>,
    /// High level witness data (blinding openings to V commitments)
    v_blinding: Vec<SF<Fr>>,
    /// Index of a pending multiplier that hasn't been assigned yet
    pending_multiplier: Option<usize>,
    /// This list holds closures that will be called in the second phase of the protocol,
    /// when non-randomized variables are committed.
    deferred_constraints:
        Vec<Box<dyn Send + Sync + FnOnce(&mut RandomizingMpcProver) -> Result<(), R1CSError>>>,
}

/// A prover in the randomizing phase.
///
/// In this phase constraints may be built using challenge scalars derived from the
/// protocol transcript so far.
pub struct RandomizingMpcProver<'t, 'g> {
    prover: MpcProver<'t, 'g>,
}

impl<'t, 'g> ConstraintSystem for MpcProver <'t, 'g>{
    /// Lease the transcript to the caller
    fn transcript(&mut self) -> &mut Transcript {
        self.transcript.borrow_mut()
    }

    fn multiply(
        &mut self,
        left: LinearCombination,
        right: LinearCombination,
    ) -> (Variable, Variable, Variable){

        let l = self.eval(&left);
        let r = self.eval(&right);
        let o = l * r;

        // Create variables for l,r,o ...
        let l_var = Variable::MultiplierLeft(self.a_L.len());
        let r_var = Variable::MultiplierRight(self.a_R.len());
        let o_var = Variable::MultiplierOutput(self.a_O.len());

        // Add the value assignments
        self.a_L.push(l);
        self.a_R.push(r);
        self.a_O.push(o);

        // Constrain the multiplication
        let mut left_constraints = left.clone();
        let mut right_constraints = right.clone();

        // Constrain l,r,o:
        left_constraints.terms.push((l_var, -SF::<Fr>::one()));
        right_constraints.terms.push((r_var, -SF::<Fr>::one()));
        self.constrain(left_constraints);
        self.constrain(right_constraints);

        (l_var, r_var, o_var)
    }

    fn allocate(
        &mut self,
        assignment: Option<SF<Fr>>,
    ) -> Result<Variable, R1CSError> {
        let scalar = assignment.ok_or(R1CSError::MissingAssignment)?;

        match self.pending_multiplier {
            None => {
                let i = self.a_L.len();
                self.pending_multiplier = Some(i);
                self.a_L.push(scalar);
                self.a_R.push(SF::<Fr>::zero());
                self.a_O.push(SF::<Fr>::zero());
                Ok(Variable::MultiplierLeft(i))
            }
            Some(i) => {
                self.pending_multiplier = None;
                self.a_R[i] = scalar;
                self.a_O[i] = self.a_L[i] * self.a_R[i];
                Ok(Variable::MultiplierRight(i))
            }
        }
    }

    fn allocate_multiplier(
        &mut self,
        input_assignments: Option<(SF<Fr>, SF<Fr>)>,
    ) -> Result<(Variable, Variable, Variable), R1CSError> {
        let (l, r) = input_assignments.ok_or(R1CSError::MissingAssignment)?;
        let o = l * r;

        // Create variables for l,r,o ...
        let l_var = Variable::MultiplierLeft(self.a_L.len());
        let r_var = Variable::MultiplierRight(self.a_R.len());
        let o_var = Variable::MultiplierOutput(self.a_O.len());
        // ... and assign them
        self.a_L.push(l);
        self.a_R.push(r);
        self.a_O.push(o);

        Ok((l_var, r_var, o_var))
    }

    fn constrain(&mut self, lc: LinearCombination) {
        self.constraints.push(lc)
    }

    fn constraints(&self) -> usize {
        self.constraints.len()
    }

    fn multipliers_len(&self) -> usize {
        self.a_O.len()
    }
}

// TODO: implement RandomizingMpcProver
// impl MpcRandomizableConstraintSystem for MpcProver {
// impl MpcConstraintSystem for RandomizingMpcProver {


impl<'t, 'g> MpcProver <'t, 'g>{

    pub fn new(pc_gens: &'g PedersenGens, transcript: &'t mut Transcript) -> Self {
        transcript.r1cs_domain_sep();

        MpcProver {
            pc_gens,
            transcript,
            v: Vec::new(),
            v_public: Vec::new(),
            v_blinding: Vec::new(),
            constraints: Vec::new(),
            a_L: Vec::new(),
            a_R: Vec::new(),
            a_O: Vec::new(),
            deferred_constraints: Vec::new(),
            pending_multiplier: None,
        }
    }

    pub fn commit(&mut self, v: SF<Fr>, v_blinding: SF<Fr>) -> (SG<P>, Variable) {
        let i = self.v.len();
        self.v.push(v);
        self.v_blinding.push(v_blinding);

        // Add the commitment to the transcript.
        let V = self.pc_gens.commit(v, v_blinding);
        let V = V.reveal();
        self.transcript.append_point(b"V", &V.get_share_group_val());

        (V, Variable::Committed(i))
    }

    /// Use a challenge, `z`, to flatten the constraints in the
    /// constraint system into vectors used for proving and
    /// verification.
    ///
    /// # Output
    ///
    /// Returns a tuple of
    /// ```text
    /// (wL, wR, wO, wV)
    /// ```
    /// where `w{L,R,O}` is \\( z \cdot z^Q \cdot W_{L,R,O} \\).
    fn flattened_constraints(
        &mut self,
        z: &SF<Fr>,
    ) -> (
        Vec<SF<Fr>>,
        Vec<SF<Fr>>,
        Vec<SF<Fr>>,
        Vec<SF<Fr>>,
    ) {
        let n = self.a_L.len();
        let m = self.v.len();

        let mut wL = vec![SF::<Fr>::zero();n];
        let mut wR = vec![SF::<Fr>::zero();n];
        let mut wO = vec![SF::<Fr>::zero();n];
        let mut wV = vec![SF::<Fr>::zero();m];

        let mut exp_z = *z;
        for lc in self.constraints.iter() {
            for (var, coeff) in &lc.terms {
                match var {
                    Variable::MultiplierLeft(i) => {
                        wL[*i] += exp_z * coeff;
                    }
                    Variable::MultiplierRight(i) => {
                        wR[*i] += exp_z * coeff;
                    }
                    Variable::MultiplierOutput(i) => {
                        wO[*i] += exp_z * coeff;
                    }
                    Variable::Committed(i) => {
                        wV[*i] -= exp_z * coeff;
                    }
                    Variable::One() | Variable::Zero() => {
                        // The prover doesn't need to handle constant terms
                    }
                }
            }
            exp_z *= *z;
        }

        (wL, wR, wO, wV)
    }


    fn create_randomized_constraints(mut self) -> Result<Self, R1CSError> {
        self.pending_multiplier = None;

        if self.deferred_constraints.is_empty() {
            self.transcript.r1cs_1phase_domain_sep();
            Ok(self)
        } else {
            self.transcript.r1cs_2phase_domain_sep();

            let mut callbacks = std::mem::take(&mut self.deferred_constraints);
            let mut wrapped_self = RandomizingMpcProver { prover: self };
            for callback in callbacks.drain(..) {
                callback(&mut wrapped_self)?;
            }
            Ok(wrapped_self.prover)
        }
    }

    pub fn eval(&self, lc: &LinearCombination) -> SF<Fr> {
        let mut sum = SF::<Fr>::zero();
        for (var, coeff) in lc.terms.iter() {
            let resolved_val = match var{
                Variable::MultiplierLeft(i) => self.a_L[*i].to_owned(),
                Variable::MultiplierRight(i) => self.a_R[*i].to_owned(),
                Variable::MultiplierOutput(i) => self.a_O[*i].to_owned(),
                Variable::Committed(i) => self.v[*i].to_owned(),
                Variable::One() => SF::<Fr>::one(),
                Variable::Zero() => SF::<Fr>::zero(),
            };
            sum = sum + *coeff * resolved_val;
        }

        sum
    }

    pub fn prove(
        mut self,
        bp_gens: &BulletproofGens,
    ) -> Result<SharedR1CSProof, R1CSError> {

        self.transcript.append_u64(b"m", self.v.len() as u64);
        let mut rng = StdRng::seed_from_u64(5u64);

        let gens = bp_gens.share(0);;

        let n1 = self.a_L.len();

        let blinding_factors: Vec<SF<Fr>> = iter::repeat(SF::rand(&mut rng)).take(3 + 2 * n1).collect();


        let (i_blinding1, o_blinding1, s_blinding1) = (
            blinding_factors[0].clone(),
            blinding_factors[1].clone(),
            blinding_factors[2].clone(),
        );

        let s_L1 = blinding_factors[3..3 + n1].to_vec();
        let s_R1 = blinding_factors[3 + n1..3 + 2 * n1].to_vec();

        let B_blinding = self.pc_gens.B_blinding;

        let scalars = iter::once(&i_blinding1)
            .chain(self.a_L.iter())
            .chain(self.a_R.iter())
            .copied();

        let bases = iter::once(&self.pc_gens.B_blinding)
            .chain(gens.G(n1))
            .chain(gens.H(n1))
            .copied();

        let acc = custom_msm_iter(scalars,bases);
        let A_I1 = acc.reveal(); // reveal

        let scalars = iter::once(&o_blinding1).chain(self.a_O.iter()).copied();
        let bases = iter::once(&self.pc_gens.B_blinding)
            .chain(gens.G(n1))
            .copied();
        let acc = custom_msm_iter(scalars,bases);
        let A_O1 = acc.reveal(); //reveal

        let scalars = iter::once(&s_blinding1)
            .chain(s_L1.iter())
            .chain(s_R1.iter())
            .copied();
        let bases = iter::once(&self.pc_gens.B_blinding)
            .chain(gens.G(n1))
            .chain(gens.H(n1))
            .copied();
        let acc = custom_msm_iter(scalars,bases);
        let S1 = acc.reveal(); //reveal

        self.transcript.append_point(b"A_I1", &A_I1.get_share_group_val());
        self.transcript.append_point(b"A_O1", &A_O1.get_share_group_val());
        self.transcript.append_point(b"S1", &S1.get_share_group_val());

        self = self
            .create_randomized_constraints()
            .unwrap();

        let n = self.a_L.len();
        let n2 = n - n1;
        let padded_n = self.a_L.len().next_power_of_two();
        let pad = padded_n - n;

        if bp_gens.gens_capacity < padded_n {
            return Err(
                R1CSError::InvalidGeneratorsLength,
            );
        }

        let has_2nd_phase_commitments = n2 > 0;

        let blinding_factors:Vec<SF<Fr>> = if has_2nd_phase_commitments {
            iter::repeat(SF::<Fr>::rand(&mut rng)).take(3 + 2 * n2).collect()
        } else {
            iter::repeat(SF::<Fr>::zero()).take(3 + 2 * n1).collect()
        };

        let (i_blinding2, o_blinding2, s_blinding2) = (
            blinding_factors[0].clone(),
            blinding_factors[1].clone(),
            blinding_factors[2].clone(),
        );

        let s_L2 = blinding_factors[3..3 + n2].to_vec();
        let s_R2 = blinding_factors[3 + n2..3 + 2 * n2].to_vec();

        let (A_I2, A_O2, S2) = if has_2nd_phase_commitments {

            let scalars = iter::once(&i_blinding2)
                    .chain(self.a_L.iter().skip(n1))
                    .chain(self.a_R.iter().skip(n1))
                    .copied();
            let bases = iter::once(&self.pc_gens.B_blinding)
                        .chain(gens.G(n).skip(n1))
                        .chain(gens.H(n).skip(n1))
                        .copied();
            let acc = custom_msm_iter(scalars,bases);
            let A_I2 = acc.reveal();//reveal

            let scalars = iter::once(&o_blinding2)
                        .chain(self.a_O.iter().skip(n1))
                        .copied();
            let bases = iter::once(&self.pc_gens.B_blinding)
                        .chain(gens.G(n).skip(n1))
                        .copied();
            let acc = custom_msm_iter(scalars,bases);
            let A_O2 = acc.reveal();//reveal

            let scalars = iter::once(&s_blinding2)
                        .chain(s_L2.iter())
                        .chain(s_R2.iter())
                        .copied();
            let bases = iter::once(&self.pc_gens.B_blinding)
                        .chain(gens.G(n).skip(n1))
                        .chain(gens.H(n).skip(n1))
                        .copied();
            let acc = custom_msm_iter(scalars,bases);
            let S2 = acc.reveal();//reveal

            (A_I2,A_O2,S2)

        } else {
            (
                SG::<P>::from_public(GA::identity()),
                SG::<P>::from_public(GA::identity()),
                SG::<P>::from_public(GA::identity()),
            )
        };

        self.transcript.append_point(b"A_I2", &A_I2.get_share_group_val());
        self.transcript.append_point(b"A_O2", &A_O2.get_share_group_val());
        self.transcript.append_point(b"S2", &S2.get_share_group_val());

        let y = self.transcript.challenge_scalar(b"y");
        let y = SF::<Fr>::from_public(y);
        let z = self.transcript.challenge_scalar(b"z");
        let z = SF::<Fr>::from_public(z);

        let (wL, wR, wO, wV) = self.flattened_constraints(&z);

        let mut l_poly = util::VecPoly3::zero(n);
        let mut r_poly = util::VecPoly3::zero(n);

        let mut exp_y = SF::<Fr>::one();
        let y_inv = y.inverse().unwrap();
        let exp_y_inv = util::exp_iter(y_inv).take(padded_n).collect::<Vec<_>>();

        let sLsR = s_L1
            .iter()
            .chain(s_L2.iter())
            .zip(s_R1.iter().chain(s_R2.iter()));

        for (i, (sl, sr)) in sLsR.enumerate() {
            l_poly.1[i] = self.a_L[i] + exp_y_inv[i] * &wR[i];
            l_poly.2[i] = self.a_O[i].clone();
            l_poly.3[i] = sl.clone();
            r_poly.0[i] = wO[i] - &exp_y;
            r_poly.1[i] = exp_y * &self.a_R[i] + &wL[i];
            r_poly.3[i] = exp_y * sr;
            exp_y = exp_y * &y;
        }

        let t_poly = util::VecPoly3::special_inner_product(&l_poly, &r_poly);
        let mut t_blinding_factors: Vec<SF<Fr>> = iter::repeat(SF::<Fr>::rand(&mut rng)).take(5).collect();

        let (T_1, T_3, T_4, T_5, T_6) = {
            let t_1_shared = self
                .pc_gens
                .commit(t_poly.t1, t_blinding_factors[0]);
            let t_3_shared = self
                .pc_gens
                .commit(t_poly.t3, t_blinding_factors[1]);
            let t_4_shared = self
                .pc_gens
                .commit(t_poly.t4, t_blinding_factors[2]);
            let t_5_shared = self
                .pc_gens
                .commit(t_poly.t5, t_blinding_factors[3]);
            let t_6_shared = self
                .pc_gens
                .commit(t_poly.t6, t_blinding_factors[4]);

            (
                t_1_shared.reveal(),
                t_3_shared.reveal(),
                t_4_shared.reveal(),
                t_5_shared.reveal(),
                t_6_shared.reveal(),
            )
        };

        self.transcript.append_point(b"T_1", &T_1.get_share_group_val());
        self.transcript.append_point(b"T_3", &T_3.get_share_group_val());
        self.transcript.append_point(b"T_4", &T_4.get_share_group_val());
        self.transcript.append_point(b"T_5", &T_5.get_share_group_val());
        self.transcript.append_point(b"T_6", &T_6.get_share_group_val());

        let u = self.transcript.challenge_scalar(b"u");
        let u = SF::<Fr>::from_public(u);
        let x = self.transcript.challenge_scalar(b"x");
        let x = SF::<Fr>::from_public(x);

        let t_2_blinding: SF<Fr> = wV
            .iter()
            .zip(self.v_blinding.iter())
            .map(|(c, v_blinding)| *c * v_blinding)
            .sum();

        let t_blinding_poly = util::Poly6 {
            t1: t_blinding_factors.remove(0),
            t2: t_2_blinding,
            t3: t_blinding_factors.remove(0),
            t4: t_blinding_factors.remove(0),
            t5: t_blinding_factors.remove(0),
            t6: t_blinding_factors.remove(0),
        };

        let t_x = t_poly.eval(x);
        let t_x_blinding = t_blinding_poly.eval(x);

        let mut l_vec = l_poly.eval(x);
        l_vec.append(&mut vec![SF::<Fr>::zero(); pad]);

        let mut r_vec = r_poly.eval(x);
        r_vec.append(&mut vec![SF::<Fr>::zero(); pad]);

        let mut exp_y = -SF::<Fr>::one() * exp_y;
        for i in n..padded_n {
            r_vec[i] = exp_y.clone();
            exp_y = exp_y * &y;
        }

        let i_blinding = i_blinding1 + u * i_blinding2;
        let o_blinding = o_blinding1 + u * o_blinding2;
        let s_blinding = s_blinding1 + u * s_blinding2;

        let e_blinding = x * (i_blinding + x * (o_blinding + x * s_blinding));

        let (t_x_open, t_x_blinding_open, e_blinding_open) = {
            (
                t_x.reveal(),
                t_x_blinding.reveal(),
                e_blinding.reveal()
            )
        };

        self.transcript.append_scalar(b"t_x", &t_x_open.get_share_field_val());
        self.transcript
            .append_scalar(b"t_x_blinding", &t_x_blinding_open.get_share_field_val());
        self.transcript
            .append_scalar(b"e_blinding", &e_blinding_open.get_share_field_val());

        let w = self.transcript.challenge_scalar(b"w");
        let w = SF::<Fr>::from_public(w);
        let Q = (self.pc_gens.B * w).into_affine();

        let G_factors = iter::repeat(SF::<Fr>::one())
            .take(n1)
            .chain(iter::repeat(u).take(n2 + pad))
            .collect::<Vec<_>>();
        let H_factors = exp_y_inv
            .into_iter()
            .zip(G_factors.iter())
            .map(|(y, u_or_1)| y * u_or_1)
            .collect::<Vec<_>>();

        let ipp = SharedInnerProductProof::create(
            &mut self.transcript,
            Q,
            &G_factors,
            &H_factors,
            gens.G(padded_n).copied().collect(),
            gens.H(padded_n).copied().collect(),
            l_vec,
            r_vec,
        ).unwrap();

        Ok(SharedR1CSProof {
            A_I1,
            A_O1,
            S1,
            A_I2,
            A_O2,
            S2,
            T_1,
            T_3,
            T_4,
            T_5,
            T_6,
            t_x: t_x_open,
            t_x_blinding: t_x_blinding_open,
            e_blinding: e_blinding_open,
            ipp_proof: ipp,
        })
    }

    pub fn prove_ipa(
        mut self,
        bp_gens: &BulletproofGens,
    ) -> Result<SharedR1CSProof, R1CSError> {

        self.transcript.append_u64(b"m", self.v.len() as u64);
        let mut rng = StdRng::seed_from_u64(5u64);

        let gens = bp_gens.share(0);;

        let n1 = self.a_L.len();

        let blinding_factors: Vec<SF<Fr>> = iter::repeat(SF::rand(&mut rng)).take(3 + 2 * n1).collect();


        let (i_blinding1, o_blinding1, s_blinding1) = (
            blinding_factors[0].clone(),
            blinding_factors[1].clone(),
            blinding_factors[2].clone(),
        );

        let s_L1 = blinding_factors[3..3 + n1].to_vec();
        let s_R1 = blinding_factors[3 + n1..3 + 2 * n1].to_vec();

        let B_blinding = self.pc_gens.B_blinding;

        let scalars = iter::once(&i_blinding1)
            .chain(self.a_L.iter())
            .chain(self.a_R.iter())
            .copied();

        let bases = iter::once(&self.pc_gens.B_blinding)
            .chain(gens.G(n1))
            .chain(gens.H(n1))
            .copied();

        let acc = custom_msm_iter(scalars,bases);
        let A_I1 = acc.reveal(); // reveal

        let scalars = iter::once(&o_blinding1).chain(self.a_O.iter()).copied();
        let bases = iter::once(&self.pc_gens.B_blinding)
            .chain(gens.G(n1))
            .copied();
        let acc = custom_msm_iter(scalars,bases);
        let A_O1 = acc.reveal(); //reveal

        let scalars = iter::once(&s_blinding1)
            .chain(s_L1.iter())
            .chain(s_R1.iter())
            .copied();
        let bases = iter::once(&self.pc_gens.B_blinding)
            .chain(gens.G(n1))
            .chain(gens.H(n1))
            .copied();
        let acc = custom_msm_iter(scalars,bases);
        let S1 = acc.reveal(); //reveal

        self.transcript.append_point(b"A_I1", &A_I1.get_share_group_val());
        self.transcript.append_point(b"A_O1", &A_O1.get_share_group_val());
        self.transcript.append_point(b"S1", &S1.get_share_group_val());

        self = self
            .create_randomized_constraints()
            .unwrap();

        let n = self.a_L.len();
        let n2 = n - n1;
        let padded_n = self.a_L.len().next_power_of_two();
        let pad = padded_n - n;

        if bp_gens.gens_capacity < padded_n {
            return Err(
                R1CSError::InvalidGeneratorsLength,
            );
        }

        let has_2nd_phase_commitments = n2 > 0;

        let blinding_factors:Vec<SF<Fr>> = if has_2nd_phase_commitments {
            iter::repeat(SF::<Fr>::rand(&mut rng)).take(3 + 2 * n2).collect()
        } else {
            iter::repeat(SF::<Fr>::zero()).take(3 + 2 * n1).collect()
        };

        let (i_blinding2, o_blinding2, s_blinding2) = (
            blinding_factors[0].clone(),
            blinding_factors[1].clone(),
            blinding_factors[2].clone(),
        );

        let s_L2 = blinding_factors[3..3 + n2].to_vec();
        let s_R2 = blinding_factors[3 + n2..3 + 2 * n2].to_vec();

        let (A_I2, A_O2, S2) = if has_2nd_phase_commitments {

            let scalars = iter::once(&i_blinding2)
                .chain(self.a_L.iter().skip(n1))
                .chain(self.a_R.iter().skip(n1))
                .copied();
            let bases = iter::once(&self.pc_gens.B_blinding)
                .chain(gens.G(n).skip(n1))
                .chain(gens.H(n).skip(n1))
                .copied();
            let acc = custom_msm_iter(scalars,bases);
            let A_I2 = acc.reveal();//reveal

            let scalars = iter::once(&o_blinding2)
                .chain(self.a_O.iter().skip(n1))
                .copied();
            let bases = iter::once(&self.pc_gens.B_blinding)
                .chain(gens.G(n).skip(n1))
                .copied();
            let acc = custom_msm_iter(scalars,bases);
            let A_O2 = acc.reveal();//reveal

            let scalars = iter::once(&s_blinding2)
                .chain(s_L2.iter())
                .chain(s_R2.iter())
                .copied();
            let bases = iter::once(&self.pc_gens.B_blinding)
                .chain(gens.G(n).skip(n1))
                .chain(gens.H(n).skip(n1))
                .copied();
            let acc = custom_msm_iter(scalars,bases);
            let S2 = acc.reveal();//reveal

            (A_I2,A_O2,S2)

        } else {
            (
                SG::<P>::from_public(GA::identity()),
                SG::<P>::from_public(GA::identity()),
                SG::<P>::from_public(GA::identity()),
            )
        };

        self.transcript.append_point(b"A_I2", &A_I2.get_share_group_val());
        self.transcript.append_point(b"A_O2", &A_O2.get_share_group_val());
        self.transcript.append_point(b"S2", &S2.get_share_group_val());

        let y = self.transcript.challenge_scalar(b"y");
        let y = SF::<Fr>::from_public(y);
        let z = self.transcript.challenge_scalar(b"z");
        let z = SF::<Fr>::from_public(z);

        let (wL, wR, wO, wV) = self.flattened_constraints(&z);

        let mut l_poly = util::VecPoly3::zero(n);
        let mut r_poly = util::VecPoly3::zero(n);

        let mut exp_y = SF::<Fr>::one();
        let y_inv = y.inverse().unwrap();
        let exp_y_inv = util::exp_iter(y_inv).take(padded_n).collect::<Vec<_>>();

        let sLsR = s_L1
            .iter()
            .chain(s_L2.iter())
            .zip(s_R1.iter().chain(s_R2.iter()));

        for (i, (sl, sr)) in sLsR.enumerate() {

            l_poly.1[i] = self.a_L[i] + exp_y_inv[i] * &wR[i];
            l_poly.2[i] = self.a_O[i].clone();
            l_poly.3[i] = sl.clone();
            r_poly.0[i] = wO[i] - &exp_y;
            r_poly.1[i] = exp_y * &self.a_R[i] + &wL[i];
            r_poly.3[i] = exp_y * sr;
            exp_y = exp_y * &y;
        }

        let t_poly = util::VecPoly3::special_inner_product(&l_poly, &r_poly);
        let mut t_blinding_factors: Vec<SF<Fr>> = iter::repeat(SF::<Fr>::rand(&mut rng)).take(5).collect();

        let (T_1, T_3, T_4, T_5, T_6) = {
            let t_1_shared = self
                .pc_gens
                .commit(t_poly.t1, t_blinding_factors[0]);
            let t_3_shared = self
                .pc_gens
                .commit(t_poly.t3, t_blinding_factors[1]);
            let t_4_shared = self
                .pc_gens
                .commit(t_poly.t4, t_blinding_factors[2]);
            let t_5_shared = self
                .pc_gens
                .commit(t_poly.t5, t_blinding_factors[3]);
            let t_6_shared = self
                .pc_gens
                .commit(t_poly.t6, t_blinding_factors[4]);

            (
                t_1_shared.reveal(),
                t_3_shared.reveal(),
                t_4_shared.reveal(),
                t_5_shared.reveal(),
                t_6_shared.reveal(),
            )
        };

        self.transcript.append_point(b"T_1", &T_1.get_share_group_val());
        self.transcript.append_point(b"T_3", &T_3.get_share_group_val());
        self.transcript.append_point(b"T_4", &T_4.get_share_group_val());
        self.transcript.append_point(b"T_5", &T_5.get_share_group_val());
        self.transcript.append_point(b"T_6", &T_6.get_share_group_val());

        let u = self.transcript.challenge_scalar(b"u");
        let u = SF::<Fr>::from_public(u);
        let x = self.transcript.challenge_scalar(b"x");
        let x = SF::<Fr>::from_public(x);

        let t_2_blinding: SF<Fr> = wV
            .iter()
            .zip(self.v_blinding.iter())
            .map(|(c, v_blinding)| *c * v_blinding)
            .sum();

        let t_blinding_poly = util::Poly6 {
            t1: t_blinding_factors.remove(0),
            t2: t_2_blinding,
            t3: t_blinding_factors.remove(0),
            t4: t_blinding_factors.remove(0),
            t5: t_blinding_factors.remove(0),
            t6: t_blinding_factors.remove(0),
        };

        let t_x = t_poly.eval(x);
        let t_x_blinding = t_blinding_poly.eval(x);

        let mut l_vec = l_poly.eval(x);
        l_vec = l_vec.iter().map(|l|l.reveal()).collect();
        l_vec.append(&mut vec![SF::<Fr>::zero(); pad]);

        let mut r_vec = r_poly.eval(x);
        r_vec = r_vec.iter().map(|r|r.reveal()).collect();
        r_vec.append(&mut vec![SF::<Fr>::zero(); pad]);

        let mut exp_y = -SF::<Fr>::one() * exp_y;
        for i in n..padded_n {
            r_vec[i] = exp_y.clone();
            exp_y = exp_y * &y;
        }

        let i_blinding = i_blinding1 + u * i_blinding2;
        let o_blinding = o_blinding1 + u * o_blinding2;
        let s_blinding = s_blinding1 + u * s_blinding2;

        let e_blinding = x * (i_blinding + x * (o_blinding + x * s_blinding));

        let (t_x_open, t_x_blinding_open, e_blinding_open) = {
            (
                t_x.reveal(),
                t_x_blinding.reveal(),
                e_blinding.reveal()
            )
        };

        self.transcript.append_scalar(b"t_x", &t_x_open.get_share_field_val());
        self.transcript
            .append_scalar(b"t_x_blinding", &t_x_blinding_open.get_share_field_val());
        self.transcript
            .append_scalar(b"e_blinding", &e_blinding_open.get_share_field_val());

        let w = self.transcript.challenge_scalar(b"w");
        let w = SF::<Fr>::from_public(w);
        let Q = (self.pc_gens.B * w).into_affine();

        let G_factors = iter::repeat(SF::<Fr>::one())
            .take(n1)
            .chain(iter::repeat(u).take(n2 + pad))
            .collect::<Vec<_>>();
        let H_factors = exp_y_inv
            .into_iter()
            .zip(G_factors.iter())
            .map(|(y, u_or_1)| y * u_or_1)
            .collect::<Vec<_>>();

        let ipp = SharedInnerProductProof::create(
            &mut self.transcript,
            Q,
            &G_factors,
            &H_factors,
            gens.G(padded_n).copied().collect(),
            gens.H(padded_n).copied().collect(),
            l_vec,
            r_vec,
        ).unwrap();

        Ok(SharedR1CSProof {
            A_I1,
            A_O1,
            S1,
            A_I2,
            A_O2,
            S2,
            T_1,
            T_3,
            T_4,
            T_5,
            T_6,
            t_x: t_x_open,
            t_x_blinding: t_x_blinding_open,
            e_blinding: e_blinding_open,
            ipp_proof: ipp,
        })
    }
}


pub fn custom_msm_iter<I, J>(scalars: J, bases: I) -> SG<P>
    where
        I: Iterator<Item = SG<P>>,
        J: Iterator<Item = SF<Fr>>,
{
    let mut acc = <SG<P> as AffineRepr>::Group::zero();
    for (base, scalar) in bases.zip(scalars) {
        acc += base.mul(scalar);
    }
    acc.into_affine()
}

#[cfg(test)]
mod tests {
    use std::env;
    use super::MpcProver;
    use super::*;
    use crate::bp::r1cs_mpc::{
        mpc_constraint_system::ConstraintSystem,
        mpc_prover::MpcProver as Prover,
        mpc_generators::PedersenGens,
    };
    use merlin::Transcript;
    use crate::bp::transcript_381::TranscriptProtocol;
    use ark_bls12_381::Fr;
    use ark_bls12_381::G1Affine as G;
    use ark_ff::{One, Zero};
    use crate::bp::generators_381::BulletproofGens;
    use crate::bp::r1cs::Verifier;
    use super::Variable;

    #[test]
    fn test_lc_add() {
        let args: Vec<String> = env::args().collect();

        // Parse arguments
        let party_id = args[4].parse::<usize>().unwrap();
        let n_parties = args[5].parse::<usize>().unwrap();

        Net::init_network(party_id, n_parties);

        let one_var = Variable::One();
        let res = one_var + Fr::one();

        let mut prover_transcript = Transcript::new("test".as_bytes());
        let pc_gens = PedersenGens::default();
        let mut cs = Prover::new(&pc_gens, &mut prover_transcript);

        let (_, _, c_var) = cs.multiply(res.clone(), res.clone());
        let new_res = c_var + Fr::one();

        let eval_res = cs.eval(&new_res);
        assert_eq!(eval_res.get_share_field_val(), Fr::one()+Fr::one()+Fr::one()+Fr::one()+Fr::one());

        Net::deinit_network();
    }
    #[test]
    fn test_constrain() {
        let args: Vec<String> = env::args().collect();

        // Parse arguments
        let party_id = args[4].parse::<usize>().unwrap();
        let n_parties = args[5].parse::<usize>().unwrap();

        Net::init_network(party_id, n_parties);

        let blinding = SF::<Fr>::from_public(Fr::from(47u8));
        let a = SF::<Fr>::from_public(Fr::from(5u8));
        let b = SF::<Fr>::from_public(Fr::from(5u8));
        // Evaluate this in a constraint system for posterity sake
        let mut prover_transcript = Transcript::new("test".as_bytes());
        let pc_gens = PedersenGens::default();
        let bp_gens: BulletproofGens = BulletproofGens::new(128, 1);

        let mut cs = Prover::new(&pc_gens, &mut prover_transcript);

        let (a_com,a_var) = cs.commit(a,blinding);
        let (b_com,b_var) = cs.commit(b,blinding);
        cs.constrain(a_var - b_var);

        Net::deinit_network();
    }
}
