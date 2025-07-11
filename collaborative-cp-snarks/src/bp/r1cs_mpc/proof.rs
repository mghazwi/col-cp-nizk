#![allow(non_snake_case)]
//! Definition of the proof struct.

use crate::bp::errors::MPCError;
use crate::bp::r1cs::R1CSProof;

use super::mpc_inner_product::SharedInnerProductProof;
use ark_bls12_381::Fr;
use ark_bls12_381::Bls12_381 as P;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, Zero};

use crate::mpc::spdz_field::{SpdzSharedField as SF, SpdzSharedFieldTrait};
use crate::mpc::spdz_group::g1_affine::SpdzSharedG1Affine as SG;
use crate::mpc::spdz_group::group::SpdzSharedAffineTrait;

#[derive(Clone, Debug)]
#[allow(non_snake_case)]
pub struct SharedR1CSProof {
    /// Commitment to the values of input wires in the first phase.
    pub(super) A_I1: SG<P>,
    /// Commitment to the values of output wires in the first phase.
    pub(super) A_O1: SG<P>,
    /// Commitment to the blinding factors in the first phase.
    pub(super) S1: SG<P>,
    /// Commitment to the values of input wires in the second phase.
    pub(super) A_I2: SG<P>,
    /// Commitment to the values of output wires in the second phase.
    pub(super) A_O2: SG<P>,
    /// Commitment to the blinding factors in the second phase.
    pub(super) S2: SG<P>,
    /// Commitment to the \\(t_1\\) coefficient of \\( t(x) \\)
    pub(super) T_1: SG<P>,
    /// Commitment to the \\(t_3\\) coefficient of \\( t(x) \\)
    pub(super) T_3: SG<P>,
    /// Commitment to the \\(t_4\\) coefficient of \\( t(x) \\)
    pub(super) T_4: SG<P>,
    /// Commitment to the \\(t_5\\) coefficient of \\( t(x) \\)
    pub(super) T_5: SG<P>,
    /// Commitment to the \\(t_6\\) coefficient of \\( t(x) \\)
    pub(super) T_6: SG<P>,
    /// Evaluation of the polynomial \\(t(x)\\) at the challenge point \\(x\\)
    pub(super) t_x: SF<Fr>,
    /// Blinding factor for the synthetic commitment to \\( t(x) \\)
    pub(super) t_x_blinding: SF<Fr>,
    /// Blinding factor for the synthetic commitment to the
    /// inner-product arguments
    pub(super) e_blinding: SF<Fr>,
    /// Proof data for the inner-product argument.
    /// Made public for integration tests to test malleability
    pub(super) ipp_proof: SharedInnerProductProof,
}

impl SharedR1CSProof {

    pub fn reveal(&self) -> Result<R1CSProof, MPCError> {
        let ipp_open = self.ipp_proof.reveal().unwrap();

        Ok(R1CSProof {
            A_I1: self.A_I1.clone().get_share_group_val(),
            A_O1: self.A_O1.clone().get_share_group_val(),
            S1: self.S1.clone().get_share_group_val(),
            A_I2: self.A_I2.clone().get_share_group_val(),
            A_O2: self.A_O2.clone().get_share_group_val(),
            S2: self.S2.clone().get_share_group_val(),
            T_1: self.T_1.clone().get_share_group_val(),
            T_3: self.T_3.clone().get_share_group_val(),
            T_4: self.T_4.clone().get_share_group_val(),
            T_5: self.T_5.clone().get_share_group_val(),
            T_6: self.T_6.clone().get_share_group_val(),
            t_x: self.t_x.clone().get_share_field_val(),
            t_x_blinding: self.t_x_blinding.clone().get_share_field_val(),
            e_blinding: self.e_blinding.clone().get_share_field_val(),
            ipp_proof: ipp_open,
        })
    }
}
