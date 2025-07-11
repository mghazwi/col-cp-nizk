use crate::{mpc::spdz_pairing::MpcPairingTrait, snark::legogroth16::prepare_verifying_key};
use ark_ec::pairing::Pairing;
use ark_serialize::*;
use ark_std::vec::Vec;

use super::link::{SubspaceSnarkProvingKey, SubspaceSnarkVerificationKey, PP};

/// A proof in the Groth16 SNARK.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<B: Pairing, E: MpcPairingTrait<B>> {
    /// The `A` element in `G1`.
    pub a: <E as MpcPairingTrait<B>>::G1Affine,
    /// The `B` element in `G2`.
    pub b: <E as MpcPairingTrait<B>>::G2Affine,
    /// The `C` element in `G1`.
    pub c: <E as MpcPairingTrait<B>>::G1Affine,

    // LegoGroth16 additions
    /// The `D` element in `G1`.
    pub d: <E as MpcPairingTrait<B>>::G1Affine,

    /// cp_{link} proof-dependent commitment
    pub link_d: <E as MpcPairingTrait<B>>::G1Affine,
    /// cp_{link} proof of commitment equality
    pub link_pi: <E as MpcPairingTrait<B>>::G1Affine,
}

impl<B, E> Default for Proof<B, E>
where
    B: Pairing,
    E: MpcPairingTrait<B>,
{
    fn default() -> Self {
        Self {
            a: <E as MpcPairingTrait<B>>::G1Affine::default(),
            b: <E as MpcPairingTrait<B>>::G2Affine::default(),
            c: <E as MpcPairingTrait<B>>::G1Affine::default(),
            d: <E as MpcPairingTrait<B>>::G1Affine::default(),
            link_pi: <E as MpcPairingTrait<B>>::G1Affine::default(),
            link_d: <E as MpcPairingTrait<B>>::G1Affine::default(),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

/// A verification key in the Groth16 SNARK.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifyingKey<B, E>
where
    B: Pairing,
    E: MpcPairingTrait<B>,
{
    /// The `alpha * G`, where `G` is the generator of `<E as MpcPairingTrait<B>>::G1`.
    pub alpha_g1: <E as MpcPairingTrait<B>>::G1Affine,
    /// The `alpha * H`, where `H` is the generator of `<E as MpcPairingTrait<B>>::G2`.
    pub beta_g2: <E as MpcPairingTrait<B>>::G2Affine,
    /// The `gamma * H`, where `H` is the generator of `<E as MpcPairingTrait<B>>::G2`.
    pub gamma_g2: <E as MpcPairingTrait<B>>::G2Affine,
    /// The `delta * H`, where `H` is the generator of `<E as MpcPairingTrait<B>>::G2`.
    pub delta_g2: <E as MpcPairingTrait<B>>::G2Affine,
    /// The `gamma^{-1} * (beta * a_i + alpha * b_i + c_i) * H`, where `H` is the generator of `<E as MpcPairingTrait<B>>::G1`.
    pub gamma_abc_g1: Vec<<E as MpcPairingTrait<B>>::G1Affine>,

    // LegoGroth16 additions
    /// The element `eta*gamma^-1 * G` in `E::G1`.
    pub eta_gamma_inv_g1: <E as MpcPairingTrait<B>>::G1Affine,
    /// cp_{link}
    pub link_pp: PP<<E as MpcPairingTrait<B>>::G1Affine, <E as MpcPairingTrait<B>>::G2Affine>,
    /// cp_{link} bases
    pub link_bases: Vec<<E as MpcPairingTrait<B>>::G1Affine>,
    /// cp_{link} verification key
    pub link_vk: SubspaceSnarkVerificationKey<<E as MpcPairingTrait<B>>::G2Affine>,
}

impl<B, E> Default for VerifyingKey<B, E>
where
    B: Pairing,
    E: MpcPairingTrait<B>,
{
    fn default() -> Self {
        Self {
            alpha_g1: <E as MpcPairingTrait<B>>::G1Affine::default(),
            beta_g2: <E as MpcPairingTrait<B>>::G2Affine::default(),
            gamma_g2: <E as MpcPairingTrait<B>>::G2Affine::default(),
            delta_g2: <E as MpcPairingTrait<B>>::G2Affine::default(),
            gamma_abc_g1: Vec::new(),
            eta_gamma_inv_g1: <E as MpcPairingTrait<B>>::G1Affine::default(),
            link_pp: PP::<<E as MpcPairingTrait<B>>::G1Affine, <E as MpcPairingTrait<B>>::G2Affine>::default(),
            link_bases: Vec::new(),
            link_vk: SubspaceSnarkVerificationKey::<<E as MpcPairingTrait<B>>::G2Affine>::default(),
        }
    }
}

/// Preprocessed verification key parameters that enable faster verification
/// at the expense of larger size in memory.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PreparedVerifyingKey<B, E>
where
    B: Pairing,
    E: MpcPairingTrait<B>,
{
    /// The unprepared verification key.
    pub vk: VerifyingKey<B, E>,
    /// The element `e(alpha * G, beta * H)` in `E::GT`.
    pub alpha_g1_beta_g2: <E as MpcPairingTrait<B>>::TargetField,
    /// The element `- gamma * H` in `<E as MpcPairingTrait<B>>::G2`, prepared for use in pairings.
    pub gamma_g2_neg_pc: <E as MpcPairingTrait<B>>::G2Prepared,
    /// The element `- delta * H` in `<E as MpcPairingTrait<B>>::G2`, prepared for use in pairings.
    pub delta_g2_neg_pc: <E as MpcPairingTrait<B>>::G2Prepared,
}

impl<B, E> From<PreparedVerifyingKey<B, E>> for VerifyingKey<B, E>
where
    B: Pairing,
    E: MpcPairingTrait<B>,
{
    fn from(other: PreparedVerifyingKey<B, E>) -> Self {
        other.vk
    }
}

impl<B, E> From<VerifyingKey<B, E>> for PreparedVerifyingKey<B, E>
where
    B: Pairing,
    E: MpcPairingTrait<B>,
{
    fn from(other: VerifyingKey<B, E>) -> Self {
        prepare_verifying_key(&other)
    }
}

impl<B, E> Default for PreparedVerifyingKey<B, E>
where
    B: Pairing,
    E: MpcPairingTrait<B>,
{
    fn default() -> Self {
        Self {
            vk: VerifyingKey::default(),
            alpha_g1_beta_g2: <E as MpcPairingTrait<B>>::TargetField::default(),
            gamma_g2_neg_pc: <E as MpcPairingTrait<B>>::G2Prepared::default(),
            delta_g2_neg_pc: <E as MpcPairingTrait<B>>::G2Prepared::default(),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

/// The prover key for for the Groth16 zkSNARK.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProvingKey<B, E>
where
    B: Pairing,
    E: MpcPairingTrait<B>,
{
    /// The underlying verification key.
    pub vk: VerifyingKey<B, E>,
    /// The element `beta * G` in `<E as MpcPairingTrait<B>>::G1`.
    pub beta_g1: <E as MpcPairingTrait<B>>::G1Affine,
    /// The element `delta * G` in `<E as MpcPairingTrait<B>>::G1`.
    pub delta_g1: <E as MpcPairingTrait<B>>::G1Affine,
    /// The elements `a_i * G` in `<E as MpcPairingTrait<B>>::G1`.
    pub a_query: Vec<<E as MpcPairingTrait<B>>::G1Affine>,
    /// The elements `b_i * G` in `<E as MpcPairingTrait<B>>::G1`.
    pub b_g1_query: Vec<<E as MpcPairingTrait<B>>::G1Affine>,
    /// The elements `b_i * H` in `<E as MpcPairingTrait<B>>::G2`.
    pub b_g2_query: Vec<<E as MpcPairingTrait<B>>::G2Affine>,
    /// The elements `h_i * G` in `<E as MpcPairingTrait<B>>::G1`.
    pub h_query: Vec<<E as MpcPairingTrait<B>>::G1Affine>,
    /// The elements `l_i * G` in `<E as MpcPairingTrait<B>>::G1`.
    pub l_query: Vec<<E as MpcPairingTrait<B>>::G1Affine>,

    // LegoGroth16 additions
    /// The element `eta*delta^-1 * G` in `E::G1`.
    pub eta_delta_inv_g1: <E as MpcPairingTrait<B>>::G1Affine,
    /// Evaluation key of cp_{link}
    pub link_ek: SubspaceSnarkProvingKey<<E as MpcPairingTrait<B>>::G1Affine>,
}
