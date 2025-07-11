use super::spdz_field::SpdzSharedField;
use crate::network::Net;
use ark_bls12_381::FrConfig;
use ark_bls12_381::Bls12_381;
use ark_ff::{Fp, MontBackend};
use crate::mpc::spdz_group::g1::SpdzSharedG1;

pub fn distribute_witnesses(
    party_id: usize,
    my_value_shares: Vec<SpdzSharedField<Fp<MontBackend<FrConfig, 4>, 4>>>,
    // n_constraints: usize,
    n_parties: usize,
    // witness_size: usize,
) -> Vec<SpdzSharedField<Fp<MontBackend<FrConfig, 4>, 4>>> {
    let mut witness_input: Vec<SpdzSharedField<Fp<MontBackend<FrConfig, 4>, 4>>> = Vec::new();

    for i in 0..n_parties {
        // If party_id is my party_id, call Network::distribute_witnesses with the shares for my value
        if i == party_id {
            Net::distribute_witnesses(&my_value_shares[1..].to_vec());
            witness_input.push(my_value_shares[0])
        } else {
            // Else, call Network::receive_value to receive the share for this witness element
            let value = Net::receive_value_from(i);

            witness_input.push(value);
        }
    }

    witness_input
}

pub fn distribute_group_witnesses(
    party_id: usize,
    my_value_shares: Vec<SpdzSharedG1<Bls12_381>>,
    n_constraints: usize,
    n_parties: usize,
    witness_size: usize,
) -> Vec<SpdzSharedG1<Bls12_381>> {
    let mut witness_input: Vec<SpdzSharedG1<Bls12_381>> = Vec::new();

    for i in 0..witness_size {
        // If party_id is my party_id, call Network::distribute_witnesses with the shares for my value
        if i == party_id {
            Net::distribute_witnesses(&my_value_shares[1..].to_vec());
            witness_input.push(my_value_shares[0])
        } else {
            // Else, call Network::receive_value to receive the share for this witness element
            let value = Net::receive_value_from(i);

            witness_input.push(value);
        }
    }

    witness_input
}
