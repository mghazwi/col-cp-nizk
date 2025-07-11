use super::field::SharedField;
use crate::network::Network;
use ark_bls12_381::FrConfig;
use ark_ff::{Fp, MontBackend};

pub async fn distribute_witnesses(
    party_id: usize,
    my_value_shares: Vec<SharedField<Fp<MontBackend<FrConfig, 4>, 4>>>,
    n_constraints: usize,
    n_parties: usize,
    witness_size: usize,
) -> Vec<SharedField<Fp<MontBackend<FrConfig, 4>, 4>>> {
    let mut witness_input: Vec<SharedField<Fp<MontBackend<FrConfig, 4>, 4>>> = Vec::new();

    for i in 0..witness_size {
        // If party_id is my party_id, call Network::distribute_witnesses with the shares for my value
        if i == party_id {
            Network::distribute_witnesses(&my_value_shares[1..].to_vec());
            witness_input.push(my_value_shares[0])
        } else {
            // Else, call Network::receive_value to receive the share for this witness element
            let value = Network::receive_value_from(i).await;

            witness_input.push(value);
        }
    }

    witness_input
}

pub fn distribute_witnesses2(
    party_id: usize,
    my_value_shares: Vec<SharedField<Fp<MontBackend<FrConfig, 4>, 4>>>,
    n_constraints: usize,
    n_parties: usize,
    witness_size: usize,
) -> Vec<SharedField<Fp<MontBackend<FrConfig, 4>, 4>>> {
    let mut witness_input: Vec<SharedField<Fp<MontBackend<FrConfig, 4>, 4>>> = Vec::new();

    for i in 0..witness_size {
        // If party_id is my party_id, call Network::distribute_witnesses with the shares for my value
        if i == party_id {
            Network::distribute_witnesses(&my_value_shares[1..].to_vec());
            witness_input.push(my_value_shares[0])
        } else {
            // Else, call Network::receive_value to receive the share for this witness element
            let value = Network::receive_value_from2(i);

            witness_input.push(value);
        }
    }

    witness_input
}
