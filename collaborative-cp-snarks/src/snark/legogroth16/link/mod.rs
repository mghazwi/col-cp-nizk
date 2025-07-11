#[macro_use]

mod matrix;
mod snark;

pub use matrix::*;
pub use snark::*;

#[cfg(test)]
mod test {
    use std::env;
    use super::{PESubspaceSnark, SparseMatrix, SubspaceSnark, PP};
    use ark_bls12_381::{Bls12_381 as P, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
    use ark_ec::{AffineRepr, CurveGroup, Group};
    use ark_ff::{One, PrimeField, UniformRand, Zero};
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use crate::mpc::spdz_field::{SpdzSharedField as SF, SpdzSharedFieldTrait};
    use crate::mpc::spdz_group::g1_affine::SpdzSharedG1Affine as SG;
    use crate::mpc::spdz_group::g2_affine::SpdzSharedG2Affine as SG2;
    use std::ops::{Add, Mul};
    use ark_std::{end_timer, start_timer};
    use tokio::time::Instant;
    use crate::globals::{get_party_id, set_experiment_name, set_phase, set_phase_time};
    use crate::mpc::spdz::Spdz;
    use crate::mpc::spdz_group::group::SpdzSharedAffineTrait;
    use crate::mpc::spdz_pairing::MpcPairing;
    use crate::network::Net;

    type MP = MpcPairing<P>;

    #[test]
    fn single_test_same_value_different_bases() {
        // Given `bases1 = [h1, h2]` and `bases2 = [h3, h4]`, prove knowledge of `x1, x2` in `y0 = h1 * x1 + h2 * x2` and `y1 = h3 * x1 + h4 * x2`

        let args: Vec<String> = env::args().collect();

        // Parse arguments
        let party_id = 0;
        let my_value_arg = 1;
        let n_constraints = 4;
        let n_parties = 1;

        // Experiment setup
        let experiment_name = String::from("cplink/")
            + n_parties.to_string().as_str()
            + "/"
            + n_constraints.to_string().as_str()
            + "/";
        set_experiment_name(&experiment_name);

        Net::init_network(party_id, n_parties);

        let mut rng = StdRng::seed_from_u64(0u64);
        let g1 = SG::rand(&mut rng);
        let g2 = SG2::rand(&mut rng);

        let mut pp = PP { l: 2, t: 2, g1, g2 };

        let bases1 = [SG::rand(&mut rng), SG::rand(&mut rng)];
        let bases2 = [SG::rand(&mut rng), SG::rand(&mut rng)];
        let mut m = SparseMatrix::<SG<P>>::new(2, 2);
        m.insert_row_slice(0, 0, &bases1);
        m.insert_row_slice(1, 0, &bases2);

        let w: Vec<SF<Fr>> = vec![SF::rand(&mut rng), SF::rand(&mut rng)];

        let mut acc = SG::<P>::zero();

        // TODO: replace with a call to msm

        for (base, scalar) in bases1.iter().zip(w.iter()) {
            acc =  (acc + base.mul(*scalar)).into_affine();
        }
        let x1 = acc;

        let mut acc = SG::<P>::zero();

        // TODO: replace with a call to msm

        for (base, scalar) in bases2.iter().zip(w.iter()) {
            acc =  (acc + base.mul(*scalar)).into_affine();
        }
        let x2 = acc;

        let x = [x1,x2];

        let cplink_timer = start_timer!(|| "CP-Link");

        set_phase("key gen");
        let kg_timer = start_timer!(|| "key gen");
        let (ek, vk) = PESubspaceSnark::<P, MP>::keygen(&mut rng, &pp, m);
        end_timer!(kg_timer);


        set_phase("prove");
        let prove_timer = start_timer!(|| "prove");
        let pi = PESubspaceSnark::<P,MP>::prove(&mut pp, &ek, &w);
        end_timer!(prove_timer);

        set_phase("verify");
        let ver_timer = start_timer!(|| "verify");
        assert!(PESubspaceSnark::<P,MP>::verify(&pp, &vk, &x, &pi));
        end_timer!(ver_timer);

        Net::deinit_network();
    }

    #[test]
    fn test_same_value_different_bases_n_times() {
        // Given `bases1 = [h1, h2]` and `bases2 = [h3, h4]`, prove knowledge of `x1, x2` in `y0 = h1 * x1 + h2 * x2` and `y1 = h3 * x1 + h4 * x2`

        let args: Vec<String> = env::args().collect();

        // Parse arguments
        let party_id = args[4].parse::<usize>().unwrap();
        let my_value_arg = args[5].parse::<usize>().unwrap();
        let n_values = args[6].parse::<usize>().unwrap();
        let n_parties = args[7].parse::<usize>().unwrap();

        // Experiment setup
        let experiment_name = String::from("cplink/")
            + n_parties.to_string().as_str()
            + "/"
            + n_values.to_string().as_str()
            + "/";
        set_experiment_name(&experiment_name);

        Net::init_network(party_id, n_parties);

        let mut rng = StdRng::seed_from_u64(0u64);
        let g1 = SG::rand(&mut rng);
        let g2 = SG2::rand(&mut rng);

        let mut pp = PP { l: 2, t: n_values, g1, g2 };

        let bases1 = vec![SG::rand(&mut rng); n_values];
        let bases2 = vec![SG::rand(&mut rng); n_values];
        let mut m = SparseMatrix::<SG<P>>::new(2, n_values);
        m.insert_row_slice(0, 0, &bases1);
        m.insert_row_slice(1, 0, &bases2);

        let w: Vec<SF<Fr>> = vec![SF::rand(&mut rng); n_values];

        let mut acc = SG::<P>::zero();

        // TODO: replace with a call to msm

        for (base, scalar) in bases1.iter().zip(w.iter()) {
            acc =  (acc + base.mul(*scalar)).into_affine();
        }
        let x1 = acc;

        let mut acc = SG::<P>::zero();

        // TODO: replace with a call to msm

        for (base, scalar) in bases2.iter().zip(w.iter()) {
            acc =  (acc + base.mul(*scalar)).into_affine();
        }
        let x2 = acc;

        let x = [x1,x2];

        let cplink_timer = start_timer!(|| "CP-Link");

        set_phase("key gen");
        let kg_timer = start_timer!(|| "key gen");
        let (ek, vk) = PESubspaceSnark::<P, MP>::keygen(&mut rng, &pp, m);
        end_timer!(kg_timer);


        set_phase("prove");
        let prove_timer = start_timer!(|| "prove");
        let pi = PESubspaceSnark::<P,MP>::prove(&mut pp, &ek, &w);
        end_timer!(prove_timer);

        set_phase("verify");
        let ver_timer = start_timer!(|| "verify");
        assert!(PESubspaceSnark::<P,MP>::verify(&pp, &vk, &x, &pi));
        end_timer!(ver_timer);

        Net::deinit_network();
    }

    #[test]
    fn test_same_value_different_bases_n_time_on_shares() {
        // Given `bases1 = [h1, h2]` and `bases2 s= [h3, h4]`, prove knowledge of `x1, x2` in `y0 = h1 * x1 + h2 * x2` and `y1 = h3 * x1 + h4 * x2`

        let args: Vec<String> = env::args().collect();

        // Parse arguments
        let party_id = args[4].parse::<usize>().unwrap();
        // let my_value_arg = args[5].parse::<usize>().unwrap();
        let n_values = args[5].parse::<usize>().unwrap();
        let n_parties = args[6].parse::<usize>().unwrap();

        // Experiment setup
        let experiment_name = String::from("cplink_share/")
            + n_parties.to_string().as_str()
            + "/"
            + n_values.to_string().as_str()
            + "/";
        set_experiment_name(&experiment_name);

        Net::init_network(party_id, n_parties);

        let mut rng = StdRng::seed_from_u64(5u64);
        let g1 = SG::generator();
        let g2 = SG2::generator();

        let mut pp = PP { l: 2, t: n_values, g1, g2 };

        let bases1 = vec![SG::generator(); n_values];
        let bases2 = vec![SG::generator(); n_values];
        let mut m = SparseMatrix::<SG<P>>::new(2, n_values);
        m.insert_row_slice(0, 0, &bases1);
        m.insert_row_slice(1, 0, &bases2);

        let w: Vec<Fr> = vec![Fr::rand(&mut rng); n_values];

        let my_w: Vec<SF<Fr>> =
            w.iter().map(|wi|
                {
                    let v = Spdz::<P, MpcPairing<P>>::generate_shares_for_value(
                        n_parties, Fr::from(*wi), &mut rng,
                    );
                    v[get_party_id()]
                }
            ).collect();

        let mut acc = SG::<P>::zero();

        // TODO: replace with a call to msm

        for (base, scalar) in bases1.iter().zip(my_w.iter()) {
            acc =  (acc + base.mul(*scalar)).into_affine();
        }
        let x1 = acc;

        let mut acc = SG::<P>::zero();

        // TODO: replace with a call to msm

        for (base, scalar) in bases2.iter().zip(my_w.iter()) {
            acc =  (acc + base.mul(*scalar)).into_affine();
        }
        let x2 = acc;

        let x = [x1.reveal(),x2.reveal()];

        let cplink_timer = start_timer!(|| "CP-Link");

        set_phase("key gen");
        let kg_timer = start_timer!(|| "key gen");
        let (ek, vk) = PESubspaceSnark::<P, MP>::keygen(&mut rng, &pp, m);
        end_timer!(kg_timer);
        set_phase_time(kg_timer.time.elapsed().as_micros());

        set_phase("prove");
        let prove_timer = start_timer!(|| "prove");
        let prove_start = Instant::now();
        let pi = PESubspaceSnark::<P,MP>::prove(&mut pp, &ek, &my_w);
        let prove_duration = prove_start.elapsed();
        println!("cplink prove for {} is {:?}", n_values, prove_duration);
        end_timer!(prove_timer);
        set_phase_time(prove_timer.time.elapsed().as_micros());

        let pi_revealed = pi.reveal();

        set_phase("verify");
        let ver_timer = start_timer!(|| "verify");
        let ver = PESubspaceSnark::<P,MP>::verify(&pp, &vk, &x, &pi_revealed);
        end_timer!(ver_timer);
        set_phase_time(ver_timer.time.elapsed().as_micros());

        assert!(ver);

        Net::deinit_network();
    }
}