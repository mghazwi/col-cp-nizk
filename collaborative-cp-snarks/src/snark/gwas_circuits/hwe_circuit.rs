use ark_ff::Field;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable,
};
use ark_relations::lc;
use crate::snark::gwas_circuits::{alpha_circuit::AlphaCircuit,e0_circuit::E0Circuit, e1_circuit::E1Circuit,
e2_circuit::E2Circuit,ojt_circuit::OjTCircuit,chi_square_circuit::ChiSquaredCircuit};

/// circuit for HWE test
/// num of constraints is 25 x N + 39
#[derive(Clone)]
pub struct MasterCircuit<F: Field> {
    pub alpha_circuit: AlphaCircuit<F>,
    pub e0_circuit: E0Circuit<F>,
    pub e1_circuit: E1Circuit<F>,
    pub e2_circuit: E2Circuit<F>,
    pub oj_t_circuit: OjTCircuit<F>,
    pub chi_squared_circuit_AA: ChiSquaredCircuit<F>,
    pub chi_squared_circuit_Aa: ChiSquaredCircuit<F>,
    pub chi_squared_circuit_aa: ChiSquaredCircuit<F>,
    pub total_chi_squared: Option<F>, // Total chi-squared statistic (public output)
}

impl<F: Field> ConstraintSynthesizer<F> for MasterCircuit<F> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {
        // Generate constraints for alpha circuit
        self.alpha_circuit.generate_constraints(cs.clone())?;

        // Generate constraints for E0, E1, E2 circuits
        self.e0_circuit.generate_constraints(cs.clone())?;
        self.e1_circuit.generate_constraints(cs.clone())?;
        self.e2_circuit.generate_constraints(cs.clone())?;

        // Generate constraints for OjTCircuit
        self.oj_t_circuit.generate_constraints(cs.clone())?;

        // Extract chi_squared values before moving the circuits
        let chi_squared_AA_value = self.chi_squared_circuit_AA.chi_squared.ok_or(SynthesisError::AssignmentMissing)?;
        let chi_squared_Aa_value = self.chi_squared_circuit_Aa.chi_squared.ok_or(SynthesisError::AssignmentMissing)?;
        let chi_squared_aa_value = self.chi_squared_circuit_aa.chi_squared.ok_or(SynthesisError::AssignmentMissing)?;

        // Generate constraints for chi-squared circuits (this moves the circuits)
        self.chi_squared_circuit_AA.generate_constraints(cs.clone())?;
        self.chi_squared_circuit_Aa.generate_constraints(cs.clone())?;
        self.chi_squared_circuit_aa.generate_constraints(cs.clone())?;

        // Create public input variables for chi-squared values using the extracted values
        let chi_squared_AA_public = cs.new_input_variable(|| Ok(chi_squared_AA_value))?;
        let chi_squared_Aa_public = cs.new_input_variable(|| Ok(chi_squared_Aa_value))?;
        let chi_squared_aa_public = cs.new_input_variable(|| Ok(chi_squared_aa_value))?;

        // Sum the chi-squared values
        let total_chi_squared_value = self.total_chi_squared.ok_or(SynthesisError::AssignmentMissing)?;
        let total_chi_squared_public = cs.new_input_variable(|| Ok(total_chi_squared_value))?;

        // Enforce total_chi_squared = chi_squared_AA + chi_squared_Aa + chi_squared_aa
        cs.enforce_constraint(
            lc!() + chi_squared_AA_public + chi_squared_Aa_public + chi_squared_aa_public - total_chi_squared_public,
            lc!() + Variable::One,
            lc!(),
        )?;

        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ff::{One, Zero}; // Using BLS12-381 scalar field
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::test_rng;
    use rand::Rng;

    #[test]
    fn test_master_circuit() {
        let n = 100; // Number of individuals
        let mut rng = test_rng();

        // Generate random inputs
        let mut x_list = Vec::with_capacity(n);
        let mut v_list = Vec::with_capacity(n);
        let mut y_list = Vec::with_capacity(n);

        for _ in 0..n {
            // x_i ∈ {0,1,2}
            let x_i_val = rng.gen_range(0u64..=2u64);
            let x_i = Fr::from(x_i_val);
            x_list.push(Some(x_i));

            // v_i ∈ {0,1}
            let v_i_val = rng.gen_range(0u64..=1u64);
            let v_i = Fr::from(v_i_val);
            v_list.push(Some(v_i));

            // y_i ∈ {0,1}
            let y_i_val = rng.gen_range(0u64..=1u64);
            let y_i = Fr::from(y_i_val);
            y_list.push(Some(y_i));
        }

        // Compute sum_y_x = ∑ y_i x_i
        let mut sum_y_x = Fr::zero();
        for i in 0..n {
            sum_y_x += y_list[i].unwrap() * x_list[i].unwrap();
        }

        // Compute sum_y_v = ∑ y_i v_i
        let mut sum_y_v = Fr::zero();
        for i in 0..n {
            sum_y_v += y_list[i].unwrap() * v_list[i].unwrap();
        }

        // Compute denom = 2 * (n - sum_y_v)
        let n_f = Fr::from(n as u64);
        let denom = Fr::from(2u64) * (n_f - sum_y_v);

        // Compute alpha
        let alpha_value = sum_y_x * denom.inverse().unwrap();

        // Compute n - sum_y
        let mut sum_y = Fr::zero();
        for i in 0..n {
            sum_y += y_list[i].unwrap();
        }
        let n_minus_sum_y = n_f - sum_y;

        // Compute E_j^t values
        let alpha_squared = alpha_value.square();
        let one_minus_alpha = Fr::one() - alpha_value;
        let one_minus_alpha_squared = one_minus_alpha.square();

        let E0_value = alpha_squared * n_minus_sum_y; // E_j^{AA}
        let E1_value = Fr::from(2u64) * alpha_value * one_minus_alpha * n_minus_sum_y; // E_j^{Aa}
        let E2_value = one_minus_alpha_squared * n_minus_sum_y; // E_j^{aa}

        // Generate u_{ij}^t from x_i
        let mut u_AA_list = Vec::with_capacity(n);
        let mut u_Aa_list = Vec::with_capacity(n);
        let mut u_aa_list = Vec::with_capacity(n);

        for i in 0..n {

            let (u_AA, u_Aa, u_aa) = if v_list[i].unwrap() == Fr::one() {
                (Fr::zero(), Fr::zero(), Fr::zero())
            } else {
                // Randomly assign one of u_{ij}^{AA}, u_{ij}^{Aa}, u_{ij}^{aa} to be 1, others 0
                let genotype = rng.gen_range(0u64..=2u64);
                match genotype {
                    0 => (Fr::one(), Fr::zero(), Fr::zero()),
                    1 => (Fr::zero(), Fr::one(), Fr::zero()),
                    2 => (Fr::zero(), Fr::zero(), Fr::one()),
                    _ => unreachable!(),
                }
            };
            u_AA_list.push(Some(u_AA));
            u_Aa_list.push(Some(u_Aa));
            u_aa_list.push(Some(u_aa));
        }

        // Compute O_j^t values
        let mut O_j_AA_value = Fr::zero();
        let mut O_j_Aa_value = Fr::zero();
        let mut O_j_aa_value = Fr::zero();

        for i in 0..n {
            let one_minus_y_i = Fr::one() - y_list[i].unwrap();

            O_j_AA_value += one_minus_y_i * u_AA_list[i].unwrap();
            O_j_Aa_value += one_minus_y_i * u_Aa_list[i].unwrap();
            O_j_aa_value += one_minus_y_i * u_aa_list[i].unwrap();
        }

        // Compute chi-squared values
        let chi_squared_AA_value = if !E0_value.is_zero() {
            (O_j_AA_value - E0_value).square() * E0_value.inverse().unwrap()
        } else {
            Fr::zero()
        };

        let chi_squared_Aa_value = if !E1_value.is_zero() {
            (O_j_Aa_value - E1_value).square() * E1_value.inverse().unwrap()
        } else {
            Fr::zero()
        };

        let chi_squared_aa_value = if !E2_value.is_zero() {
            (O_j_aa_value - E2_value).square() * E2_value.inverse().unwrap()
        } else {
            Fr::zero()
        };

        // Compute total chi-squared
        let total_chi_squared_value = chi_squared_AA_value + chi_squared_Aa_value + chi_squared_aa_value;

        // Build circuits
        let alpha_circuit = AlphaCircuit {
            x_list: x_list.clone(),
            v_list: v_list.clone(),
            y_list: y_list.clone(),
            n,
            alpha: Some(alpha_value),
        };

        let e0_circuit = E0Circuit {
            y_list: y_list.clone(),
            n,
            alpha: Some(alpha_value),
            E_aa: Some(E0_value),
        };

        let e1_circuit = E1Circuit {
            y_list: y_list.clone(),
            n,
            alpha: Some(alpha_value),
            E_aa: Some(E1_value),
        };

        let e2_circuit = E2Circuit {
            y_list: y_list.clone(),
            n,
            alpha: Some(alpha_value),
            E_aa: Some(E2_value),
        };

        let oj_t_circuit = OjTCircuit {
            u_AA_list: u_AA_list.clone(),
            u_Aa_list: u_Aa_list.clone(),
            u_aa_list: u_aa_list.clone(),
            v_list: v_list.clone(),
            y_list: y_list.clone(),
            n,
            O_j_AA: Some(O_j_AA_value),
            O_j_Aa: Some(O_j_Aa_value),
            O_j_aa: Some(O_j_aa_value),
        };

        let chi_squared_circuit_AA = ChiSquaredCircuit {
            O_j: Some(O_j_AA_value),
            E_j: Some(E0_value),
            chi_squared: Some(chi_squared_AA_value),
        };

        let chi_squared_circuit_Aa = ChiSquaredCircuit {
            O_j: Some(O_j_Aa_value),
            E_j: Some(E1_value),
            chi_squared: Some(chi_squared_Aa_value),
        };

        let chi_squared_circuit_aa = ChiSquaredCircuit {
            O_j: Some(O_j_aa_value),
            E_j: Some(E2_value),
            chi_squared: Some(chi_squared_aa_value),
        };

        // Create master circuit
        let master_circuit = MasterCircuit {
            alpha_circuit,
            e0_circuit,
            e1_circuit,
            e2_circuit,
            oj_t_circuit,
            chi_squared_circuit_AA,
            chi_squared_circuit_Aa,
            chi_squared_circuit_aa,
            total_chi_squared: Some(total_chi_squared_value),
        };

        // Create constraint system
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Generate constraints
        master_circuit.generate_constraints(cs.clone()).unwrap();

        // Check if the circuit is satisfied
        assert!(cs.is_satisfied().unwrap());

        // Optionally, print the number of constraints
        println!("Number of constraints: {}", cs.num_constraints());

        // Print the total chi-squared value
        println!("Total chi-squared value: {:?}", total_chi_squared_value);
    }
}

