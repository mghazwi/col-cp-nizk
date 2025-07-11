use ark_ff::Field;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable},
};

/// Circuit for computing the Minor Allele Frequency (MAF) as per the given equation.
/// The circuit enforces that the MAF is correctly computed from the inputs `x_list` and `v_list`.
/// number of constraints for this circuits are 4 x n + 6, where n = num of individuals
#[derive(Clone)]
pub struct MAFCircuit<F: Field> {
    pub x_list: Vec<Option<F>>, // Genotype data x_{ij}, where each x_i ∈ {0,1,2}
    pub v_list: Vec<Option<F>>, // Missing data indicators v_{ij}, where each v_i ∈ {0,1}
    pub n: usize,               // Number of individuals
    pub maf: Option<F>,         // The computed MAF value (public input)
}

impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for MAFCircuit<ConstraintF> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        // Create variables for x_i and v_i
        let mut x_vars = Vec::with_capacity(self.n);
        let mut v_vars = Vec::with_capacity(self.n);

        // Also keep track of x_i and v_i values
        let mut x_values = Vec::with_capacity(self.n);
        let mut v_values = Vec::with_capacity(self.n);

        for i in 0..self.n {
            // Witness values for x_i and v_i
            let x_i_value = self.x_list[i].ok_or(SynthesisError::AssignmentMissing)?;
            let v_i_value = self.v_list[i].ok_or(SynthesisError::AssignmentMissing)?;

            // Witness variables for x_i and v_i
            let x_i = cs.new_witness_variable(|| Ok(x_i_value))?;
            x_vars.push(x_i);
            x_values.push(x_i_value);

            let v_i = cs.new_witness_variable(|| Ok(v_i_value))?;
            v_vars.push(v_i);
            v_values.push(v_i_value);

            // Enforce x_i ∈ {0,1,2} by ensuring (x_i)*(x_i - 1)*(x_i - 2) = 0
            // First, compute x_i - 1 and x_i - 2 as linear combinations
            let x_i_minus_1 = lc!() + x_i - (ConstraintF::one(), Variable::One);
            let x_i_minus_2 = lc!() + x_i - (ConstraintF::from(2u64), Variable::One);

            // Compute t1 = x_i * (x_i - 1)
            let t1_value = x_i_value * (x_i_value - ConstraintF::one());
            let t1 = cs.new_witness_variable(|| Ok(t1_value))?;
            cs.enforce_constraint(
                lc!() + x_i,
                x_i_minus_1.clone(),
                lc!() + t1,
            )?;

            // Compute t2 = t1 * (x_i - 2)
            let t2_value = t1_value * (x_i_value - ConstraintF::from(2u64));
            let t2 = cs.new_witness_variable(|| Ok(t2_value))?;
            cs.enforce_constraint(
                lc!() + t1,
                x_i_minus_2.clone(),
                lc!() + t2,
            )?;

            // Enforce t2 = 0
            cs.enforce_constraint(
                lc!() + t2,
                lc!() + Variable::One,
                lc!(),
            )?;

            // Enforce v_i ∈ {0,1} by ensuring v_i*(v_i - 1) = 0
            let v_i_minus_1 = lc!() + v_i - (ConstraintF::one(), Variable::One);
            cs.enforce_constraint(
                lc!() + v_i,
                v_i_minus_1,
                lc!(),
            )?;
        }

        // Compute sum_x = Σ x_i
        let sum_x_value = x_values.iter().fold(ConstraintF::zero(), |acc, x| acc + *x);
        let sum_x = cs.new_witness_variable(|| Ok(sum_x_value))?;

        // Compute sum_v = Σ v_i
        let sum_v_value = v_values.iter().fold(ConstraintF::zero(), |acc, v| acc + *v);
        let sum_v = cs.new_witness_variable(|| Ok(sum_v_value))?;

        // Enforce sum_x - Σ x_i = 0
        let mut sum_x_lc = lc!() + sum_x;
        for x_var in &x_vars {
            sum_x_lc = sum_x_lc - (*x_var);
        }
        cs.enforce_constraint(sum_x_lc, lc!() + Variable::One, lc!())?;

        // Enforce sum_v - Σ v_i = 0
        let mut sum_v_lc = lc!() + sum_v;
        for v_var in &v_vars {
            sum_v_lc = sum_v_lc - (*v_var);
        }
        cs.enforce_constraint(sum_v_lc, lc!() + Variable::One, lc!())?;

        // Compute n_minus_sum_v = n - sum_v
        let n_f = ConstraintF::from(self.n as u64);
        let n_minus_sum_v_value = n_f - sum_v_value;
        let n_minus_sum_v = cs.new_witness_variable(|| Ok(n_minus_sum_v_value))?;
        cs.enforce_constraint(
            lc!() + n_minus_sum_v + sum_v - (n_f, Variable::One),
            lc!() + Variable::One,
            lc!(),
        )?;

        // Compute denom = 2 * (n - sum_v)
        let denom_value = ConstraintF::from(2u64) * n_minus_sum_v_value;
        let denom = cs.new_witness_variable(|| Ok(denom_value))?;
        cs.enforce_constraint(
            lc!() + denom - (ConstraintF::from(2u64), n_minus_sum_v),
            lc!() + Variable::One,
            lc!(),
        )?;

        // Public input: maf (MAF_j)
        let maf_j = cs.new_input_variable(|| self.maf.ok_or(SynthesisError::AssignmentMissing))?;

        // Enforce maf_j * denom - sum_x = 0
        // Compute the product maf_j * denom as a new witness variable
        let maf_times_denom_value = self.maf.ok_or(SynthesisError::AssignmentMissing)? * denom_value;
        let maf_times_denom = cs.new_witness_variable(|| Ok(maf_times_denom_value))?;
        cs.enforce_constraint(
            lc!() + maf_j,
            lc!() + denom,
            lc!() + maf_times_denom,
        )?;

        // Enforce maf_j * denom - sum_x = 0
        cs.enforce_constraint(
            lc!() + maf_times_denom - sum_x,
            lc!() + Variable::One,
            lc!(),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr; // Or any other field you'd like to use
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::Zero;
    use rand::Rng;

    #[test]
    fn test_maf_circuit() {
        let n = 3;
        let x_list = vec![Some(Fr::from(0u64)), Some(Fr::from(1u64)), Some(Fr::from(2u64))];
        let v_list = vec![Some(Fr::from(0u64)); n]; // No missing data
        let sum_x = Fr::from(3u64); // 0 + 1 + 2 = 3
        let sum_v = Fr::from(0u64); // No missing data
        let denom = Fr::from(2u64 * n as u64); // 2 * (n - sum_v) = 6
        let maf = sum_x / denom; // 3 / 6 = 0.5

        let circuit = MAFCircuit {
            x_list,
            v_list,
            n,
            maf: Some(maf),
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        println!("num of constraints = {:?}", cs.num_constraints());

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_maf_circuit_with_n() {
        let n = 5; // Set `n` to any desired value

        // Initialize random number generator
        let mut rng = rand::thread_rng();

        // Generate `x_list` with random elements from {0,1,2}
        let mut x_list = Vec::with_capacity(n);
        for _ in 0..n {
            let x_i_value = rng.gen_range(0..=2); // Random integer in [0, 2]
            x_list.push(Some(Fr::from(x_i_value as u64)));
        }

        // Generate `v_list` with random elements from {0,1}
        let mut v_list = Vec::with_capacity(n);
        for _ in 0..n {
            let v_i_value = rng.gen_range(0..=1); // Random integer in [0, 1]
            v_list.push(Some(Fr::from(v_i_value as u64)));
        }

        // Compute sum_x = Σ x_i
        let sum_x = x_list.iter().fold(Fr::zero(), |acc, x| acc + x.unwrap());

        // Compute sum_v = Σ v_i
        let sum_v = v_list.iter().fold(Fr::zero(), |acc, v| acc + v.unwrap());

        // Compute denom = 2 * (n - sum_v)
        let n_f = Fr::from(n as u64);
        let denom = Fr::from(2u64) * (n_f - sum_v);

        // Ensure denom is not zero to avoid division by zero
        assert!(!denom.is_zero(), "Denominator is zero, cannot compute MAF");

        // Compute maf = sum_x / denom
        let maf = sum_x * denom.inverse().unwrap(); // Multiply by the inverse of denom

        // Instantiate the circuit
        let circuit = MAFCircuit {
            x_list,
            v_list,
            n,
            maf: Some(maf),
        };

        // Create a constraint system and generate constraints
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        println!("num of constraints = {:?}", cs.num_constraints());

        // Check if the constraints are satisfied
        assert!(cs.is_satisfied().unwrap());
    }
}
