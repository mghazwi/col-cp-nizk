use ark_ff::Field;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable,
};
use ark_relations::lc;

/// Circuit to compute E_j^{AA} = alpha_j^2 * (n - sum_y)
#[derive(Clone)]
pub struct E0Circuit<F: Field> {
    pub y_list: Vec<Option<F>>,    // y_i ∈ {0,1}
    pub n: usize,                  // Number of individuals
    pub alpha: Option<F>,          // alpha_j (public input)
    pub E_aa: Option<F>,           // E_j^{AA} (public output)
}

impl<F: Field> ConstraintSynthesizer<F> for E0Circuit<F> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {
        let mut y_vars = Vec::with_capacity(self.n);
        let mut sum_y_value = F::zero();

        // Process each y_i
        for i in 0..self.n {
            // Get witness value
            let y_i_value = self.y_list[i].ok_or(SynthesisError::AssignmentMissing)?;
            sum_y_value += y_i_value;

            // Create variable for y_i
            let y_i = cs.new_witness_variable(|| Ok(y_i_value))?;
            y_vars.push(y_i);

            // Enforce y_i ∈ {0,1}: y_i * (y_i - 1) = 0
            cs.enforce_constraint(
                lc!() + y_i,
                lc!() + y_i - (F::one(), Variable::One),
                lc!(),
            )?;
        }

        // Compute sum_y = Σ y_i
        let sum_y = cs.new_witness_variable(|| Ok(sum_y_value))?;

        // Enforce sum_y = sum of y_i
        let mut sum_y_lc = lc!() + sum_y;
        for y_i in &y_vars {
            sum_y_lc = sum_y_lc - *y_i;
        }
        cs.enforce_constraint(
            sum_y_lc,
            lc!() + Variable::One,
            lc!(),
        )?;

        // Compute n - sum_y
        let n_f = F::from(self.n as u64);
        let n_minus_sum_y_value = n_f - sum_y_value;
        let n_minus_sum_y = cs.new_witness_variable(|| Ok(n_minus_sum_y_value))?;
        cs.enforce_constraint(
            lc!() + n_minus_sum_y + sum_y - (n_f, Variable::One),
            lc!() + Variable::One,
            lc!(),
        )?;

        // Input alpha (public input)
        let alpha_value = self.alpha.ok_or(SynthesisError::AssignmentMissing)?;
        let alpha = cs.new_input_variable(|| Ok(alpha_value))?;

        // Compute alpha^2
        let alpha_squared_value = alpha_value.square();
        let alpha_squared = cs.new_witness_variable(|| Ok(alpha_squared_value))?;
        cs.enforce_constraint(
            lc!() + alpha,
            lc!() + alpha,
            lc!() + alpha_squared,
        )?;

        // Compute E_aa = alpha^2 * (n - sum_y)
        let E_aa_value = alpha_squared_value * n_minus_sum_y_value;
        let E_aa = cs.new_witness_variable(|| Ok(E_aa_value))?;
        cs.enforce_constraint(
            lc!() + alpha_squared,
            lc!() + n_minus_sum_y,
            lc!() + E_aa,
        )?;

        // Output E_aa as public output
        let E_aa_public = cs.new_input_variable(|| self.E_aa.ok_or(SynthesisError::AssignmentMissing))?;

        // Enforce E_aa_public = E_aa
        cs.enforce_constraint(
            lc!() + E_aa_public - E_aa,
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
    use ark_ff::Zero; // Using BLS12-381 scalar field
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::test_rng;
    use rand::Rng;

    #[test]
    fn test_0_circuit() {
        let n = 5; // Number of individuals
        let mut rng = test_rng();

        let mut y_list = Vec::with_capacity(n);
        let mut sum_y_value = Fr::zero();

        for _ in 0..n {
            // y_i ∈ {0,1}
            let y_i_val = rng.gen_range(0u64..=1u64);
            let y_i = Fr::from(y_i_val);
            y_list.push(Some(y_i));

            sum_y_value += y_i;
        }

        // Given alpha (public input)
        let alpha_value = Fr::from(3u64) / Fr::from(7u64); // Example alpha value in field

        // Compute E_j^{AA} = alpha^2 * (n - sum_y)
        let alpha_squared = alpha_value.square();
        let n_f = Fr::from(n as u64);
        let n_minus_sum_y = n_f - sum_y_value;
        let E_aa_value = alpha_squared * n_minus_sum_y;

        // Create the circuit
        let circuit = E0Circuit {
            y_list,
            n,
            alpha: Some(alpha_value),
            E_aa: Some(E_aa_value),
        };

        // Create constraint system
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Generate constraints
        circuit.generate_constraints(cs.clone()).unwrap();

        // Check if the circuit is satisfied
        assert!(cs.is_satisfied().unwrap());

        // Optionally, print the number of constraints
        println!("Number of constraints: {}", cs.num_constraints());
    }
}
