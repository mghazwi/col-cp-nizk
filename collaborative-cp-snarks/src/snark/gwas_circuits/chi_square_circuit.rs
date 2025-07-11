use ark_ff::Field;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable};
use ark_relations::lc;

/// Circuit to compute chi-squared statistic: χ² = (O_j - E_j)² / E_j
#[derive(Clone)]
pub struct ChiSquaredCircuit<F: Field> {
    pub O_j: Option<F>,         // Observed count O_j (witness input)
    pub E_j: Option<F>,         // Expected count E_j (witness input)
    pub chi_squared: Option<F>, // Chi-squared statistic (public output)
}

impl<F: Field> ConstraintSynthesizer<F> for ChiSquaredCircuit<F> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {
        // Extract values from self
        let O_j_value = self.O_j.ok_or(SynthesisError::AssignmentMissing)?;
        let E_j_value = self.E_j.ok_or(SynthesisError::AssignmentMissing)?;

        // Compute O_j - E_j
        let O_minus_E_value = O_j_value - E_j_value;

        // Compute (O_j - E_j)^2
        let O_minus_E_squared_value = O_minus_E_value.square();

        // Witness variables
        let O_j = cs.new_witness_variable(|| Ok(O_j_value))?;
        let E_j = cs.new_witness_variable(|| Ok(E_j_value))?;

        // Compute O_j - E_j
        let O_minus_E = cs.new_witness_variable(|| Ok(O_minus_E_value))?;
        cs.enforce_constraint(
            lc!() + O_j - E_j,
            lc!() + Variable::One,
            lc!() + O_minus_E,
        )?;

        // Compute (O_j - E_j)^2
        let O_minus_E_squared = cs.new_witness_variable(|| Ok(O_minus_E_squared_value))?;
        cs.enforce_constraint(
            lc!() + O_minus_E,
            lc!() + O_minus_E,
            lc!() + O_minus_E_squared,
        )?;

        // Output chi_squared as public input
        let chi_squared_public = cs.new_input_variable(|| {
            self.chi_squared.ok_or(SynthesisError::AssignmentMissing)
        })?;
        // Enforce chi_squared_public = chi_squared
        cs.enforce_constraint(
            lc!() + chi_squared_public,
            lc!() + E_j,
            lc!() + O_minus_E_squared,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ff::{One, Zero}; // Using the BLS12-381 scalar field
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::test_rng;
    use rand::Rng;

    #[test]
    fn test_chi_squared_circuit() {
        let mut rng = test_rng();

        // Randomly generate E_j (can be zero)
        let E_j_value = Fr::from(rng.gen_range(0u64..=10u64));

        // Handle case where E_j = 0
        let E_nonzero_value = if E_j_value.is_zero() { Fr::zero() } else { Fr::one() };

        // Randomly generate O_j, ensuring O_j = E_j when E_j = 0
        let O_j_value = if E_j_value.is_zero() {
            E_j_value  // O_j = E_j = 0
        } else {
            Fr::from(rng.gen_range(0u64..=10u64))
        };

        // Compute O_j - E_j
        let O_minus_E_value = O_j_value - E_j_value;

        // Compute (O_j - E_j)^2
        let O_minus_E_squared_value = O_minus_E_value.square();

        // Compute chi_squared
        let chi_squared_value = if !E_j_value.is_zero() {
            O_minus_E_squared_value * E_j_value.inverse().unwrap()
        } else {
            Fr::zero()
        };

        // Create the circuit
        let circuit = ChiSquaredCircuit {
            O_j: Some(O_j_value),
            E_j: Some(E_j_value),
            chi_squared: Some(chi_squared_value),
        };

        // Create constraint system
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Generate constraints
        circuit.generate_constraints(cs.clone()).unwrap();

        // Check if the circuit is satisfied
        assert!(cs.is_satisfied().unwrap());

        // Optionally, print the number of constraints
        println!("Number of constraints: {}", cs.num_constraints());

        // For debugging purposes, you can print the computed chi_squared_value
        println!("Computed chi_squared: {:?}", chi_squared_value);
    }
}
