use ark_ff::Field;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable,
};
use ark_relations::lc;

/// Circuit to compute O_j^t for t ∈ {AA, Aa, aa}, considering missing data indicators.
#[derive(Clone)]
pub struct OjTCircuit<F: Field> {
    pub u_AA_list: Vec<Option<F>>, // u_{ij}^{AA} ∈ {0,1}
    pub u_Aa_list: Vec<Option<F>>, // u_{ij}^{Aa} ∈ {0,1}
    pub u_aa_list: Vec<Option<F>>, // u_{ij}^{aa} ∈ {0,1}
    pub v_list: Vec<Option<F>>,    // v_{ij} ∈ {0,1}
    pub y_list: Vec<Option<F>>,    // y_i ∈ {0,1}
    pub n: usize,                  // Number of individuals
    pub O_j_AA: Option<F>,         // Computed O_j^{AA} (public output)
    pub O_j_Aa: Option<F>,         // Computed O_j^{Aa} (public output)
    pub O_j_aa: Option<F>,         // Computed O_j^{aa} (public output)
}

impl<F: Field> ConstraintSynthesizer<F> for OjTCircuit<F> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {
        let mut u_AA_vars = Vec::with_capacity(self.n);
        let mut u_Aa_vars = Vec::with_capacity(self.n);
        let mut u_aa_vars = Vec::with_capacity(self.n);
        let mut v_vars = Vec::with_capacity(self.n);
        let mut y_vars = Vec::with_capacity(self.n);

        let mut u_AA_values = Vec::with_capacity(self.n);
        let mut u_Aa_values = Vec::with_capacity(self.n);
        let mut u_aa_values = Vec::with_capacity(self.n);
        let mut v_values = Vec::with_capacity(self.n);
        let mut y_values = Vec::with_capacity(self.n);

        // Values for O_j^t
        let mut O_j_AA_value = F::zero();
        let mut O_j_Aa_value = F::zero();
        let mut O_j_aa_value = F::zero();

        for i in 0..self.n {
            // Get witness values
            let u_AA_value = self.u_AA_list[i].ok_or(SynthesisError::AssignmentMissing)?;
            let u_Aa_value = self.u_Aa_list[i].ok_or(SynthesisError::AssignmentMissing)?;
            let u_aa_value = self.u_aa_list[i].ok_or(SynthesisError::AssignmentMissing)?;
            let v_i_value = self.v_list[i].ok_or(SynthesisError::AssignmentMissing)?;
            let y_i_value = self.y_list[i].ok_or(SynthesisError::AssignmentMissing)?;

            u_AA_values.push(u_AA_value);
            u_Aa_values.push(u_Aa_value);
            u_aa_values.push(u_aa_value);
            v_values.push(v_i_value);
            y_values.push(y_i_value);

            // Create variables
            let u_AA = cs.new_witness_variable(|| Ok(u_AA_value))?;
            u_AA_vars.push(u_AA);

            let u_Aa = cs.new_witness_variable(|| Ok(u_Aa_value))?;
            u_Aa_vars.push(u_Aa);

            let u_aa = cs.new_witness_variable(|| Ok(u_aa_value))?;
            u_aa_vars.push(u_aa);

            let v_i = cs.new_witness_variable(|| Ok(v_i_value))?;
            v_vars.push(v_i);

            let y_i = cs.new_witness_variable(|| Ok(y_i_value))?;
            y_vars.push(y_i);

            // Enforce u_{ij}^{AA}, u_{ij}^{Aa}, u_{ij}^{aa} ∈ {0,1}
            cs.enforce_constraint(
                lc!() + u_AA,
                lc!() + u_AA - (F::one(), Variable::One),
                lc!(),
            )?;
            cs.enforce_constraint(
                lc!() + u_Aa,
                lc!() + u_Aa - (F::one(), Variable::One),
                lc!(),
            )?;
            cs.enforce_constraint(
                lc!() + u_aa,
                lc!() + u_aa - (F::one(), Variable::One),
                lc!(),
            )?;

            // Enforce v_i ∈ {0,1}
            cs.enforce_constraint(
                lc!() + v_i,
                lc!() + v_i - (F::one(), Variable::One),
                lc!(),
            )?;

            // Enforce y_i ∈ {0,1}
            cs.enforce_constraint(
                lc!() + y_i,
                lc!() + y_i - (F::one(), Variable::One),
                lc!(),
            )?;

            // Enforce u_{ij}^{AA} + u_{ij}^{Aa} + u_{ij}^{aa} = 1 - v_{ij}
            let sum_u_i = cs.new_witness_variable(|| Ok(u_AA_value + u_Aa_value + u_aa_value))?;
            cs.enforce_constraint(
                lc!() + u_AA + u_Aa + u_aa - sum_u_i,
                lc!() + Variable::One,
                lc!(),
            )?;
            let one_minus_v_i = cs.new_witness_variable(|| Ok(F::one() - v_i_value))?;
            cs.enforce_constraint(
                lc!() + (F::one(), Variable::One) - v_i,
                lc!() + Variable::One,
                lc!() + one_minus_v_i,
            )?;
            cs.enforce_constraint(
                lc!() + sum_u_i - one_minus_v_i,
                lc!() + Variable::One,
                lc!(),
            )?;

            // Compute x_i = u_{ij}^{Aa} + 2 * u_{ij}^{aa}
            let two_u_aa = cs.new_witness_variable(|| Ok(u_aa_value.double()))?;
            cs.enforce_constraint(
                lc!() + (F::from(2u64), Variable::One),
                lc!() + u_aa,
                lc!() + two_u_aa,
            )?;
            let x_i_value = u_Aa_value + u_aa_value.double();
            let x_i = cs.new_witness_variable(|| Ok(x_i_value))?;
            cs.enforce_constraint(
                lc!() + u_Aa + two_u_aa - x_i,
                lc!() + Variable::One,
                lc!(),
            )?;

            // Compute (1 - y_i)
            let one_minus_y_i = cs.new_witness_variable(|| Ok(F::one() - y_i_value))?;
            cs.enforce_constraint(
                lc!() + (F::one(), Variable::One) - y_i,
                lc!() + Variable::One,
                lc!() + one_minus_y_i,
            )?;

            // Compute (1 - y_i) * u_{ij}^t
            // For AA
            let term_AA_value = (F::one() - y_i_value) * u_AA_value;
            O_j_AA_value += term_AA_value;
            let term_AA = cs.new_witness_variable(|| Ok(term_AA_value))?;
            cs.enforce_constraint(
                lc!() + one_minus_y_i,
                lc!() + u_AA,
                lc!() + term_AA,
            )?;

            // For Aa
            let term_Aa_value = (F::one() - y_i_value) * u_Aa_value;
            O_j_Aa_value += term_Aa_value;
            let term_Aa = cs.new_witness_variable(|| Ok(term_Aa_value))?;
            cs.enforce_constraint(
                lc!() + one_minus_y_i,
                lc!() + u_Aa,
                lc!() + term_Aa,
            )?;

            // For aa
            let term_aa_value = (F::one() - y_i_value) * u_aa_value;
            O_j_aa_value += term_aa_value;
            let term_aa = cs.new_witness_variable(|| Ok(term_aa_value))?;
            cs.enforce_constraint(
                lc!() + one_minus_y_i,
                lc!() + u_aa,
                lc!() + term_aa,
            )?;
        }

        // Sum the terms to compute O_j^t
        let O_j_AA_public = cs.new_input_variable(|| self.O_j_AA.ok_or(SynthesisError::AssignmentMissing))?;
        cs.enforce_constraint(
            lc!() + O_j_AA_public - (O_j_AA_value, Variable::One),
            lc!() + Variable::One,
            lc!(),
        )?;

        let O_j_Aa_public = cs.new_input_variable(|| self.O_j_Aa.ok_or(SynthesisError::AssignmentMissing))?;
        cs.enforce_constraint(
            lc!() + O_j_Aa_public - (O_j_Aa_value, Variable::One),
            lc!() + Variable::One,
            lc!(),
        )?;

        let O_j_aa_public = cs.new_input_variable(|| self.O_j_aa.ok_or(SynthesisError::AssignmentMissing))?;
        cs.enforce_constraint(
            lc!() + O_j_aa_public - (O_j_aa_value, Variable::One),
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
    fn test_ojt_circuit() {
        let n = 5; // Number of individuals
        let mut rng = test_rng();

        let mut u_AA_list = Vec::with_capacity(n);
        let mut u_Aa_list = Vec::with_capacity(n);
        let mut u_aa_list = Vec::with_capacity(n);
        let mut v_list = Vec::with_capacity(n);
        let mut y_list = Vec::with_capacity(n);

        // Values for computing O_j^t
        let mut O_j_AA_value = Fr::zero();
        let mut O_j_Aa_value = Fr::zero();
        let mut O_j_aa_value = Fr::zero();

        for _ in 0..n {
            // Randomly decide if the genotype is missing
            let v_i_val = rng.gen_range(0u64..=1u64);
            let v_i = Fr::from(v_i_val);
            v_list.push(Some(v_i));

            // If genotype is missing, set u_{ij}^t = 0
            let (u_AA, u_Aa, u_aa) = if v_i_val == 1 {
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

            // y_i ∈ {0,1}
            let y_i_val = rng.gen_range(0u64..=1u64);
            let y_i = Fr::from(y_i_val);
            y_list.push(Some(y_i));

            // Compute (1 - y_i)
            let one_minus_y_i = Fr::one() - y_i;

            // Update O_j^t
            O_j_AA_value += one_minus_y_i * u_AA;
            O_j_Aa_value += one_minus_y_i * u_Aa;
            O_j_aa_value += one_minus_y_i * u_aa;
        }

        // Create the circuit
        let circuit = OjTCircuit {
            u_AA_list,
            u_Aa_list,
            u_aa_list,
            v_list,
            y_list,
            n,
            O_j_AA: Some(O_j_AA_value),
            O_j_Aa: Some(O_j_Aa_value),
            O_j_aa: Some(O_j_aa_value),
        };

        // Create constraint system
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Generate constraints
        circuit.generate_constraints(cs.clone()).unwrap();

        // Check if the circuit is satisfied
        assert!(cs.is_satisfied().unwrap());
    }
}
