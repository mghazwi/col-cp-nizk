use ark_ff::Field;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable,
};
use ark_relations::lc;

#[derive(Clone)]
pub struct AlphaCircuit<F: Field> {
    pub x_list: Vec<Option<F>>,   // Genotype data x_i ∈ {0,1,2}
    pub v_list: Vec<Option<F>>,   // Missing data indicators v_i ∈ {0,1}
    pub y_list: Vec<Option<F>>,   // Indicator variables y_i ∈ {0,1}
    pub n: usize,                 // Number of individuals
    pub alpha: Option<F>,         // The computed alpha value (public input)
}

impl<F: Field> ConstraintSynthesizer<F> for AlphaCircuit<F> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {
        let mut x_vars = Vec::with_capacity(self.n);
        let mut v_vars = Vec::with_capacity(self.n);
        let mut y_vars = Vec::with_capacity(self.n);

        let mut sum_y_x_value = F::zero();
        let mut sum_y_v_value = F::zero();

        for i in 0..self.n {
            // Get witness values
            let x_i_value = self.x_list[i].ok_or(SynthesisError::AssignmentMissing)?;
            let v_i_value = self.v_list[i].ok_or(SynthesisError::AssignmentMissing)?;
            let y_i_value = self.y_list[i].ok_or(SynthesisError::AssignmentMissing)?;

            // Create variables
            let x_i = cs.new_witness_variable(|| Ok(x_i_value))?;
            x_vars.push(x_i);

            let v_i = cs.new_witness_variable(|| Ok(v_i_value))?;
            v_vars.push(v_i);

            let y_i = cs.new_witness_variable(|| Ok(y_i_value))?;
            y_vars.push(y_i);

            // Enforce x_i ∈ {0,1,2}
            // Enforce (x_i)*(x_i - 1)*(x_i - 2) = 0
            let x_i_minus_1 = cs.new_witness_variable(|| Ok(x_i_value - F::one()))?;
            cs.enforce_constraint(
                lc!() + x_i - (F::one(), Variable::One),
                lc!() + Variable::One,
                lc!() + x_i_minus_1,
            )?;

            let x_i_minus_2 = cs.new_witness_variable(|| Ok(x_i_value - F::from(2u64)))?;
            cs.enforce_constraint(
                lc!() + x_i - (F::from(2u64), Variable::One),
                lc!() + Variable::One,
                lc!() + x_i_minus_2,
            )?;

            // t1 = x_i * (x_i - 1)
            let t1_value = x_i_value * (x_i_value - F::one());
            let t1 = cs.new_witness_variable(|| Ok(t1_value))?;
            cs.enforce_constraint(
                lc!() + x_i,
                lc!() + x_i_minus_1,
                lc!() + t1,
            )?;

            // t2 = t1 * (x_i - 2)
            let t2_value = t1_value * (x_i_value - F::from(2u64));
            let t2 = cs.new_witness_variable(|| Ok(t2_value))?;
            cs.enforce_constraint(
                lc!() + t1,
                lc!() + x_i_minus_2,
                lc!() + t2,
            )?;

            // Enforce t2 = 0
            cs.enforce_constraint(
                lc!() + t2,
                lc!() + Variable::One,
                lc!(),
            )?;

            // Enforce v_i ∈ {0,1}: v_i * (v_i - 1) = 0
            cs.enforce_constraint(
                lc!() + v_i,
                lc!() + v_i - (F::one(), Variable::One),
                lc!(),
            )?;

            // Enforce y_i ∈ {0,1}: y_i * (y_i - 1) = 0
            cs.enforce_constraint(
                lc!() + y_i,
                lc!() + y_i - (F::one(), Variable::One),
                lc!(),
            )?;

            // Compute y_i * x_i
            let y_i_x_i_value = y_i_value * x_i_value;
            sum_y_x_value += y_i_x_i_value;
            let y_i_x_i = cs.new_witness_variable(|| Ok(y_i_x_i_value))?;
            cs.enforce_constraint(
                lc!() + y_i,
                lc!() + x_i,
                lc!() + y_i_x_i,
            )?;

            // Compute y_i * v_i
            let y_i_v_i_value = y_i_value * v_i_value;
            sum_y_v_value += y_i_v_i_value;
            let y_i_v_i = cs.new_witness_variable(|| Ok(y_i_v_i_value))?;
            cs.enforce_constraint(
                lc!() + y_i,
                lc!() + v_i,
                lc!() + y_i_v_i,
            )?;
        }

        // Compute sum_y_x variable
        let sum_y_x = cs.new_witness_variable(|| Ok(sum_y_x_value))?;
        let mut sum_y_x_lc = lc!() + sum_y_x;
        for i in 0..self.n {
            let y_i_x_i = cs.new_witness_variable(|| {
                let y_i_value = self.y_list[i].unwrap();
                let x_i_value = self.x_list[i].unwrap();
                Ok(y_i_value * x_i_value)
            })?;
            cs.enforce_constraint(
                lc!() + y_vars[i],
                lc!() + x_vars[i],
                lc!() + y_i_x_i,
            )?;
            sum_y_x_lc = sum_y_x_lc - y_i_x_i;
        }
        cs.enforce_constraint(
            sum_y_x_lc,
            lc!() + Variable::One,
            lc!(),
        )?;

        // Compute sum_y_v variable
        let sum_y_v = cs.new_witness_variable(|| Ok(sum_y_v_value))?;
        let mut sum_y_v_lc = lc!() + sum_y_v;
        for i in 0..self.n {
            let y_i_v_i = cs.new_witness_variable(|| {
                let y_i_value = self.y_list[i].unwrap();
                let v_i_value = self.v_list[i].unwrap();
                Ok(y_i_value * v_i_value)
            })?;
            cs.enforce_constraint(
                lc!() + y_vars[i],
                lc!() + v_vars[i],
                lc!() + y_i_v_i,
            )?;
            sum_y_v_lc = sum_y_v_lc - y_i_v_i;
        }
        cs.enforce_constraint(
            sum_y_v_lc,
            lc!() + Variable::One,
            lc!(),
        )?;

        // Compute denom = 2 * (n - sum_y_v)
        let n_f = F::from(self.n as u64);
        let n_minus_sum_y_v_value = n_f - sum_y_v_value;
        let n_minus_sum_y_v = cs.new_witness_variable(|| Ok(n_minus_sum_y_v_value))?;
        cs.enforce_constraint(
            lc!() + n_minus_sum_y_v + sum_y_v - (n_f, Variable::One),
            lc!() + Variable::One,
            lc!(),
        )?;

        let denom_value = F::from(2u64) * n_minus_sum_y_v_value;
        let denom = cs.new_witness_variable(|| Ok(denom_value))?;
        cs.enforce_constraint(
            lc!() + denom - (F::from(2u64), n_minus_sum_y_v),
            lc!() + Variable::One,
            lc!(),
        )?;

        // Enforce alpha * denom = sum_y_x
        let alpha_value = self.alpha.ok_or(SynthesisError::AssignmentMissing)?;
        let alpha = cs.new_input_variable(|| Ok(alpha_value))?;
        let alpha_times_denom = cs.new_witness_variable(|| Ok(alpha_value * denom_value))?;
        cs.enforce_constraint(
            lc!() + alpha,
            lc!() + denom,
            lc!() + alpha_times_denom,
        )?;
        cs.enforce_constraint(
            lc!() + alpha_times_denom - sum_y_x,
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
    use ark_ff::{One, Zero}; // Use Fr as the field
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::test_rng;
    use rand::Rng;

    #[test]
    fn test_alpha_circuit() {
        let n = 5; // Number of individuals
        let mut rng = test_rng();

        let mut x_list = Vec::with_capacity(n);
        let mut v_list = Vec::with_capacity(n);
        let mut y_list = Vec::with_capacity(n);

        for _ in 0..n {
            // x_i ∈ {0,1,2}
            let x_i_value = rng.gen_range(0u64..=2u64);
            let x_i = Fr::from(x_i_value);
            x_list.push(Some(x_i));

            // v_i ∈ {0,1}
            let v_i_value = rng.gen_range(0u64..=1u64);
            let v_i = Fr::from(v_i_value);
            v_list.push(Some(v_i));

            // y_i ∈ {0,1}
            let y_i_value = rng.gen_range(0u64..=1u64);
            let y_i = Fr::from(y_i_value);
            y_list.push(Some(y_i));
        }

        // Compute alpha
        let one = Fr::one();
        let two = Fr::from(2u64);
        let n_f = Fr::from(n as u64);

        // Compute sum_y_x and sum_y_v
        let sum_y_x = y_list.iter().zip(x_list.iter())
            .fold(Fr::zero(), |acc, (&y_i, &x_i)| acc + y_i.unwrap() * x_i.unwrap());
        let sum_y_v = y_list.iter().zip(v_list.iter())
            .fold(Fr::zero(), |acc, (&y_i, &v_i)| acc + y_i.unwrap() * v_i.unwrap());

        let denom = two * (n_f - sum_y_v);

        // Ensure denom is not zero
        assert!(!denom.is_zero(), "Denominator is zero, cannot compute alpha");

        let denom_inv = denom.inverse().unwrap();
        let alpha = sum_y_x * denom_inv;

        // Create the circuit
        let circuit = AlphaCircuit {
            x_list,
            v_list,
            y_list,
            n,
            alpha: Some(alpha),
        };

        // Create constraint system
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Generate constraints
        circuit.generate_constraints(cs.clone()).unwrap();

        println!("num of constraints = {:?}", cs.num_constraints());

        // Check if the circuit is satisfied
        assert!(cs.is_satisfied().unwrap());
    }
}
