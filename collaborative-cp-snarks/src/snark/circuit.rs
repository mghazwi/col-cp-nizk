use ark_ff::Field;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};

/// Circuit for verifying that the product of witnesses `a` and `b` equals public value `c`.
#[derive(Clone)]
pub struct VerifyMultiplicationCircuit<F: Field> {
    pub a: Option<F>,
    pub b: Option<F>,
    pub n: usize,
}

impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF>
    for VerifyMultiplicationCircuit<ConstraintF>
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;

        let c = cs.new_input_variable(|| {
            let mut a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

            a.mul_assign(&b);

            Ok(a)
        })?;

        for _ in 0..self.n {
            cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        }

        Ok(())
    }
}
