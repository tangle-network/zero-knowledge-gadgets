use crate::Vec;
use ark_ff::fields::PrimeField;
use ark_r1cs_std::{
	eq::EqGadget,
	fields::{fp::FpVar, FieldVar},
	prelude::*,
};
use ark_relations::r1cs::{Namespace, SynthesisError};
use core::{borrow::Borrow, convert::TryInto};

pub struct SetGadget<F: PrimeField, const M: usize> {
    set: [FpVar<F>; M]
}

impl<F: PrimeField, const M: usize> SetGadget<F, M> {
    pub fn new(set: [FpVar<F>; M]) -> Self {
        Self { set }
    }

    pub fn check_membership<T: ToBytesGadget<F>>(
        &self,
        target: &T,
    ) -> Result<Boolean<F>, SynthesisError> {
        let target = Boolean::le_bits_to_fp_var(&target.to_bytes()?.to_bits_le()?)?;
        // Calculating the diffs inside the circuit
        let mut diffs = Vec::new();
        for root in &self.set {
            diffs.push(root - &target);
        }

        // Checking the membership
        let mut product = target.clone();
        for (diff, real) in diffs.iter().zip(self.set.iter()) {
            real.enforce_equal(&(diff + &target))?;
            product *= diff;
        }
        
        product.is_eq(&FpVar::<F>::zero())
    }
}

impl<F: PrimeField, const M: usize> AllocVar<[F; M], F> for SetGadget<F, M> {
	fn new_variable<T: Borrow<[F; M]>>(
		into_ns: impl Into<Namespace<F>>,
		f: impl FnOnce() -> Result<T, SynthesisError>,
		mode: AllocationMode,
	) -> Result<Self, SynthesisError> {
		let inp = f()?.borrow().clone();
		let set_var = Vec::<FpVar<F>>::new_variable(into_ns, || Ok(inp), mode)?;
        let set_array_var: [FpVar<F>; M] = set_var.try_into().map_err(|_| SynthesisError::UnconstrainedVariable)?;
		Ok(SetGadget::new(set_array_var))
	}
}