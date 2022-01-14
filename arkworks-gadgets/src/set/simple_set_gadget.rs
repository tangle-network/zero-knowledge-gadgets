use crate::Vec;
use ark_ff::fields::PrimeField;
use ark_r1cs_std::{
	eq::EqGadget,
	fields::{fp::FpVar, FieldVar},
	prelude::*,
};
use ark_relations::r1cs::SynthesisError;

pub struct SetGadget<F: PrimeField> {
	set: Vec<FpVar<F>>,
}

impl<F: PrimeField> SetGadget<F> {
	pub fn new(set: Vec<FpVar<F>>) -> Self {
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
