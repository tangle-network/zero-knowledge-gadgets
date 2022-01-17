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

#[cfg(test)]
mod test {
	use super::*;
	use ark_bls12_381::Fr;
	use ark_relations::r1cs::ConstraintSystem;

	#[test]
	fn should_verify_set_membership() {
		let cs = ConstraintSystem::<Fr>::new_ref();

		let set = vec![Fr::from(0u32), Fr::from(1u32), Fr::from(2u32)];
		let target = Fr::from(0u32);
		let target_var = FpVar::<Fr>::new_input(cs.clone(), || Ok(target)).unwrap();
		let set_var = Vec::<FpVar<Fr>>::new_input(cs.clone(), || Ok(set)).unwrap();

		let set_gadget = SetGadget::new(set_var);
		let is_member = set_gadget.check_membership(&target_var).unwrap();

		is_member.enforce_equal(&Boolean::TRUE).unwrap();

		assert!(cs.is_satisfied().unwrap());
	}

	#[test]
	fn should_verify_set_non_membership() {
		let cs = ConstraintSystem::<Fr>::new_ref();

		let set = vec![Fr::from(0u32), Fr::from(1u32), Fr::from(2u32)];
		let target = Fr::from(3u32);
		let target_var = FpVar::<Fr>::new_input(cs.clone(), || Ok(target)).unwrap();
		let set_var = Vec::<FpVar<Fr>>::new_input(cs.clone(), || Ok(set)).unwrap();

		let set_gadget = SetGadget::new(set_var);
		let is_member = set_gadget.check_membership(&target_var).unwrap();

		is_member.enforce_equal(&Boolean::FALSE).unwrap();

		assert!(cs.is_satisfied().unwrap());
	}
}