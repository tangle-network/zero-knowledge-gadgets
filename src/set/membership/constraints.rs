use super::{Input, SetMembership};
use ark_ff::fields::PrimeField;
use ark_r1cs_std::{
	eq::EqGadget,
	fields::{fp::FpVar, FieldVar},
	prelude::*,
};
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::marker::PhantomData;
use core::borrow::Borrow;

use crate::set::constraints::SetGadget;

#[derive(Clone)]
pub struct InputVar<F: PrimeField> {
	pub diffs: Vec<FpVar<F>>,
	pub target: FpVar<F>,
	pub set: Vec<FpVar<F>>,
}

impl<F: PrimeField> InputVar<F> {
	pub fn new(target: FpVar<F>, diffs: Vec<FpVar<F>>, set: Vec<FpVar<F>>) -> Self {
		Self { target, diffs, set }
	}
}

#[derive(Clone)]
pub struct SetMembershipGadget<F: PrimeField> {
	field: PhantomData<F>,
}

impl<F: PrimeField> SetGadget<F, SetMembership<F>> for SetMembershipGadget<F> {
	type InputVar = InputVar<F>;

	fn check_membership(input: &Self::InputVar) -> Result<Boolean<F>, SynthesisError> {
		let mut product = FpVar::<F>::zero();
		for (diff, real) in input.diffs.iter().zip(input.set.iter()) {
			real.enforce_equal(&(diff + &input.target))?;
			product *= diff;
		}

		Ok(product.is_eq(&FpVar::<F>::zero())?)
	}
}

impl<F: PrimeField> AllocVar<Input<F>, F> for InputVar<F> {
	fn new_variable<T: Borrow<Input<F>>>(
		cs: impl Into<Namespace<F>>,
		f: impl FnOnce() -> Result<T, SynthesisError>,
		_: AllocationMode,
	) -> Result<Self, SynthesisError> {
		let inp = f()?.borrow().clone();
		let target_var = FpVar::<F>::new_input(cs, || Ok(inp.target))?;
		let set_var = inp
			.set
			.iter()
			.map(|x| FpVar::<F>::new_input(target_var.cs(), || Ok(x)))
			.collect::<Result<Vec<_>, _>>()?;
		let diffs_var = inp
			.diffs
			.iter()
			.map(|x| FpVar::<F>::new_witness(target_var.cs(), || Ok(x)))
			.collect::<Result<Vec<_>, _>>()?;
		Ok(InputVar::new(target_var, diffs_var, set_var))
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::set::Set;
	use ark_ed_on_bn254::Fq;
	use ark_ff::UniformRand;
	use ark_relations::r1cs::ConstraintSystem;
	use ark_std::test_rng;

	type TestSetMembership = SetMembership<Fq>;
	type TestSetMembershipGadget = SetMembershipGadget<Fq>;
	#[test]
	fn test_native_equality() {
		let rng = &mut test_rng();
		let root = Fq::rand(rng);
		let mut set = vec![Fq::rand(rng); 5];
		set.push(root);

		// Native
		let input = TestSetMembership::generate_inputs(&root, set);
		let product = TestSetMembership::check_membership(&input).unwrap();

		// Constraint version
		let cs = ConstraintSystem::<Fq>::new_ref();
		let input_var = InputVar::new_variable(cs, || Ok(input), AllocationMode::Input).unwrap();
		let is_member = TestSetMembershipGadget::check_membership(&input_var).unwrap();

		let is_member_native = Boolean::<Fq>::Constant(product);
		is_member_native.enforce_equal(&is_member).unwrap();
		is_member.enforce_equal(&Boolean::TRUE).unwrap();
	}
}
