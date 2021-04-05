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
	diffs: Vec<FpVar<F>>,
	target: FpVar<F>,
	set: Vec<FpVar<F>>,
}

impl<F: PrimeField> InputVar<F> {
	pub fn new(target: FpVar<F>, diffs: Vec<FpVar<F>>, set: Vec<FpVar<F>>) -> Self {
		Self { target, diffs, set }
	}
}

pub struct SetMembershipGadget<F: PrimeField> {
	field: PhantomData<F>,
}

impl<F: PrimeField> SetGadget<F, SetMembership<F>> for SetMembershipGadget<F> {
	type InputVar = InputVar<F>;
	type OutputVar = FpVar<F>;

	fn product(input: &Self::InputVar) -> Result<Self::OutputVar, SynthesisError> {
		let mut product = FpVar::<F>::zero();
		for (diff, real) in input.diffs.iter().zip(input.set.iter()) {
			real.is_eq(&(diff + &input.target))?.cs().is_satisfied()?;
			product *= diff;
		}

		Ok(product)
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
