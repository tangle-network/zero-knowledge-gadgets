use super::{Private, SetMembership};
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
pub struct PrivateVar<F: PrimeField> {
	pub diffs: Vec<FpVar<F>>,
}

impl<F: PrimeField> PrivateVar<F> {
	pub fn new(diffs: Vec<FpVar<F>>) -> Self {
		Self { diffs }
	}
}
#[derive(Clone)]
pub struct SetMembershipGadget<F: PrimeField> {
	field: PhantomData<F>,
}

impl<F: PrimeField> SetGadget<F, SetMembership<F>> for SetMembershipGadget<F> {
	type PrivateVar = PrivateVar<F>;

	fn check<T: ToBytesGadget<F>>(
		target: &T,
		set: &Vec<FpVar<F>>,
		private: &Self::PrivateVar,
	) -> Result<Boolean<F>, SynthesisError> {
		let target = Boolean::le_bits_to_fp_var(&target.to_bytes()?.to_bits_le()?)?;
		let mut product = FpVar::<F>::zero();
		for (diff, real) in private.diffs.iter().zip(set.iter()) {
			real.enforce_equal(&(diff + &target))?;
			product *= diff;
		}

		Ok(product.is_eq(&FpVar::<F>::zero())?)
	}
}

impl<F: PrimeField> AllocVar<Private<F>, F> for PrivateVar<F> {
	fn new_variable<T: Borrow<Private<F>>>(
		into_ns: impl Into<Namespace<F>>,
		f: impl FnOnce() -> Result<T, SynthesisError>,
		mode: AllocationMode,
	) -> Result<Self, SynthesisError> {
		let inp = f()?.borrow().clone();
		let diffs_var = Vec::<FpVar<F>>::new_variable(into_ns, || Ok(inp.diffs), mode)?;
		Ok(PrivateVar::new(diffs_var))
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
		let s = TestSetMembership::generate_secrets(&root, &set).unwrap();
		let product = TestSetMembership::check(&root, &s).unwrap();

		// Constraint version
		let cs = ConstraintSystem::<Fq>::new_ref();
		let private_var = PrivateVar::new_witness(cs.clone(), || Ok(s)).unwrap();
		let root_var = FpVar::<Fq>::new_input(cs.clone(), || Ok(root)).unwrap();
		let set_var = Vec::<FpVar<Fq>>::new_input(cs, || Ok(set)).unwrap();
		let is_member = TestSetMembershipGadget::check(&root_var, &set_var, &private_var).unwrap();

		let is_member_native = Boolean::<Fq>::Constant(product);
		is_member_native.enforce_equal(&is_member).unwrap();
		is_member.enforce_equal(&Boolean::TRUE).unwrap();
	}
}
