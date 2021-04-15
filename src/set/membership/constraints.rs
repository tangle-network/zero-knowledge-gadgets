use super::{Private, Public, SetMembership};
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
pub struct PublicVar<F: PrimeField> {
	pub target: FpVar<F>,
	pub set: Vec<FpVar<F>>,
}

impl<F: PrimeField> PublicVar<F> {
	pub fn new(target: FpVar<F>, set: Vec<FpVar<F>>) -> Self {
		Self { target, set }
	}
}

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
	type PublicVar = PublicVar<F>;

	fn check_membership(
		p: &Self::PublicVar,
		s: &Self::PrivateVar,
	) -> Result<Boolean<F>, SynthesisError> {
		let mut product = FpVar::<F>::zero();
		for (diff, real) in s.diffs.iter().zip(p.set.iter()) {
			real.enforce_equal(&(diff + &p.target))?;
			product *= diff;
		}

		Ok(product.is_eq(&FpVar::<F>::zero())?)
	}
}

impl<F: PrimeField> AllocVar<Public<F>, F> for PublicVar<F> {
	fn new_variable<T: Borrow<Public<F>>>(
		into_ns: impl Into<Namespace<F>>,
		f: impl FnOnce() -> Result<T, SynthesisError>,
		mode: AllocationMode,
	) -> Result<Self, SynthesisError> {
		let inp = f()?.borrow().clone();
		let ns = into_ns.into();
		let cs = ns.cs();
		let target_var = FpVar::<F>::new_variable(cs.clone(), || Ok(inp.target), mode)?;
		let set_var = Vec::<FpVar<F>>::new_variable(cs.clone(), || Ok(inp.set), mode)?;
		Ok(PublicVar::new(target_var, set_var))
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
		let p = Public::new(root, set.clone());
		let s = TestSetMembership::generate_secrets(&root, set);
		let product = TestSetMembership::check_membership(&p, &s).unwrap();

		// Constraint version
		let cs = ConstraintSystem::<Fq>::new_ref();
		let p_var = PublicVar::new_input(cs.clone(), || Ok(p)).unwrap();
		let s_var = PrivateVar::new_witness(cs, || Ok(s)).unwrap();
		let is_member = TestSetMembershipGadget::check_membership(&p_var, &s_var).unwrap();

		let is_member_native = Boolean::<Fq>::Constant(product);
		is_member_native.enforce_equal(&is_member).unwrap();
		is_member.enforce_equal(&Boolean::TRUE).unwrap();
	}
}
