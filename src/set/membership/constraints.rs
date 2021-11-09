use super::{Private, SetMembership};
use crate::Vec;
use ark_ff::fields::PrimeField;
use ark_r1cs_std::{
	eq::EqGadget,
	fields::{fp::FpVar, FieldVar},
	prelude::*,
};
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::{marker::PhantomData, panic};
use core::{borrow::Borrow, convert::TryInto};

use crate::set::constraints::SetGadget;

#[derive(Clone)]
pub struct PrivateVar<F: PrimeField, const M: usize> {
	pub diffs: [FpVar<F>; M],
}

impl<F: PrimeField, const M: usize> PrivateVar<F, M> {
	pub fn new(diffs: Vec<FpVar<F>>) -> Self {
		Self {
			diffs: diffs.try_into().unwrap_or_else(|v: Vec<FpVar<F>>| {
				panic!("Expected a Vec of length {} but it was {}", M, v.len())
			}),
		}
	}
}
#[derive(Clone)]
pub struct SetMembershipGadget<F: PrimeField, const M: usize> {
	field: PhantomData<F>,
}

impl<F: PrimeField, const M: usize> SetGadget<F, SetMembership<F, M>, M>
	for SetMembershipGadget<F, M>
{
	type PrivateVar = PrivateVar<F, M>;

	fn check<T: ToBytesGadget<F>>(
		target: &T,
		set: &Vec<FpVar<F>>,
		private: &Self::PrivateVar,
	) -> Result<Boolean<F>, SynthesisError> {
		assert_eq!(set.len(), M); // FIXME Should we enforce it in constrain system?
		let target = Boolean::le_bits_to_fp_var(&target.to_bytes()?.to_bits_le()?)?;
		let mut product = target.clone();
		for (diff, real) in private.diffs.iter().zip(set.iter()) {
			real.enforce_equal(&(diff + &target))?;
			product *= diff;
		}

		Ok(product.is_eq(&FpVar::<F>::zero())?)
	}

	fn check_is_enabled<T: ToBytesGadget<F>>(
		target: &T,
		set: &Vec<FpVar<F>>,
		private: &Self::PrivateVar,
		is_enabled: &FpVar<F>,
	) -> Result<Boolean<F>, SynthesisError> {
		assert_eq!(set.len(), M); // FIXME Should we enforce it in constrain system?
		let target = Boolean::le_bits_to_fp_var(&target.to_bytes()?.to_bits_le()?)?;
		let mut product = target.clone();
		for (diff, real) in private.diffs.iter().zip(set.iter()) {
			real.enforce_equal(&(diff + &target))?;
			product *= diff;
		}
		product *= is_enabled;
		Ok(product.is_eq(&FpVar::<F>::zero())?)
	}
}

impl<F: PrimeField, const M: usize> AllocVar<Private<F, M>, F> for PrivateVar<F, M> {
	fn new_variable<T: Borrow<Private<F, M>>>(
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
	use ark_bls12_381::Fq;
	use ark_ff::UniformRand;
	use ark_relations::r1cs::ConstraintSystem;
	use ark_std::test_rng;

	pub const TEST_M: usize = 5;

	type TestSetMembership = SetMembership<Fq, TEST_M>;
	type TestSetMembershipGadget = SetMembershipGadget<Fq, TEST_M>;
	#[test]
	fn test_native_equality() {
		let rng = &mut test_rng();
		let root = Fq::rand(rng);
		let mut set = [Fq::rand(rng); TEST_M];
		set[0] = root;

		// Native
		let s = TestSetMembership::generate_secrets(&root, &set).unwrap();
		let product = TestSetMembership::check(&root, &set, &s).unwrap();

		// Constraint version
		let cs = ConstraintSystem::<Fq>::new_ref();
		let private_var = PrivateVar::new_witness(cs.clone(), || Ok(s)).unwrap();
		let root_var = FpVar::<Fq>::new_input(cs.clone(), || Ok(root)).unwrap();
		let set_var = Vec::<FpVar<Fq>>::new_input(cs, || Ok(set)).unwrap();
		let is_member = TestSetMembershipGadget::check(&root_var, &set_var, &private_var).unwrap();

		let is_member_native = Boolean::<Fq>::Constant(product);
		is_member_native.enforce_equal(&is_member).unwrap();
		is_member.enforce_equal(&Boolean::TRUE).unwrap();
		assert!(is_member.cs().is_satisfied().unwrap());
	}

	#[test]
	fn membership_success() {
		let rng = &mut test_rng();
		let root = Fq::rand(rng);
		let mut set = [Fq::rand(rng); TEST_M];
		set[0] = root;
		let s = TestSetMembership::generate_secrets(&root, &set).unwrap();

		let cs = ConstraintSystem::<Fq>::new_ref();
		let private_var = PrivateVar::new_witness(cs.clone(), || Ok(s)).unwrap();
		let set_var = Vec::<FpVar<Fq>>::new_input(cs.clone(), || Ok(set)).unwrap();

		let root_var = FpVar::<Fq>::new_input(cs.clone(), || Ok(root)).unwrap();
		let is_member = TestSetMembershipGadget::check(&root_var, &set_var, &private_var).unwrap();
		is_member.enforce_equal(&Boolean::TRUE).unwrap();
		assert!(is_member.cs().is_satisfied().unwrap());

		let wrong_root = Fq::rand(rng);
		let wrong_root_var = FpVar::<Fq>::new_input(cs.clone(), || Ok(wrong_root)).unwrap();
		let is_member =
			TestSetMembershipGadget::check(&wrong_root_var, &set_var, &private_var).unwrap();
		is_member.enforce_equal(&Boolean::TRUE).unwrap();
		assert!(!is_member.cs().is_satisfied().unwrap());
	}

	#[should_panic(expected = "assertion failed: `(left == right)`
  left: `4`,
 right: `5`")]
	#[test]
	fn wrong_prover_set_size() {
		let rng = &mut test_rng();
		let root = Fq::rand(rng);
		let mut set = [Fq::rand(rng); TEST_M];
		set[0] = root;
		let s = TestSetMembership::generate_secrets(&root, &set).unwrap();

		let cs = ConstraintSystem::<Fq>::new_ref();
		let private_var = PrivateVar::new_witness(cs.clone(), || Ok(s)).unwrap();
		let root_var = FpVar::<Fq>::new_input(cs.clone(), || Ok(root)).unwrap();

		// same as set for which secret is generated but one less in size
		let another_set = [set[0], set[1], set[2], set[3]];
		let another_set_var = Vec::<FpVar<Fq>>::new_input(cs.clone(), || Ok(another_set)).unwrap();
		let is_member =
			TestSetMembershipGadget::check(&root_var, &another_set_var, &private_var).unwrap();
		is_member.enforce_equal(&Boolean::TRUE).unwrap();
		assert!(is_member.cs().is_satisfied().unwrap());
	}
}
