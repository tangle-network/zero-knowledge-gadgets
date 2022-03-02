use super::{Private, Public};
use crate::{
	poseidon::{field_hasher::FieldHasher, field_hasher_constraints::FieldHasherGadget},
	Vec,
};
use ark_crypto_primitives::{crh::CRHGadget, CRH};
use ark_ff::fields::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::marker::PhantomData;
use core::borrow::Borrow;

#[derive(Clone)]
pub struct PrivateVar<F: PrimeField> {
	secret: FpVar<F>,
	nullifier: FpVar<F>,
}

impl<F: PrimeField> PrivateVar<F> {
	pub fn new(secret: FpVar<F>, nullifier: FpVar<F>) -> Self {
		Self { secret, nullifier }
	}
}

#[derive(Clone)]
pub struct PublicVar<F: PrimeField> {
	chain_id: FpVar<F>,
}

impl<F: PrimeField> PublicVar<F> {
	pub fn new(chain_id: FpVar<F>) -> Self {
		Self { chain_id }
	}
}

pub struct AnchorLeafGadget<F: PrimeField, HG: FieldHasherGadget<F>> {
	field: PhantomData<F>,
	hasher_gadget: PhantomData<HG>,
}

impl<F: PrimeField, HG: FieldHasherGadget<F>> AnchorLeafGadget<F, HG> {
	// Leaf creation should match across all anchor protocol implementations
	// Solidity impl: https://github.com/webb-tools/protocol-solidity/blob/main/circuits/bridge/withdraw.circom#L5
	pub fn create_leaf(
		private: &PrivateVar<F>,
		public: &PublicVar<F>,
		hasher: &HG,
	) -> Result<FpVar<F>, SynthesisError> {
		hasher.hash(&[
			public.chain_id.clone(),
			private.nullifier.clone(),
			private.secret.clone(),
		])
	}

	pub fn create_nullifier(
		private: &PrivateVar<F>,
		hasher: &HG,
	) -> Result<FpVar<F>, SynthesisError> {
		hasher.hash_two(&private.nullifier, &private.nullifier.clone())
	}
}

impl<F: PrimeField> AllocVar<Private<F>, F> for PrivateVar<F> {
	fn new_variable<T: Borrow<Private<F>>>(
		into_ns: impl Into<Namespace<F>>,
		f: impl FnOnce() -> Result<T, SynthesisError>,
		mode: AllocationMode,
	) -> Result<Self, SynthesisError> {
		let private = f()?.borrow().clone();
		let ns = into_ns.into();
		let cs = ns.cs();

		let secret = private.secret;
		let nullifier = private.nullifier;

		let secret_var = FpVar::new_variable(cs.clone(), || Ok(secret), mode)?;
		let nullifier_var = FpVar::new_variable(cs, || Ok(nullifier), mode)?;

		Ok(PrivateVar::new(secret_var, nullifier_var))
	}
}

impl<F: PrimeField> AllocVar<Public<F>, F> for PublicVar<F> {
	fn new_variable<T: Borrow<Public<F>>>(
		cs: impl Into<Namespace<F>>,
		f: impl FnOnce() -> Result<T, SynthesisError>,
		mode: AllocationMode,
	) -> Result<Self, SynthesisError> {
		let public = f()?.borrow().clone();
		let chain_id = FpVar::new_variable(cs, || Ok(public.chain_id), mode)?;
		Ok(PublicVar::new(chain_id))
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::{
		leaf::anchor::AnchorLeaf,
		poseidon::{
			constraints::{CRHGadget, PoseidonParametersVar},
			field_hasher::Poseidon,
			field_hasher_constraints::PoseidonGadget,
			CRH,
		},
	};
	use ark_ed_on_bn254::Fq;
	use ark_ff::One;
	use ark_relations::r1cs::ConstraintSystem;
	use ark_std::test_rng;
	use arkworks_utils::utils::common::{setup_params_x5_3, setup_params_x5_4};

	type Leaf = AnchorLeaf<Fq, Poseidon<Fq>>;
	type LeafGadget = AnchorLeafGadget<Fq, PoseidonGadget<Fq>>;

	#[test]
	fn should_create_anchor_leaf_constraints() {
		let rng = &mut test_rng();
		let curve = arkworks_utils::utils::common::Curve::Bn254;

		let mut cs = ConstraintSystem::<Fq>::new_ref();

		// Native version
		let leaf_hash_params = setup_params_x5_4(curve);
		let leaf_hasher = Poseidon::<Fq>::new(leaf_hash_params);
		let nullifier_hash_params = setup_params_x5_3(curve);
		let nullifier_hasher = Poseidon::<Fq>::new(nullifier_hash_params);
		let chain_id = Fq::one();

		let public = Public::new(chain_id);
		let private = Private::generate(rng);
		let leaf_hash = Leaf::create_leaf(&private, &public, &leaf_hasher).unwrap();
		let nullifier = Leaf::create_nullifier(&private, &nullifier_hasher).unwrap();

		let leaf_hasher_gadget = FieldHasherGadget::<Fq>::from_native(&mut cs, leaf_hasher);
		let nullifier_hasher_gadget =
			FieldHasherGadget::<Fq>::from_native(&mut cs, nullifier_hasher);
		let public_var = PublicVar::new_input(cs.clone(), || Ok(&public)).unwrap();
		let private_var = PrivateVar::new_witness(cs.clone(), || Ok(&private)).unwrap();
		let leaf_hash_var =
			LeafGadget::create_leaf(&private_var, &public_var, &leaf_hasher_gadget).unwrap();
		let nullifier_var =
			LeafGadget::create_nullifier(&private_var, &nullifier_hasher_gadget).unwrap();

		// Checking equality
		let leaf_new_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(&leaf_hash)).unwrap();
		let nullifier_new_var = FpVar::<Fq>::new_witness(cs, || Ok(&nullifier)).unwrap();
		let leaf_res = leaf_hash_var.is_eq(&leaf_new_var).unwrap();
		let nullifier_res = nullifier_var.is_eq(&nullifier_new_var).unwrap();
		assert!(leaf_res.value().unwrap());
		assert!(leaf_res.cs().is_satisfied().unwrap());
		assert!(nullifier_res.value().unwrap());
		assert!(nullifier_res.cs().is_satisfied().unwrap());
	}
}
