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
	pub amount: FpVar<F>,
	blinding: FpVar<F>,
}

#[derive(Clone)]
pub struct PublicVar<F: PrimeField> {
	chain_id: FpVar<F>,
}

impl<F: PrimeField> PublicVar<F> {
	pub fn default() -> Self {
		let chain_id = F::zero();

		Self {
			chain_id: FpVar::Constant(chain_id),
		}
	}

	pub fn new(chain_id: FpVar<F>) -> Self {
		Self { chain_id }
	}
}

impl<F: PrimeField> PrivateVar<F> {
	pub fn new(amount: FpVar<F>, blinding: FpVar<F>) -> Self {
		Self { amount, blinding }
	}
}

pub struct VAnchorLeafGadget<F: PrimeField, HG: FieldHasherGadget<F>> {
	field: PhantomData<F>,
	hasher_gadget: PhantomData<HG>,
}

impl<F: PrimeField, HG: FieldHasherGadget<F>> VAnchorLeafGadget<F, HG> {
	pub fn create_leaf(
		private: &PrivateVar<F>,
		public: &PublicVar<F>,
		public_key: &FpVar<F>,
		h_w5: &HG,
	) -> Result<FpVar<F>, SynthesisError> {
		h_w5.hash(&[
			public.chain_id.clone(),
			private.amount.clone(),
			public_key.clone(),
			private.blinding.clone(),
		])
	}

	pub fn create_nullifier(
		signature: &FpVar<F>,
		commitment: &FpVar<F>,
		index: &FpVar<F>,
		h_w4: &HG,
	) -> Result<FpVar<F>, SynthesisError> {
		h_w4.hash(&[commitment.clone(), index.clone(), signature.clone()])
	}
}

impl<F: PrimeField> AllocVar<Private<F>, F> for PrivateVar<F> {
	fn new_variable<T: Borrow<Private<F>>>(
		into_ns: impl Into<Namespace<F>>,
		f: impl FnOnce() -> Result<T, SynthesisError>,
		mode: AllocationMode,
	) -> Result<Self, SynthesisError> {
		let secrets = f()?.borrow().clone();
		let ns = into_ns.into();
		let cs = ns.cs();

		let amount = secrets.amount;
		let blinding = secrets.blinding;

		let amount_var = FpVar::new_variable(cs.clone(), || Ok(amount), mode)?;
		let blinding_var = FpVar::new_variable(cs, || Ok(blinding), mode)?;
		Ok(PrivateVar::new(amount_var, blinding_var))
	}
}

impl<F: PrimeField> AllocVar<Public<F>, F> for PublicVar<F> {
	fn new_variable<T: Borrow<Public<F>>>(
		into_ns: impl Into<Namespace<F>>,
		f: impl FnOnce() -> Result<T, SynthesisError>,
		mode: AllocationMode,
	) -> Result<Self, SynthesisError> {
		let public = f()?.borrow().clone();
		let ns = into_ns.into();
		let cs = ns.cs();
		let chain_id = FpVar::new_variable(cs, || Ok(public.chain_id), mode)?;
		Ok(PublicVar::new(chain_id))
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::{
		ark_std::{One, UniformRand},
		leaf::vanchor::VAnchorLeaf,
		poseidon::{
			field_hasher::{FieldHasher, Poseidon},
			field_hasher_constraints::{PoseidonGadget, PoseidonParametersVar},
			CRH,
		},
	};

	//use ark_bls12_381::Fq;
	use ark_bn254::Fq;

	use ark_relations::r1cs::ConstraintSystem;
	use ark_std::test_rng;
	use arkworks_utils::utils::common::{
		setup_params_x5_2, setup_params_x5_4, setup_params_x5_5, Curve,
	};

	type Leaf = VAnchorLeaf<Fq, Poseidon<Fq>>;
	type LeafGadget = VAnchorLeafGadget<Fq, PoseidonGadget<Fq>>;
	#[test]
	fn should_crate_new_leaf_constraints() {
		let rng = &mut test_rng();
		let cs = ConstraintSystem::<Fq>::new_ref();
		let curve = Curve::Bn254;

		// Native version

		let params5_2 = setup_params_x5_2(curve);
		let params5_5 = setup_params_x5_5(curve);
		let hasher2 = Poseidon::<Fq>::new(params5_2.clone());
		let hasher5 = Poseidon::<Fq>::new(params5_5.clone());

		let chain_id = Fq::one();
		let index = Fq::one();
		let public = Public::new(chain_id);
		let secrets = Private::generate(rng);
		let private_key = Fq::rand(rng);
		let public_key = hasher2.hash(&[private_key]).unwrap();
		let leaf = Leaf::create_leaf(&secrets, &public, &public_key, &hasher5).unwrap();

		// Constraints version
		let index_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(index)).unwrap();
		let public_var = PublicVar::new_input(cs.clone(), || Ok(&public)).unwrap();
		let secrets_var = PrivateVar::new_witness(cs.clone(), || Ok(&secrets)).unwrap();
		let private_key_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(&private_key)).unwrap();
		let params_var5_5 = PoseidonParametersVar::new_variable(
			cs.clone(),
			|| Ok(&params5_5),
			AllocationMode::Constant,
		)
		.unwrap();
		let params_var5_2 = PoseidonParametersVar::new_variable(
			cs.clone(),
			|| Ok(&params5_2),
			AllocationMode::Constant,
		)
		.unwrap();
		let hasher_gadget2 = PoseidonGadget::<Fq> {
			params: params_var5_2,
		};
		let hasher_gadget5 = PoseidonGadget::<Fq> {
			params: params_var5_5,
		};

		let mut bytes = Vec::new();
		bytes.extend(private_key_var.to_bytes().unwrap());
		let public_key_var = hasher_gadget2.hash(&[private_key_var.clone()]).unwrap();

		let leaf_var =
			LeafGadget::create_leaf(&secrets_var, &public_var, &public_key_var, &hasher_gadget5)
				.unwrap();

		// Check equality
		let leaf_new_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(leaf)).unwrap();
		let res = leaf_var.is_eq(&leaf_new_var).unwrap();
		assert!(res.value().unwrap());
		assert!(res.cs().is_satisfied().unwrap());

		// Test Nullifier
		// Native version
		let params5_4 = setup_params_x5_4(curve);
		let hasher4 = Poseidon::<Fq>::new(params5_4.clone());
		let params_var5_4 = PoseidonParametersVar::new_variable(
			cs.clone(),
			|| Ok(&params5_4),
			AllocationMode::Constant,
		)
		.unwrap();
		let hasher_gadget4 = PoseidonGadget::<Fq> {
			params: params_var5_4,
		};
		let signature = Fq::rand(rng);
		let nullifier = Leaf::create_nullifier(&signature, &leaf, &index, &hasher4).unwrap();

		// Constraints version
		let signature_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(&signature)).unwrap();
		let nullifier_var =
			LeafGadget::create_nullifier(&signature_var, &leaf_var, &index_var, &hasher_gadget4)
				.unwrap();

		// Check equality
		let nullifier_new_var =
			FpVar::<Fq>::new_witness(nullifier_var.cs(), || Ok(nullifier)).unwrap();
		let res_nul = nullifier_var.is_eq(&nullifier_new_var).unwrap();
		assert!(res_nul.value().unwrap());
		assert!(res_nul.cs().is_satisfied().unwrap());
	}
}
