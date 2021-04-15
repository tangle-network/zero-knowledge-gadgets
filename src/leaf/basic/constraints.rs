use super::{BasicLeaf, Private, Public};
use crate::leaf::{LeafCreation, LeafCreationGadget};
use ark_ff::fields::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::marker::PhantomData;
use core::borrow::Borrow;
use webb_crypto_primitives::{
	crh::{poseidon::constraints::to_field_var_bytes, FixedLengthCRHGadget},
	FixedLengthCRH,
};

#[derive(Clone)]
pub struct PrivateVar<F: PrimeField> {
	r: FpVar<F>,
	nullifier: FpVar<F>,
}

#[derive(Clone, Default)]
pub struct PublicVar<F: PrimeField> {
	f: PhantomData<F>,
}

impl<F: PrimeField> PrivateVar<F> {
	pub fn new(r: FpVar<F>, nullifier: FpVar<F>) -> Self {
		Self { r, nullifier }
	}
}

pub struct BasicLeafGadget<
	F: PrimeField,
	H: FixedLengthCRH,
	HG: FixedLengthCRHGadget<H, F>,
	L: LeafCreation<H>,
> {
	field: PhantomData<F>,
	hasher: PhantomData<H>,
	hasher_gadget: PhantomData<HG>,
	leaf_creation: PhantomData<L>,
}

impl<F: PrimeField, H: FixedLengthCRH, HG: FixedLengthCRHGadget<H, F>>
	LeafCreationGadget<F, H, HG, BasicLeaf<F, H>> for BasicLeafGadget<F, H, HG, BasicLeaf<F, H>>
{
	type OutputVar = HG::OutputVar;
	type PrivateVar = PrivateVar<F>;
	type PublicVar = PublicVar<F>;

	fn create(
		s: &Self::PrivateVar,
		_: &Self::PublicVar,
		h: &HG::ParametersVar,
	) -> Result<Self::OutputVar, SynthesisError> {
		let bytes = to_field_var_bytes(&[s.r.clone(), s.nullifier.clone()])?;
		HG::evaluate(h, &bytes)
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

		let r = secrets.r;
		let nullifier = secrets.nullifier;
		let r_var = FpVar::new_variable(cs.clone(), || Ok(r), mode)?;
		let nullifier_var = FpVar::new_variable(cs.clone(), || Ok(nullifier), mode)?;
		Ok(PrivateVar::new(r_var, nullifier_var))
	}
}

impl<F: PrimeField> AllocVar<Public<F>, F> for PublicVar<F> {
	fn new_variable<T: Borrow<Public<F>>>(
		_: impl Into<Namespace<F>>,
		_: impl FnOnce() -> Result<T, SynthesisError>,
		_: AllocationMode,
	) -> Result<Self, SynthesisError> {
		Ok(PublicVar::default())
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::test_data::{get_mds_3, get_rounds_3};
	use ark_ed_on_bn254::Fq;
	use ark_relations::r1cs::ConstraintSystem;
	use ark_std::test_rng;
	use webb_crypto_primitives::crh::poseidon::{
		constraints::{CRHGadget, PoseidonParametersVar},
		sbox::PoseidonSbox,
		PoseidonParameters, Rounds, CRH,
	};

	#[derive(Default, Clone)]
	struct PoseidonRounds3;

	impl Rounds for PoseidonRounds3 {
		const FULL_ROUNDS: usize = 8;
		const PARTIAL_ROUNDS: usize = 57;
		const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
		const WIDTH: usize = 3;
	}

	type PoseidonCRH3 = CRH<Fq, PoseidonRounds3>;
	type PoseidonCRH3Gadget = CRHGadget<Fq, PoseidonRounds3>;

	type Leaf = BasicLeaf<Fq, PoseidonCRH3>;
	type LeafGadget = BasicLeafGadget<Fq, PoseidonCRH3, PoseidonCRH3Gadget, Leaf>;
	#[test]
	fn should_crate_basic_leaf_constraints() {
		let rng = &mut test_rng();

		let cs = ConstraintSystem::<Fq>::new_ref();

		let rounds = get_rounds_3::<Fq>();
		let mds = get_mds_3::<Fq>();

		// Native version
		let public = Public::default();
		let secrets = Leaf::generate_secrets(rng).unwrap();
		let params = PoseidonParameters::<Fq>::new(rounds, mds);
		let leaf = Leaf::create(&secrets, &public, &params).unwrap();

		// Constraints version
		let public_var = PublicVar::default();
		let secrets_var = PrivateVar::new_witness(cs.clone(), || Ok(&secrets)).unwrap();
		let params_var =
			PoseidonParametersVar::new_variable(cs, || Ok(&params), AllocationMode::Constant)
				.unwrap();

		let leaf_var = LeafGadget::create(&secrets_var, &public_var, &params_var).unwrap();

		// Check equality
		let leaf_new_var = FpVar::<Fq>::new_witness(leaf_var.cs(), || Ok(leaf)).unwrap();
		let res = leaf_var.is_eq(&leaf_new_var).unwrap();
		assert!(res.value().unwrap());
		assert!(res.cs().is_satisfied().unwrap());
	}
}
