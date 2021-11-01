use super::{NewLeaf1, Private, Public};
use crate::{
	leaf::{NewLeafCreation, NewLeafCreationGadget},
	Vec,
};
use ark_crypto_primitives::{crh::CRHGadget, CRH};
use ark_ff::fields::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::marker::PhantomData;
use core::borrow::Borrow;

#[derive(Clone)]
pub struct PrivateVar<F: PrimeField> {
	r: FpVar<F>,
	nullifier: FpVar<F>,
	amount: FpVar<F>,
	blinding: FpVar<F>,
	priv_key: FpVar<F>,
	merkle_path: Vec<FpVar<F>>,
}

#[derive(Clone, Default)]
pub struct PublicVar<F: PrimeField> {
	f: PhantomData<F>,
}

impl<F: PrimeField> PrivateVar<F> {
	pub fn new(r: FpVar<F>, nullifier: FpVar<F>, amount: FpVar<F>, blinding: FpVar<F>,
		priv_key: FpVar<F>, merkle_path: Vec<FpVar<F>>) -> Self {
		Self { r, nullifier, amount, blinding, priv_key, merkle_path }
	}
}

pub struct NewLeafGadget<F: PrimeField, H1: CRH, H2: CRH, HG1: CRHGadget<H1, F>, HG2: CRHGadget<H2, F>, L: NewLeafCreation<H1,H2>> {
	field: PhantomData<F>,
	hasher1: PhantomData<H1>,
	hasher_gadget1: PhantomData<HG1>,
	hasher2: PhantomData<H2>,
	hasher_gadget2: PhantomData<HG2>,
	leaf_creation: PhantomData<L>,
}

impl<F: PrimeField, H1: CRH, H2: CRH, HG1: CRHGadget<H1, F>, HG2: CRHGadget<H2, F>> NewLeafCreationGadget<F, H1, H2, HG1, HG2 , NewLeaf1<F, H1,H2>>// TODO: Change
	for NewLeafGadget<F, H1, H2, HG1, HG2, NewLeaf1<F, H1, H2>>// TODO: Change
{
	type LeafVar = HG1::OutputVar;
	type NullifierVar = HG2::OutputVar;
	type PrivateVar = PrivateVar<F>;
	type PublicVar = PublicVar<F>;

	fn create_leaf(
		s: &Self::PrivateVar,
		_: &Self::PublicVar,
		h: &HG1::ParametersVar,
	) -> Result<Self::LeafVar, SynthesisError> {
		let mut bytes = Vec::new();
		bytes.extend(s.r.to_bytes()?);
		bytes.extend(s.nullifier.to_bytes()?);
		HG1::evaluate(h, &bytes)
	}

	fn create_nullifier(
		s: &Self::PrivateVar,
		c: &Self::LeafVar,
		h: &HG2::ParametersVar,
	) -> Result<Self::NullifierVar, SynthesisError> {
		let mut bytes = Vec::new();
		bytes.extend(s.nullifier.to_bytes()?);
		bytes.extend(s.nullifier.to_bytes()?);
		HG2::evaluate(h, &bytes)
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
		let amount = secrets.amount;
		let blinding = secrets.blinding;
		let priv_key = secrets.priv_key;
		let merkle_path = secrets.merkle_path;
		
		let r_var = FpVar::new_variable(cs.clone(), || Ok(r), mode)?;
		let nullifier_var = FpVar::new_variable(cs.clone(), || Ok(nullifier), mode)?;
		let amount_var=FpVar::new_variable(cs.clone(), || Ok(amount), mode)?;
		let blinding_var=FpVar::new_variable(cs.clone(), || Ok(blinding), mode)?;
		let priv_key_var=FpVar::new_variable(cs.clone(), || Ok(priv_key), mode)?;
		let merkle_path_var=FpVar::new_witness(cs.clone(), || {
			Ok(merkle_path.as_ref().unwrap())
		})?;
		Ok(PrivateVar::new(r_var, nullifier_var, amount_var,blinding_var,priv_key_var,merkle_path_var))
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

#[cfg(feature = "default_poseidon")]
#[cfg(test)]
mod test {
	use super::*;
	use crate::{
		poseidon::{
			constraints::{CRHGadget, PoseidonParametersVar},
			sbox::PoseidonSbox,
			PoseidonParameters, Rounds, CRH,
		},
		utils::{get_mds_poseidon_bls381_x5_3, get_rounds_poseidon_bls381_x5_3},
	};
	use ark_bls12_381::Fq;
	use ark_relations::r1cs::ConstraintSystem;
	use ark_std::test_rng;

	#[derive(Default, Clone)]
	struct PoseidonRounds3;

	impl Rounds for PoseidonRounds3 {
		const FULL_ROUNDS: usize = 8;
		const PARTIAL_ROUNDS: usize = 57;
		const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
		const WIDTH: usize = 3;
	}

	#[derive(Default, Clone)]
	struct PoseidonRounds3_1;

	impl Rounds for PoseidonRounds3_1 {
		const FULL_ROUNDS: usize = 8;
		const PARTIAL_ROUNDS: usize = 57;
		const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
		const WIDTH: usize = 4;
	}

	type PoseidonCRH3_1 = CRH<Fq, PoseidonRounds3_1>;
	type PoseidonCRH3 = CRH<Fq, PoseidonRounds3>;
	type PoseidonCRH3Gadget = CRHGadget<Fq, PoseidonRounds3>;
	type PoseidonCRH3Gadget1 = CRHGadget<Fq, PoseidonRounds3_1>;

	type Leaf = NewLeaf1<Fq, PoseidonCRH3, PoseidonCRH3_1>; // TODO: Change
	type LeafGadget = NewLeafGadget<Fq, PoseidonCRH3, PoseidonCRH3_1, PoseidonCRH3Gadget, PoseidonCRH3Gadget1, Leaf>;
	#[test]
	fn should_crate_basic_leaf_constraints() {
		let rng = &mut test_rng();

		let cs = ConstraintSystem::<Fq>::new_ref();

		let rounds = get_rounds_poseidon_bls381_x5_3::<Fq>();
		let mds = get_mds_poseidon_bls381_x5_3::<Fq>();

		// Native version
		let public = Public::default();
		let secrets = Leaf::generate_secrets(rng).unwrap();
		let params = PoseidonParameters::<Fq>::new(rounds, mds);
		let leaf = Leaf::create_leaf(&secrets, &public, &params).unwrap();

		// Constraints version
		let public_var = PublicVar::default();
		let secrets_var = PrivateVar::new_witness(cs.clone(), || Ok(&secrets)).unwrap();
		let params_var =
			PoseidonParametersVar::new_variable(cs, || Ok(&params), AllocationMode::Constant)
				.unwrap();

		let leaf_var = LeafGadget::create_leaf(&secrets_var, &public_var, &params_var).unwrap();

		// Check equality
		let leaf_new_var = FpVar::<Fq>::new_witness(leaf_var.cs(), || Ok(leaf)).unwrap();
		let res = leaf_var.is_eq(&leaf_new_var).unwrap();
		assert!(res.value().unwrap());
		assert!(res.cs().is_satisfied().unwrap());
	}
}
