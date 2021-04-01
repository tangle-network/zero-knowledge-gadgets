use super::{BasicLeaf, Secrets};
use crate::leaf::{LeafCreation, LeafCreationGadget};
use ark_ff::fields::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::marker::PhantomData;
use core::borrow::Borrow;
use webb_crypto_primitives::{crh::FixedLengthCRHGadget, FixedLengthCRH};

#[derive(Clone)]
pub struct SecretsVar<F: PrimeField> {
	r: FpVar<F>,
	nullifier: FpVar<F>,
}

impl<F: PrimeField> SecretsVar<F> {
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
	type SecretsVar = SecretsVar<F>;

	fn create(
		s: &Self::SecretsVar,
		p: &HG::ParametersVar,
	) -> Result<Self::OutputVar, SynthesisError> {
		let mut bytes = Vec::new();
		bytes.extend(s.r.to_bytes().unwrap());
		bytes.extend(s.nullifier.to_bytes().unwrap());

		let bits = vec![Boolean::new_input(bytes.cs(), || Ok(false)).unwrap(); 8];
		let mut buffer = vec![UInt8::from_bits_le(&bits); H::INPUT_SIZE_BITS / 8];

		buffer.iter_mut().zip(bytes).for_each(|(b, l_b)| *b = l_b);
		HG::evaluate(p, &buffer)
	}
}

impl<F: PrimeField> AllocVar<Secrets<F>, F> for SecretsVar<F> {
	fn new_variable<T: Borrow<Secrets<F>>>(
		cs: impl Into<Namespace<F>>,
		f: impl FnOnce() -> Result<T, SynthesisError>,
		mode: AllocationMode,
	) -> Result<Self, SynthesisError> {
		let secrets = f()?.borrow().clone();
		let r = secrets.r;
		let nullifier = secrets.nullifier;
		let r_var = FpVar::new_variable(cs, || Ok(r), mode)?;
		let nullifier_var = FpVar::new_variable(r_var.cs(), || Ok(nullifier), mode)?;
		Ok(SecretsVar::new(r_var, nullifier_var))
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
	fn should_crate_leaf_constraints() {
		let rng = &mut test_rng();

		let cs = ConstraintSystem::<Fq>::new_ref();

		let rounds = get_rounds_3::<Fq>();
		let mds = get_mds_3::<Fq>();
		let params = PoseidonParameters::<Fq>::new(rounds, mds);
		let params_var = PoseidonParametersVar::new_variable(
			cs.clone(),
			|| Ok(&params),
			AllocationMode::Constant,
		)
		.unwrap();

		let secrets = Leaf::generate_secrets(rng).unwrap();
		let secrets_var = SecretsVar::new_witness(cs, || Ok(&secrets)).unwrap();

		let leaf = Leaf::create(&secrets, &params).unwrap();
		let leaf_var = LeafGadget::create(&secrets_var, &params_var).unwrap();

		let leaf_new_var = FpVar::<Fq>::new_witness(leaf_var.cs(), || Ok(leaf)).unwrap();
		let res = leaf_var.is_eq(&leaf_new_var).unwrap();
		assert!(res.value().unwrap());
		assert!(res.cs().is_satisfied().unwrap());
	}
}
