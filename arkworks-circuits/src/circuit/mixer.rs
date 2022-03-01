use ark_crypto_primitives::{crh::{constraints::CRHGadget}, CRH};
use ark_ff::fields::PrimeField;
use ark_r1cs_std::{eq::EqGadget, fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::marker::PhantomData;
use arkworks_gadgets::{
	arbitrary::mixer_data::{constraints::InputVar as ArbitraryInputVar, Input as ArbitraryInput},
	leaf::mixer::{
		constraints::{MixerLeafGadget, PrivateVar as LeafPrivateVar},
		Private as LeafPrivate,
	},
	merkle_tree::{simple_merkle::Path, simple_merkle_constraints::PathVar},
	poseidon::{
		field_hasher::{FieldHasher, Poseidon},
		field_hasher_constraints::{FieldHasherGadget, PoseidonParametersVar, PoseidonGadget},
	},
};

#[derive(Clone)]
pub struct MixerCircuit<
	F: PrimeField,
	HG: FieldHasherGadget<F>,
	const N: usize,
> {
	arbitrary_input: ArbitraryInput<F>,
	leaf_private_inputs: LeafPrivate<F>,
	path: Path<F, HG::Native, N>,
	root: F,
	nullifier_hash: F,
	hasher: HG::Native,
}

impl<F, HG, const N: usize> MixerCircuit<F, HG, N>
where
	F: PrimeField,
	HG: FieldHasherGadget<F>,
{
	pub fn new(
		arbitrary_input: ArbitraryInput<F>,
		leaf_private_inputs: LeafPrivate<F>,
		path: Path<F, HG::Native, N>,
		root: F,
		nullifier_hash: F,
		hasher: HG::Native,
	) -> Self {
		Self {
			arbitrary_input,
			leaf_private_inputs,
			path,
			root,
			nullifier_hash,
			hasher,
		}
	}
}

impl<F, HG, const N: usize> ConstraintSynthesizer<F> for MixerCircuit<F, HG, N>
where
	F: PrimeField,
	HG: FieldHasherGadget<F>,
{
	fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
		let arbitrary_input = self.arbitrary_input;
		let leaf_private = self.leaf_private_inputs;
		let path = self.path;
		let root = self.root;
		let nullifier_hash = self.nullifier_hash;

		// Generating vars
		// Public inputs
		let nullifier_hash_var = FpVar::<F>::new_input(cs.clone(), || Ok(nullifier_hash))?;
		let root_var = FpVar::<F>::new_input(cs.clone(), || Ok(root))?;
		let arbitrary_input_var = ArbitraryInputVar::new_input(cs.clone(), || Ok(arbitrary_input))?;

		// Hashers
		let hasher: HG = FieldHasherGadget::<F>::from_native(&mut cs.clone(), self.hasher);

		// Private inputs
		let leaf_private_var = LeafPrivateVar::new_witness(cs.clone(), || Ok(leaf_private))?;
		let path_var = PathVar::<F, HG, N>::new_witness(cs.clone(), || Ok(path))?;

		// Creating the leaf and checking the membership inside the tree
		let mixer_leaf_hash: FpVar<F> =
			hasher.hash_two(&mut cs.clone(), &leaf_private_var.secret, &leaf_private_var.nullifier)?;
		let mixer_nullifier_hash =
			hasher.hash_two(&mut cs.clone(), &leaf_private_var.nullifier, &leaf_private_var.nullifier)?;

		let is_member = path_var.check_membership(&root_var, &mixer_leaf_hash, &hasher)?;
		// Constraining arbitrary inputs
		arbitrary_input_var.constrain()?;

		// Enforcing constraints
		is_member.enforce_equal(&Boolean::TRUE)?;
		mixer_nullifier_hash.enforce_equal(&nullifier_hash_var)?;

		Ok(())
	}
}
