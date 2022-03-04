use ark_ff::fields::PrimeField;
use ark_r1cs_std::{eq::EqGadget, fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use arkworks_native_gadgets::merkle_tree::Path;
use arkworks_r1cs_gadgets::{merkle_tree::PathVar, poseidon::FieldHasherGadget};

#[derive(Clone)]
pub struct MixerCircuit<F: PrimeField, HG: FieldHasherGadget<F>, const N: usize> {
	arbitrary_input: F,
	secret: F,
	nullifier: F,
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
		arbitrary_input: F,
		secret: F,
		nullifier: F,
		path: Path<F, HG::Native, N>,
		root: F,
		nullifier_hash: F,
		hasher: HG::Native,
	) -> Self {
		Self {
			arbitrary_input,
			secret,
			nullifier,
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
		let secret = self.secret;
		let nullifier = self.nullifier;
		let path = self.path;
		let root = self.root;
		let nullifier_hash = self.nullifier_hash;

		// Generating vars
		// Public inputs
		let nullifier_hash_var = FpVar::<F>::new_input(cs.clone(), || Ok(nullifier_hash))?;
		let root_var = FpVar::<F>::new_input(cs.clone(), || Ok(root))?;
		let arbitrary_input_var = FpVar::<F>::new_input(cs.clone(), || Ok(arbitrary_input))?;

		// Hashers
		let hasher: HG = FieldHasherGadget::<F>::from_native(&mut cs.clone(), self.hasher)?;

		// Private inputs
		let secret_var = FpVar::<F>::new_witness(cs.clone(), || Ok(secret))?;
		let nullifier_var = FpVar::<F>::new_witness(cs.clone(), || Ok(nullifier))?;
		let path_var = PathVar::<F, HG, N>::new_witness(cs.clone(), || Ok(path))?;

		// Creating the leaf and checking the membership inside the tree
		let mixer_leaf_hash: FpVar<F> = hasher.hash_two(&secret_var, &nullifier_var)?;
		let mixer_nullifier_hash = hasher.hash_two(&nullifier_var, &nullifier_var)?;

		let is_member = path_var.check_membership(&root_var, &mixer_leaf_hash, &hasher)?;
		// Constraining arbitrary inputs
		let _ = &arbitrary_input_var * &arbitrary_input_var;

		// Enforcing constraints
		is_member.enforce_equal(&Boolean::TRUE)?;
		mixer_nullifier_hash.enforce_equal(&nullifier_hash_var)?;

		Ok(())
	}
}
