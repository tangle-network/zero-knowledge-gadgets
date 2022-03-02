use ark_crypto_primitives::{crh::CRHGadget, CRH};
use ark_ff::fields::PrimeField;
use ark_r1cs_std::{eq::EqGadget, fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::{marker::PhantomData, vec::Vec};
use arkworks_gadgets::{
	leaf::anchor::{
		constraints::{AnchorLeafGadget, PrivateVar, PublicVar},
		Private, Public,
	},
	merkle_tree::{simple_merkle::Path, simple_merkle_constraints::PathVar},
	poseidon::field_hasher_constraints::FieldHasherGadget,
	set::constraints::SetGadget,
};

#[derive(Clone)]
pub struct AnchorCircuit<
	F: PrimeField,
	HG: FieldHasherGadget<F>,
	LHG: FieldHasherGadget<F>,
	const N: usize,
	const M: usize,
> {
	arbitrary_input: F,
	leaf_private_inputs: Private<F>,
	leaf_public_inputs: Public<F>,
	root_set: [F; M],
	path: Path<F, HG::Native, N>,
	nullifier_hash: F,
	tree_hasher: HG::Native,
	leaf_hasher: LHG::Native,
}

impl<F, HG, LHG, const N: usize, const M: usize> AnchorCircuit<F, HG, LHG, N, M>
where
	F: PrimeField,
	HG: FieldHasherGadget<F>,
	LHG: FieldHasherGadget<F>,
{
	#[allow(clippy::too_many_arguments)]
	pub fn new(
		arbitrary_input: F,
		leaf_private_inputs: Private<F>,
		leaf_public_inputs: Public<F>,
		root_set: [F; M],
		path: Path<F, HG::Native, N>,
		nullifier_hash: F,
		tree_hasher: HG::Native,
		leaf_hasher: LHG::Native,
	) -> Self {
		Self {
			arbitrary_input,
			leaf_private_inputs,
			leaf_public_inputs,
			root_set,
			path,
			nullifier_hash,
			tree_hasher,
			leaf_hasher,
		}
	}
}

impl<F, HG, LHG, const N: usize, const M: usize> ConstraintSynthesizer<F>
	for AnchorCircuit<F, HG, LHG, N, M>
where
	F: PrimeField,
	HG: FieldHasherGadget<F>,
	LHG: FieldHasherGadget<F>,
{
	fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
		let arbitrary_input = self.arbitrary_input;
		let leaf_private = self.leaf_private_inputs;
		let leaf_public = self.leaf_public_inputs;
		let root_set = self.root_set;
		let path = self.path;
		let nullifier_hash = self.nullifier_hash;

		// Generating vars
		// Public inputs
		let leaf_public_var = PublicVar::new_input(cs.clone(), || Ok(leaf_public))?;
		let nullifier_hash_var = FpVar::<F>::new_input(cs.clone(), || Ok(nullifier_hash))?;
		let roots_var = Vec::<FpVar<F>>::new_input(cs.clone(), || Ok(root_set))?;
		let arbitrary_input_var = FpVar::<F>::new_input(cs.clone(), || Ok(arbitrary_input))?;

		// Hashers
		let tree_hasher: HG =
			FieldHasherGadget::<F>::from_native(&mut cs.clone(), self.tree_hasher);
		let leaf_hasher: LHG =
			FieldHasherGadget::<F>::from_native(&mut cs.clone(), self.leaf_hasher);

		// Private inputs
		let leaf_private_var = PrivateVar::new_witness(cs.clone(), || Ok(leaf_private))?;
		let path_var = PathVar::<F, HG, N>::new_witness(cs.clone(), || Ok(path))?;

		// Creating the leaf and checking the membership inside the tree
		let anchor_leaf = AnchorLeafGadget::<F, LHG>::create_leaf(
			&leaf_private_var,
			&leaf_public_var,
			&leaf_hasher,
		)?;
		let anchor_nullifier =
			AnchorLeafGadget::<F, HG>::create_nullifier(&leaf_private_var, &tree_hasher)?;
		let root_var = path_var.root_hash(&anchor_leaf, &tree_hasher)?;
		// Check if target root is in set
		let set_gadget = SetGadget::new(roots_var);
		let is_set_member = set_gadget.check_membership(&root_var)?;
		// Constraining arbitrary inputs
		let _ = &arbitrary_input_var * &arbitrary_input_var;

		// Enforcing constraints
		is_set_member.enforce_equal(&Boolean::TRUE)?;
		anchor_nullifier.enforce_equal(&nullifier_hash_var)?;

		Ok(())
	}
}
