use crate::Vec;

use ark_ff::fields::PrimeField;
use ark_r1cs_std::{eq::EqGadget, fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use arkworks_gadgets::{
	merkle_tree::{simple_merkle::Path, simple_merkle_constraints::PathVar},
	poseidon::field_hasher_constraints::FieldHasherGadget,
	set::constraints::SetGadget,
};
use core::cmp::Ordering::Less;

#[derive(Clone)]
pub struct VAnchorCircuit<
	F: PrimeField,
	HG: FieldHasherGadget<F>,
	KHG: FieldHasherGadget<F>,
	LHG: FieldHasherGadget<F>,
	NHG: FieldHasherGadget<F>,
	const HEIGHT: usize,
	const N_INS: usize,
	const N_OUTS: usize,
	const ANCHOR_CT: usize,
> {
	public_amount: F,
	ext_data_hash: F,

	in_amounts: Vec<F>,
	in_blindings: Vec<F>,
	in_private_keys: Vec<F>,
	in_chain_id: F,
	root_set: [F; ANCHOR_CT],

	paths: Vec<Path<F, HG::Native, HEIGHT>>,
	indices: Vec<F>,
	nullifier_hash: Vec<F>,

	out_commitment: Vec<F>,
	out_amounts: Vec<F>,
	out_blindings: Vec<F>,
	out_chain_ids: Vec<F>,
	out_pubkey: Vec<F>,

	tree_hasher: HG::Native,
	keypair_hasher: KHG::Native,
	leaf_hasher: LHG::Native,
	nullifier_hasher: NHG::Native,
}

impl<
		F,
		HG,
		KHG,
		LHG,
		NHG,
		const HEIGHT: usize,
		const N_INS: usize,
		const N_OUTS: usize,
		const ANCHOR_CT: usize,
	> VAnchorCircuit<F, HG, KHG, LHG, NHG, HEIGHT, N_INS, N_OUTS, ANCHOR_CT>
where
	F: PrimeField,
	HG: FieldHasherGadget<F>,
	KHG: FieldHasherGadget<F>,
	LHG: FieldHasherGadget<F>,
	NHG: FieldHasherGadget<F>,
{
	#[allow(clippy::too_many_arguments)]
	pub fn new(
		public_amount: F,
		ext_data_hash: F,
		in_amounts: Vec<F>,
		in_blindings: Vec<F>,
		in_private_keys: Vec<F>,
		in_chain_id: F,
		root_set: [F; ANCHOR_CT],
		paths: Vec<Path<F, HG::Native, HEIGHT>>,
		indices: Vec<F>,
		nullifier_hash: Vec<F>,
		out_commitment: Vec<F>,
		out_amounts: Vec<F>,
		out_blindings: Vec<F>,
		out_chain_ids: Vec<F>,
		out_pubkey: Vec<F>,
		tree_hasher: HG::Native,
		keypair_hasher: KHG::Native,
		leaf_hasher: LHG::Native,
		nullifier_hasher: NHG::Native,
	) -> Self {
		Self {
			public_amount,
			ext_data_hash,
			in_amounts,
			in_blindings,
			in_private_keys,
			in_chain_id,
			root_set,
			paths,
			indices,
			nullifier_hash,
			out_commitment,
			out_amounts,
			out_blindings,
			out_chain_ids,
			out_pubkey,
			tree_hasher,
			keypair_hasher,
			leaf_hasher,
			nullifier_hasher,
		}
	}

	#[allow(clippy::too_many_arguments)]
	pub fn verify_input_var(
		in_amounts_var: &[FpVar<F>],
		in_blindings_var: &[FpVar<F>],
		in_private_keys: &[FpVar<F>],
		in_chain_id_var: &FpVar<F>,
		in_path_indices_var: &[FpVar<F>],
		in_path_elements_var: &[PathVar<F, HG, HEIGHT>],
		in_nullifier_var: &[FpVar<F>],
		set_gadget: &SetGadget<F>,
		tree_hasher: &HG,
		keypair_hasher: &KHG,
		leaf_hasher: &LHG,
		nullifier_hasher: &NHG,
	) -> Result<FpVar<F>, SynthesisError> {
		let mut sums_ins_var = FpVar::<F>::zero();

		for tx in 0..N_INS {
			// Computing the public key
			let pub_key = keypair_hasher.hash(&[in_private_keys[tx].clone()])?;
			// Computing the hash
			let in_leaf = leaf_hasher.hash(&[
				in_chain_id_var.clone(),
				in_amounts_var[tx].clone(),
				pub_key,
				in_blindings_var[tx].clone(),
			])?;
			// End of computing the hash

			let signature = nullifier_hasher.hash(&[
				in_private_keys[tx].clone(),
				in_leaf.clone(),
				in_path_indices_var[tx].clone(),
			])?;
			// Nullifier
			let nullifier_hash = nullifier_hasher.hash(&[
				in_leaf.clone(),
				in_path_indices_var[tx].clone(),
				signature,
			])?;

			nullifier_hash.enforce_equal(&in_nullifier_var[tx])?;

			// Add the roots and diffs signals to the vanchor circuit
			let roothash = &in_path_elements_var[tx].root_hash(&in_leaf, tree_hasher)?;
			let in_amount_tx = &in_amounts_var[tx];

			// Check membership if in_amount is non zero
			let check = set_gadget.check_membership_enabled(&roothash, in_amount_tx)?;
			check.enforce_equal(&Boolean::TRUE)?;

			sums_ins_var += in_amount_tx;
		}
		Ok(sums_ins_var)
	}

	// Verify correctness of transaction outputs
	pub fn verify_output_var(
		out_commitment_var: &[FpVar<F>],
		out_amounts_var: &[FpVar<F>],
		out_blindings_var: &[FpVar<F>],
		out_chain_ids_var: &[FpVar<F>],
		out_pubkey_var: &[FpVar<F>],
		limit_var: &FpVar<F>,
		leaf_hasher: &LHG,
	) -> Result<FpVar<F>, SynthesisError> {
		let mut sums_outs_var = FpVar::<F>::zero();

		for tx in 0..N_OUTS {
			// Computing the hash
			let leaf = leaf_hasher.hash(&[
				out_chain_ids_var[tx].clone(),
				out_amounts_var[tx].clone(),
				out_pubkey_var[tx].clone(),
				out_blindings_var[tx].clone(),
			])?;
			// End of computing the hash
			let out_amount_var = &out_amounts_var[tx];
			leaf.enforce_equal(&out_commitment_var[tx])?;

			// Check that amount is less than 2^248 in the field (to prevent overflow)
			out_amount_var.enforce_cmp_unchecked(limit_var, Less, false)?;

			sums_outs_var += out_amount_var;
		}
		Ok(sums_outs_var)
	}

	// Check that there are no same nullifiers among all inputs
	pub fn verify_no_same_nul(in_nullifier_var: &[FpVar<F>]) -> Result<(), SynthesisError> {
		for i in 0..N_INS - 1 {
			for j in (i + 1)..N_INS {
				in_nullifier_var[i].enforce_not_equal(&in_nullifier_var[j])?;
			}
		}

		Ok(())
	}

	// Verify amount invariant
	pub fn verify_input_invariant(
		public_amount_var: &FpVar<F>,
		sum_ins_var: &FpVar<F>,
		sum_outs_var: &FpVar<F>,
	) -> Result<(), SynthesisError> {
		let res = sum_ins_var + public_amount_var;
		res.enforce_equal(sum_outs_var)?;
		Ok(())
	}
}

impl<
		F,
		HG,
		KHG,
		LHG,
		NHG,
		const HEIGHT: usize,
		const N_INS: usize,
		const N_OUTS: usize,
		const ANCHOR_CT: usize,
	> ConstraintSynthesizer<F>
	for VAnchorCircuit<F, HG, KHG, LHG, NHG, HEIGHT, N_INS, N_OUTS, ANCHOR_CT>
where
	F: PrimeField,
	HG: FieldHasherGadget<F>,
	KHG: FieldHasherGadget<F>,
	LHG: FieldHasherGadget<F>,
	NHG: FieldHasherGadget<F>,
{
	fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
		let public_amount = self.public_amount;
		let ext_data_hash = self.ext_data_hash;
		let in_amounts = self.in_amounts;
		let in_blindings = self.in_blindings;
		let in_chain_id = self.in_chain_id;
		let in_private_keys = self.in_private_keys;
		let out_chain_ids = self.out_chain_ids;
		let root_set = self.root_set;
		let paths = self.paths;
		let indices = self.indices;
		let nullifier_hash = self.nullifier_hash;

		let out_commitment = self.out_commitment;
		let out_amounts = self.out_amounts;
		let out_blindings = self.out_blindings;
		let out_pubkey = self.out_pubkey;

		// TODO: move outside the circuit
		// 2^248
		let limit: F = F::from_str(
			"452312848583266388373324160190187140051835877600158453279131187530910662656",
		)
		.unwrap_or_default();
		// check the previous conversion is done correctly
		assert_ne!(limit, F::default());

		// Generating vars
		// Public inputs
		let public_amount_var = FpVar::<F>::new_input(cs.clone(), || Ok(public_amount))?;
		let arbitrary_input_var = FpVar::<F>::new_input(cs.clone(), || Ok(ext_data_hash))?;
		let in_nullifier_var = Vec::<FpVar<F>>::new_input(cs.clone(), || Ok(nullifier_hash))?;
		let out_commitment_var = Vec::<FpVar<F>>::new_input(cs.clone(), || Ok(out_commitment))?;
		let in_chain_id = FpVar::<F>::new_input(cs.clone(), || Ok(in_chain_id))?;
		let root_set_var = Vec::<FpVar<F>>::new_input(cs.clone(), || Ok(root_set))?;

		// Constants
		let limit_var: FpVar<F> = FpVar::<F>::new_constant(cs.clone(), limit)?;

		// Hashers
		let tree_hasher: HG =
			FieldHasherGadget::<F>::from_native(&mut cs.clone(), self.tree_hasher);
		let keypair_hasher: KHG =
			FieldHasherGadget::<F>::from_native(&mut cs.clone(), self.keypair_hasher);
		let leaf_hasher: LHG =
			FieldHasherGadget::<F>::from_native(&mut cs.clone(), self.leaf_hasher);
		let nullifier_hasher: NHG =
			FieldHasherGadget::<F>::from_native(&mut cs.clone(), self.nullifier_hasher);

		// Private inputs
		let in_amounts_var = Vec::<FpVar<F>>::new_witness(cs.clone(), || Ok(in_amounts))?;
		let in_blindings_var = Vec::<FpVar<F>>::new_witness(cs.clone(), || Ok(in_blindings))?;
		let in_private_keys_var = Vec::<FpVar<F>>::new_witness(cs.clone(), || Ok(in_private_keys))?;
		let in_path_elements_var =
			Vec::<PathVar<F, HG, HEIGHT>>::new_witness(cs.clone(), || Ok(paths))?;
		let in_path_indices_var = Vec::<FpVar<F>>::new_witness(cs.clone(), || Ok(indices))?;

		// Outputs
		let out_amounts_var = Vec::<FpVar<F>>::new_witness(cs.clone(), || Ok(out_amounts))?;
		let out_blindings_var = Vec::<FpVar<F>>::new_witness(cs.clone(), || Ok(out_blindings))?;
		let out_chain_ids_var = Vec::<FpVar<F>>::new_witness(cs.clone(), || Ok(out_chain_ids))?;
		let out_pubkey_var = Vec::<FpVar<F>>::new_witness(cs, || Ok(out_pubkey))?;

		let set_gadget = SetGadget::new(root_set_var);
		// verify correctness of transaction inputs
		let sum_ins_var = Self::verify_input_var(
			&in_amounts_var,
			&in_blindings_var,
			&in_private_keys_var,
			&in_chain_id,
			&in_path_indices_var,
			&in_path_elements_var,
			&in_nullifier_var,
			&set_gadget,
			&tree_hasher,
			&keypair_hasher,
			&leaf_hasher,
			&nullifier_hasher,
		)?;

		// verify correctness of transaction outputs
		let sum_outs_var = Self::verify_output_var(
			&out_commitment_var,
			&out_amounts_var,
			&out_blindings_var,
			&out_chain_ids_var,
			&out_pubkey_var,
			&limit_var,
			&leaf_hasher,
		)?;

		// check that there are no same nullifiers among all inputs
		Self::verify_no_same_nul(&in_nullifier_var)?;

		// verify amount invariant
		Self::verify_input_invariant(&public_amount_var, &sum_ins_var, &sum_outs_var)?;

		// optional safety constraint to make sure extDataHash cannot be changed
		let _ = &arbitrary_input_var * &arbitrary_input_var;

		Ok(())
	}
}
