use std::ptr::null;

use crate::Vec;

use ark_crypto_primitives::{crh::CRHGadget, CRH};
use ark_ff::fields::PrimeField;
use ark_r1cs_std::{eq::EqGadget, fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::{cmp::Ordering::Less, marker::PhantomData};
use arkworks_gadgets::{
	arbitrary::vanchor_data::{
		constraints::VAnchorArbitraryDataVar as ArbitraryInputVar,
		VAnchorArbitraryData as ArbitraryInput,
	},
	keypair::vanchor::{constraints::KeypairVar, Keypair},
	leaf::vanchor::{
		constraints::{
			PrivateVar as LeafPrivateInputsVar, PublicVar as LeafPublicInputsVar, VAnchorLeafGadget,
		},
		Private as LeafPrivateInputs, Public as LeafPublicInputs,
	},
	merkle_tree::{simple_merkle::Path, simple_merkle_constraints::PathVar},
	poseidon::field_hasher_constraints::FieldHasherGadget,
	set::constraints::SetGadget,
};

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
	ext_data_hash: ArbitraryInput<F>,

	leaf_private_inputs: Vec<LeafPrivateInputs<F>>, // amount, blinding
	keypair_inputs: Vec<Keypair<F, KHG::Native, NHG::Native>>,
	leaf_public_input: LeafPublicInputs<F>, // chain_id
	root_set: [F; ANCHOR_CT],

	paths: Vec<Path<F, HG::Native, HEIGHT>>,
	indices: Vec<F>,
	nullifier_hash: Vec<F>,

	output_commitment: Vec<F>,
	out_leaf_private: Vec<LeafPrivateInputs<F>>,
	out_leaf_public: Vec<LeafPublicInputs<F>>,
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
		ext_data_hash: ArbitraryInput<F>,
		leaf_private_inputs: Vec<LeafPrivateInputs<F>>,
		keypair_inputs: Vec<Keypair<F, KHG::Native, NHG::Native>>,
		leaf_public_input: LeafPublicInputs<F>,
		root_set: [F; ANCHOR_CT],
		paths: Vec<Path<F, HG::Native, HEIGHT>>,
		indices: Vec<F>,
		nullifier_hash: Vec<F>,
		output_commitment: Vec<F>,
		out_leaf_private: Vec<LeafPrivateInputs<F>>,
		out_leaf_public: Vec<LeafPublicInputs<F>>,
		out_pubkey: Vec<F>,
		tree_hasher: HG::Native,
		keypair_hasher: KHG::Native,
		leaf_hasher: LHG::Native,
		nullifier_hasher: NHG::Native,
	) -> Self {
		Self {
			public_amount,
			ext_data_hash,
			leaf_private_inputs,
			keypair_inputs,
			leaf_public_input,
			root_set,
			paths,
			indices,
			nullifier_hash,
			output_commitment,
			out_leaf_private,
			out_leaf_public,
			out_pubkey,
			tree_hasher,
			keypair_hasher,
			leaf_hasher,
			nullifier_hasher,
		}
	}

	#[allow(clippy::too_many_arguments)]
	pub fn verify_input_var(
		leaf_private_var: &[LeafPrivateInputsVar<F>],
		inkeypair_var: &[KeypairVar<F, KHG, NHG>],
		leaf_public_input_var: &LeafPublicInputsVar<F>,
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
			let pub_key = inkeypair_var[tx].public_key(keypair_hasher)?;
			// Computing the hash
			let in_utxo_hasher_var = VAnchorLeafGadget::<F, LHG>::create_leaf(
				&leaf_private_var[tx],
				leaf_public_input_var,
				&pub_key,
				leaf_hasher,
			)?;
			// End of computing the hash

			let signature = inkeypair_var[tx].signature(
				&in_utxo_hasher_var,
				&in_path_indices_var[tx],
				nullifier_hasher,
			)?;
			// Nullifier
			let nullifier_hash = VAnchorLeafGadget::<F, NHG>::create_nullifier(
				&signature,
				&in_utxo_hasher_var,
				&in_path_indices_var[tx],
				nullifier_hasher,
			)?;

			nullifier_hash.enforce_equal(&in_nullifier_var[tx])?;

			// Add the roots and diffs signals to the vanchor circuit
			let roothash = &in_path_elements_var[tx].root_hash(&in_utxo_hasher_var, tree_hasher)?;
			let in_amount_tx = &leaf_private_var[tx].amount;

			// Check membership if in_amount is non zero
			let check = set_gadget.check_membership_enabled(&roothash, in_amount_tx)?;
			check.enforce_equal(&Boolean::TRUE)?;

			sums_ins_var += in_amount_tx;
		}
		Ok(sums_ins_var)
	}

	// Verify correctness of transaction outputs
	pub fn verify_output_var(
		output_commitment_var: &[FpVar<F>],
		leaf_private_var: &[LeafPrivateInputsVar<F>],
		leaf_public_var: &[LeafPublicInputsVar<F>],
		out_pubkey_var: &[FpVar<F>],
		limit_var: &FpVar<F>,
		leaf_hasher: &LHG,
	) -> Result<FpVar<F>, SynthesisError> {
		let mut sums_outs_var = FpVar::<F>::zero();

		for tx in 0..N_OUTS {
			// Computing the hash
			let out_utxo_hasher_var = VAnchorLeafGadget::<F, LHG>::create_leaf(
				&leaf_private_var[tx],
				&leaf_public_var[tx],
				&out_pubkey_var[tx],
				leaf_hasher,
			)?;
			// End of computing the hash
			let out_amount_var = &leaf_private_var[tx].amount;
			out_utxo_hasher_var.enforce_equal(&output_commitment_var[tx])?;

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
		let leaf_private = self.leaf_private_inputs; // amount, blinding
		let keypair_inputs = self.keypair_inputs;
		let leaf_public_input = self.leaf_public_input; // chain id
		let root_set = self.root_set;
		let paths = self.paths;
		let indices = self.indices;
		let nullifier_hash = self.nullifier_hash;

		let output_commitment = self.output_commitment;
		let out_leaf_private = self.out_leaf_private;
		let out_leaf_public = self.out_leaf_public;
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
		let arbitrary_input_var = ArbitraryInputVar::new_input(cs.clone(), || Ok(ext_data_hash))?;
		let in_nullifier_var = Vec::<FpVar<F>>::new_input(cs.clone(), || Ok(nullifier_hash))?;
		let output_commitment_var =
			Vec::<FpVar<F>>::new_input(cs.clone(), || Ok(output_commitment))?;
		let leaf_public_input_var =
			LeafPublicInputsVar::new_input(cs.clone(), || Ok(leaf_public_input))?;
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
		let leaf_private_var =
			Vec::<LeafPrivateInputsVar<F>>::new_witness(cs.clone(), || Ok(leaf_private))?;
		let inkeypair_var =
			Vec::<KeypairVar<F, KHG, NHG>>::new_witness(cs.clone(), || Ok(keypair_inputs))?;
		let in_path_elements_var =
			Vec::<PathVar<F, HG, HEIGHT>>::new_witness(cs.clone(), || Ok(paths))?;
		let in_path_indices_var = Vec::<FpVar<F>>::new_witness(cs.clone(), || Ok(indices))?;

		// Outputs
		let out_leaf_private_var =
			Vec::<LeafPrivateInputsVar<F>>::new_witness(cs.clone(), || Ok(out_leaf_private))?;
		let out_leaf_public_var =
			Vec::<LeafPublicInputsVar<F>>::new_witness(cs.clone(), || Ok(out_leaf_public))?;
		let out_pubkey_var = Vec::<FpVar<F>>::new_witness(cs, || Ok(out_pubkey))?;

		let set_gadget = SetGadget::new(root_set_var);
		// verify correctness of transaction inputs
		let sum_ins_var = Self::verify_input_var(
			&leaf_private_var,
			&inkeypair_var,
			&leaf_public_input_var,
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
			&output_commitment_var,
			&out_leaf_private_var,
			&out_leaf_public_var,
			&out_pubkey_var,
			&limit_var,
			&leaf_hasher,
		)?;

		// check that there are no same nullifiers among all inputs
		Self::verify_no_same_nul(&in_nullifier_var)?;

		// verify amount invariant
		Self::verify_input_invariant(&public_amount_var, &sum_ins_var, &sum_outs_var)?;

		// optional safety constraint to make sure extDataHash cannot be changed
		arbitrary_input_var.constrain()?;

		Ok(())
	}
}
