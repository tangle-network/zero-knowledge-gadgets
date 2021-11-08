use std::marker::PhantomData;

use crate::{
	arbitrary::{constraints::ArbitraryGadget, Arbitrary},
	leaf::{
		constraints::VanchorLeafCreationGadget,
		vanchor::{
			constraints::{PrivateVar, PublicVar},
			Private,
		},
		VanchorLeafCreation,
	},
	merkle_tree::{
		constraints::{NodeVar, PathVar},
		Config as MerkleConfig, Path,
	},
	set::{Set, SetGadget},
	Vec,
};
use ark_bls12_381::Fq;
use ark_crypto_primitives::{CRHGadget, CRH};
use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::EqGadget, ToBytesGadget};
use ark_relations::r1cs::SynthesisError;

pub struct TransactionGadget<
	F: PrimeField,
	// Arbitrary data constraints
	A: Arbitrary,
	AG: ArbitraryGadget<F, A>,
	// Hasher for the leaf creation
	H: CRH,
	HG: CRHGadget<H, F>,
	// Merkle config and hasher gadget for the tree
	C: MerkleConfig,
	LHGT: CRHGadget<C::LeafH, F>,
	HGT: CRHGadget<C::H, F>,
	// Type of leaf creation
	L: VanchorLeafCreation<H, F>,
	LG: VanchorLeafCreationGadget<F, H, HG, L>,
	// Set of merkle roots
	S: Set<F, M>,
	SG: SetGadget<F, S, M>,
	const N: usize,
	const M: usize,
> {
	public_amount_var: FpVar<F>,
	ext_data_hash_var: AG,

	//in_nullifier_var: Vec<LG::NullifierVar>,
	in_nullifier_var: Vec<HG::OutputVar>,
	in_amount_var: Vec<FpVar<F>>,
	in_private_key_var: Vec<FpVar<F>>,
	in_blinding_var: Vec<FpVar<F>>,
	in_path_indices_var: Vec<FpVar<F>>,
	in_path_elements_var: Vec<PathVar<F, C, HGT, LHGT, N>>,

	output_commitment_var: Vec<HG::OutputVar>,
	out_chain_id_var: Vec<FpVar<F>>,
	out_amount_var: Vec<FpVar<F>>,
	out_pubkey_var: Vec<FpVar<F>>,
	out_blinding_var: Vec<FpVar<F>>,

	chain_id_var: FpVar<F>,
	root_set_var: [FpVar<F>; M],
	diffs_var: [Vec<FpVar<F>>; M],

	_arbitrary: PhantomData<A>,
	_hasher: PhantomData<H>,
	_hasher_gadget: PhantomData<HG>,
	_leaf_hasher_gadget: PhantomData<LHGT>,
	_tree_hasher_gadget: PhantomData<HGT>,
	_leaf_creation: PhantomData<L>,
	_leaf_creation_gadget: PhantomData<LG>,
	_set: PhantomData<S>,
	_set_gadget: PhantomData<SG>,
	_merkle_config: PhantomData<C>,
}
use crate::{ark_std::Zero, leaf::vanchor::constraints::VanchorLeafGadget};
use ark_r1cs_std::fields::FieldVar;

use super::keypair::constraints::{KeypairCreationGadget, KeypairVar};

impl<F, A, AG, H, HG, C, LHGT, HGT, L, LG, S, SG, const N: usize, const M: usize>
	TransactionGadget<F, A, AG, H, HG, C, LHGT, HGT, L, LG, S, SG, N, M>
where
	F: PrimeField,
	A: Arbitrary,
	AG: ArbitraryGadget<F, A>,
	H: CRH,
	HG: CRHGadget<H, F>,
	C: MerkleConfig,
	LHGT: CRHGadget<C::LeafH, F>,
	HGT: CRHGadget<C::H, F>,
	L: VanchorLeafCreation<H, F>,
	LG: VanchorLeafCreationGadget<F, H, HG, L>,
	S: Set<F, M>,
	SG: SetGadget<F, S, M>,
{
	pub fn new(
		public_amount_var: FpVar<F>,
		ext_data_hash_var: AG,

		in_nullifier_var: Vec<HG::OutputVar>,
		in_amount_var: Vec<FpVar<F>>,
		in_private_key_var: Vec<FpVar<F>>,
		in_blinding_var: Vec<FpVar<F>>,

		in_path_elements_var: Vec<PathVar<F, C, HGT, LHGT, N>>,
		in_path_indices_var: Vec<FpVar<F>>,
		output_commitment_var: Vec<HG::OutputVar>,
		out_chain_id_var: Vec<FpVar<F>>,
		out_amount_var: Vec<FpVar<F>>,
		out_pubkey_var: Vec<FpVar<F>>,
		out_blinding_var: Vec<FpVar<F>>,
		chain_id_var: FpVar<F>,
		root_set_var: [FpVar<F>; M],
		diffs_var: [Vec<FpVar<F>>; M],
	) -> Self {
		Self {
			public_amount_var,
			ext_data_hash_var,
			in_nullifier_var,
			in_amount_var,
			in_private_key_var,
			in_blinding_var,
			in_path_indices_var,
			in_path_elements_var,

			output_commitment_var,
			out_chain_id_var,
			out_amount_var,
			out_pubkey_var,
			out_blinding_var,
			chain_id_var,
			root_set_var,
			diffs_var,
			_arbitrary: PhantomData,
			_hasher: PhantomData,
			_hasher_gadget: PhantomData,
			_leaf_hasher_gadget: PhantomData,
			_tree_hasher_gadget: PhantomData,
			_leaf_creation: PhantomData,
			_leaf_creation_gadget: PhantomData,
			_set: PhantomData,
			_set_gadget: PhantomData,
			_merkle_config: PhantomData,
		}
	}
}

impl<F, A, AG, H, HG, C, LHGT, HGT, L, LG, S, SG, const N: usize, const M: usize>
	TransactionGadget<F, A, AG, H, HG, C, LHGT, HGT, L, LG, S, SG, N, M>
where
	F: PrimeField,
	A: Arbitrary,
	AG: ArbitraryGadget<F, A>,
	H: CRH,
	HG: CRHGadget<H, F>,
	C: MerkleConfig,
	LHGT: CRHGadget<C::LeafH, F>,
	HGT: CRHGadget<C::H, F>,
	L: VanchorLeafCreation<H, F>,
	LG: VanchorLeafCreationGadget<F, H, HG, L>,
	S: Set<F, M>,
	SG: SetGadget<F, S, M>,
{
	//The Old way!
	pub fn verify_input_var(
		&mut self,
		hg4: HG::ParametersVar,
		hg3: HG::ParametersVar,
		secrets_var: Vec<<LG as VanchorLeafCreationGadget<F, H, HG, L>>::PrivateVar>,
		public_var: Vec<<LG as VanchorLeafCreationGadget<F, H, HG, L>>::PublicVar>,
		nullifier_var: Vec<HG::OutputVar>,
		indices: Vec<FpVar<F>>,
		// ...
	) -> Result<(), SynthesisError> {
		let mut sums_ins_var = FpVar::<F>::zero();
		//let public_key :Vec<H::Output> =Vec::with_capacity(N);
		//let private_key :Vec<F> =Vec::with_capacity(N);
		self.in_nullifier_var = nullifier_var;
		let mut in_utxo_hasher_var_out: Vec<LG::LeafVar> = Vec::with_capacity(10);
		for tx in 0..N {
			in_utxo_hasher_var_out[tx] =
				LG::create_leaf(&secrets_var[tx], &public_var[tx], &hg4).unwrap();
			let nullifier_hasher_out = LG::create_nullifier(
				&secrets_var[tx],
				&in_utxo_hasher_var_out[tx],
				&hg3,
				&indices[tx],
			)
			.unwrap();
			//nullifier_hasher_out.enforce_equal(&self.in_nullifier_var[tx])?;

			let amount = LG::get_amount(&secrets_var[tx])?;
			// We don't need to range check input amounts, since all inputs are valid UTXOs
			// that were already checked as outputs in the previous transaction (or zero
			// amount UTXOs that don't need to be checked either).
			sums_ins_var = sums_ins_var + amount;
			//...
		}

		Ok(())
	}

	//Similar to Circom
	pub fn verify_input_var_embeded(
		&mut self,
		hg4: HG::ParametersVar,
		// ...
	) -> Result<FpVar<F>, SynthesisError> {
		let mut sums_ins_var = FpVar::<F>::zero();
		let mut in_utxo_hasher_var: Vec<HG::OutputVar> = Vec::with_capacity(N);
		let mut nullifier_hash: Vec<HG::OutputVar> = Vec::with_capacity(N);

		let mut inkeypair: Vec<KeypairVar<H, HG, L, LG, F>> = Vec::with_capacity(N);
		for tx in 0..N {
			inkeypair[tx] = KeypairCreationGadget::<H, HG, F, L, LG>::new_from_key(
				&hg4,
				&self.in_private_key_var[tx],
			)
			.unwrap();
			// Computing the hash
			let mut bytes = Vec::new();
			bytes.extend(self.chain_id_var.to_bytes()?);
			bytes.extend(self.in_amount_var[tx].to_bytes()?);
			bytes.extend(inkeypair[tx].public_key_var().unwrap().to_bytes()?);
			bytes.extend(self.in_blinding_var[tx].to_bytes()?);

			in_utxo_hasher_var[tx] = HG::evaluate(&hg4, &bytes)?;
			// End of computing the hash

			// Nullifier
			let mut bytes = Vec::new();
			bytes.extend(in_utxo_hasher_var[tx].to_bytes()?);
			bytes.extend(self.in_path_indices_var[tx].to_bytes()?);
			bytes.extend(self.in_private_key_var[tx].to_bytes()?);

			nullifier_hash[tx] = HG::evaluate(&hg4, &bytes)?;

			nullifier_hash[tx].enforce_equal(&self.in_nullifier_var[tx])?;
			// add the roots and diffs signals to the bridge circuit
			// TODO:

			sums_ins_var = sums_ins_var + self.out_amount_var[tx].clone();
		}
		Ok(sums_ins_var)
	}

	//TODO: Verify correctness of transaction outputs
	pub fn verify_output_var(
		&mut self,
		hg4: HG::ParametersVar,
	) -> Result<FpVar<F>, SynthesisError> {
		let mut sums_outs_var = FpVar::<F>::zero();
		let mut in_utxo_hasher_var_out: Vec<HG::OutputVar> = Vec::with_capacity(N);
		for tx in 0..N {
			// Computing the hash
			let mut bytes = Vec::new();
			bytes.extend(self.out_chain_id_var[tx].to_bytes()?);
			bytes.extend(self.out_amount_var[tx].to_bytes()?);
			bytes.extend(self.out_pubkey_var[tx].to_bytes()?);
			bytes.extend(self.out_blinding_var[tx].to_bytes()?);
			in_utxo_hasher_var_out[tx] = HG::evaluate(&hg4, &bytes)?;
			// End of computing the hash
			in_utxo_hasher_var_out[tx].enforce_equal(&self.output_commitment_var[tx])?;

			sums_outs_var = sums_outs_var + self.out_amount_var[tx].clone();
			//...
		}
		// Check that amount fits into 248 bits to prevent overflow
		// TODO:
		Ok(sums_outs_var)
	}

	//TODO: Check that there are no same nullifiers among all inputs
	pub fn verify_no_sam_nul(&self) -> Result<(), SynthesisError> {
		let mut same_nullifiers: Vec<HG::OutputVar> = Vec::with_capacity(2);
		for i in 0..N {
			for j in i..N {
				same_nullifiers[0] = self.in_nullifier_var[i].clone();
				same_nullifiers[1] = self.in_nullifier_var[j].clone();
				same_nullifiers[0].enforce_not_equal(&same_nullifiers[1])?;
			}
		}
		Ok(())
	}

	//TODO: Verify amount invariant
	pub fn verify_input_invariant(
		&self,
		sum_ins_var: FpVar<F>,
		sum_outs_var: FpVar<F>,
	) -> Result<(), SynthesisError> {
		let res = sum_ins_var + self.public_amount_var.clone();
		res.enforce_equal(&sum_outs_var).unwrap();
		Ok(())
	}
	//TODO: Optional safety constraint to make sure extDataHash cannot be changed
}
