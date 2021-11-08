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
	public_amount: F,
	ext_data_hash: A,

	input_nullifier: Vec<LG::NullifierVar>,
	input_amount: Vec<F>,
	in_private_key: Vec<F>,
	in_private_key_var: Vec<FpVar<F>>,
	in_blinding: Vec<F>,
	in_path_indices: Vec<F>,
	in_path_elements: Vec<Path<C, N>>,

	output_commitment: Vec<HG::OutputVar>,
	out_chain_idvar: Vec<FpVar<F>>,
	out_amount_var: Vec<FpVar<F>>,
	out_pubkey_var: Vec<FpVar<F>>,
	out_blinding_var: Vec<FpVar<F>>,

	chain_id: F,
	root_set: [F; M],
	diffs: [Vec<F>; M],

	_arbitrary_gadget: PhantomData<AG>,
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
	//TODO: Verify correctness of transaction inputs using constraints
	pub fn verify_input_var(
		&mut self,
		hg4: HG::ParametersVar,
		hg3: HG::ParametersVar,
		secrets_var: Vec<<LG as VanchorLeafCreationGadget<F, H, HG, L>>::PrivateVar>,
		public_var: Vec<<LG as VanchorLeafCreationGadget<F, H, HG, L>>::PublicVar>,
		nullifier_var: Vec<LG::NullifierVar>,
		indices: Vec<FpVar<F>>,
		// ...
	) -> Result<(), SynthesisError> {
		let mut sums_ins_var = FpVar::<F>::zero();
		//let public_key :Vec<H::Output> =Vec::with_capacity(N);
		//let private_key :Vec<F> =Vec::with_capacity(N);
		self.input_nullifier = nullifier_var;
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
			nullifier_hasher_out.enforce_equal(&self.input_nullifier[tx])?;

			let amount = LG::get_amount(&secrets_var[tx])?;
			// We don't need to range check input amounts, since all inputs are valid UTXOs
			// that were already checked as outputs in the previous transaction (or zero
			// amount UTXOs that don't need to be checked either).
			sums_ins_var = sums_ins_var + amount;
			//...
		}

		Ok(())
	}

	//TODO: Verify correctness of transaction outputs
	pub fn verify_output_var(&mut self, hg4: HG::ParametersVar) -> Result<(), SynthesisError> {
		let mut sums_outs_var = FpVar::<F>::zero();
		let mut in_utxo_hasher_var_out: Vec<HG::OutputVar> = Vec::with_capacity(N);
		for tx in 0..N {
			// Computing the hash
			let mut bytes = Vec::new();
			bytes.extend(self.out_chain_idvar[tx].to_bytes()?);
			bytes.extend(self.out_amount_var[tx].to_bytes()?);
			bytes.extend(self.out_pubkey_var[tx].to_bytes()?);
			bytes.extend(self.out_blinding_var[tx].to_bytes()?);
			in_utxo_hasher_var_out[tx] = HG::evaluate(&hg4, &bytes)?;
			// End of computing the hash
			in_utxo_hasher_var_out[tx].enforce_equal(&self.output_commitment[tx])?;

			sums_outs_var = sums_outs_var + self.out_amount_var[tx].clone();
			//...
		}

		Ok(())
	}
	//TODO: Check that there are no same nullifiers among all inputs

	//TODO: Verify amount invariant

	//TODO: Optional safety constraint to make sure extDataHash cannot be changed
}
