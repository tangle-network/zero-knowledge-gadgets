use crate::{
	arbitrary::{constraints::ArbitraryGadget, Arbitrary},
	keypair::{constraints::KeypairCreationGadget, vanchor::constraints::KeypairVar},
	leaf::{constraints::VanchorLeafCreationGadget, VanchorLeafCreation},
	merkle_tree::{
		constraints::{NodeVar, PathVar},
		Config as MerkleConfig, Path,
	},
	set::{Set, SetGadget},
	Vec,
};
use ark_crypto_primitives::{crh::CRHGadget, CRH};
use ark_ff::{fields::PrimeField, to_bytes};
use ark_r1cs_std::{eq::EqGadget, fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::marker::PhantomData;

pub struct VanchorCircuit<
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
	ext_data_hash: A::Input,

	arbitrary_input: A::Input,
	leaf_private_inputs: Vec<L::Private>, // amount, blinding, privkey
	leaf_public_inputs: Vec<L::Public>,   // pubkey, chain_id
	set_private_inputs: [Vec<S::Private>; M], // diffs
	root_set: [F; M],
	hasher_params: H::Parameters,
	path: Vec<Path<C, N>>,
	index: Vec<F>, // TODO: Temporary, we may need to compute it from path
	nullifier_hash: Vec<L::Nullifier>,

	output_commitment: Vec<H::Output>,
	out_chain_id: Vec<F>,
	out_amount: Vec<F>,
	out_pubkey: Vec<F>,
	out_blinding: Vec<F>,

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

impl<F, A, AG, H, HG, C, LHGT, HGT, L, LG, S, SG, const N: usize, const M: usize>
	VanchorCircuit<F, A, AG, H, HG, C, LHGT, HGT, L, LG, S, SG, N, M>
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
		public_amount: F,
		ext_data_hash: A::Input,
		arbitrary_input: A::Input,
		leaf_private_inputs: Vec<L::Private>,
		leaf_public_inputs: Vec<L::Public>,
		set_private_inputs: [Vec<S::Private>; M],
		root_set: [F; M],
		hasher_params: H::Parameters,
		path: Vec<Path<C, N>>,
		index: Vec<F>,
		nullifier_hash: Vec<L::Nullifier>,
		output_commitment: Vec<H::Output>,
		out_chain_id: Vec<F>,
		out_amount: Vec<F>,
		out_pubkey: Vec<F>,
		out_blinding: Vec<F>,
	) -> Self {
		Self {
			public_amount,
			ext_data_hash,
			arbitrary_input,
			leaf_private_inputs,
			leaf_public_inputs,
			set_private_inputs,
			root_set,
			hasher_params,
			path,
			index,
			nullifier_hash,
			output_commitment,
			out_chain_id,
			out_amount,
			out_pubkey,
			out_blinding,
			_arbitrary_gadget: PhantomData,
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

	pub fn verify_input_var(
		&self,
		hasher_params_var: &HG::ParametersVar,
		leaf_private_var: &Vec<LG::PrivateVar>,
		leaf_public_var: &Vec<LG::PublicVar>, //TODO: this doesn't need to be Vec
		in_path_indices_var: &Vec<FpVar<F>>,
		in_path_elements_var: &Vec<PathVar<F, C, HGT, LHGT, N>>,
		in_nullifier_var: &Vec<LG::NullifierVar>,
	) -> Result<FpVar<F>, SynthesisError> {
		let mut sums_ins_var = FpVar::<F>::zero();
		let mut in_utxo_hasher_var: Vec<LG::LeafVar> = Vec::with_capacity(N);
		let mut nullifier_hash: Vec<LG::NullifierVar> = Vec::with_capacity(N);
		let mut in_amounttx: FpVar<F>;

		let mut inkeypair: Vec<KeypairVar<H, HG, L, LG, F>> = Vec::with_capacity(N);
		for tx in 0..N {
			inkeypair[tx] = KeypairCreationGadget::<H, HG, F, L, LG>::new_from_key(
				&hasher_params_var,
				&LG::get_private_key(&leaf_private_var[tx]).unwrap(),
			)
			.unwrap();
			// Computing the hash
			in_utxo_hasher_var[tx] = LG::create_leaf(
				&leaf_private_var[tx],
				&leaf_public_var[tx],
				&hasher_params_var,
			)?;
			// End of computing the hash

			// Nullifier
			nullifier_hash[tx] = LG::create_nullifier(
				&leaf_private_var[tx],
				&in_utxo_hasher_var[tx],
				&hasher_params_var,
				&in_path_indices_var[tx],
			)?;

			nullifier_hash[tx].enforce_equal(&in_nullifier_var[tx])?;
			// add the roots and diffs signals to the vanchor circuit
			// TODO:
			in_amounttx = LG::get_amount(&leaf_private_var[tx]).unwrap();
			sums_ins_var = sums_ins_var + in_amounttx; // TODo: inamount
		}
		Ok(sums_ins_var)
	}

	//TODO: Verify correctness of transaction outputs
	pub fn verify_output_var(
		&self,
		hasher_params_var: &HG::ParametersVar,
		output_commitment_var: &Vec<HG::OutputVar>,
		out_chain_id_var: &Vec<FpVar<F>>,
		out_amount_var: &Vec<FpVar<F>>,
		out_pubkey_var: &Vec<FpVar<F>>,
		out_blinding_var: &Vec<FpVar<F>>,
	) -> Result<FpVar<F>, SynthesisError> {
		let mut sums_outs_var = FpVar::<F>::zero();
		let mut in_utxo_hasher_var_out: Vec<HG::OutputVar> = Vec::with_capacity(N);
		for tx in 0..N {
			// Computing the hash
			let mut bytes = Vec::new();
			bytes.extend(out_chain_id_var[tx].to_bytes()?);
			bytes.extend(out_amount_var[tx].to_bytes()?);
			bytes.extend(out_pubkey_var[tx].to_bytes()?);
			bytes.extend(out_blinding_var[tx].to_bytes()?);
			in_utxo_hasher_var_out[tx] = HG::evaluate(&hasher_params_var, &bytes)?;
			// End of computing the hash
			in_utxo_hasher_var_out[tx].enforce_equal(&output_commitment_var[tx])?;

			sums_outs_var = sums_outs_var + out_amount_var[tx].clone();
			//...
		}
		// Check that amount fits into 248 bits to prevent overflow
		// TODO:
		Ok(sums_outs_var)
	}

	//TODO: Check that there are no same nullifiers among all inputs
	pub fn verify_no_same_nul(
		&self,
		in_nullifier_var: &Vec<LG::NullifierVar>,
	) -> Result<(), SynthesisError> {
		let mut same_nullifiers: Vec<LG::NullifierVar> = Vec::with_capacity(2);
		for i in 0..N {
			for j in i..N {
				same_nullifiers[0] = in_nullifier_var[i].clone();
				same_nullifiers[1] = in_nullifier_var[j].clone();
				same_nullifiers[0].enforce_not_equal(&same_nullifiers[1])?;
			}
		}
		Ok(())
	}

	//TODO: Verify amount invariant
	pub fn verify_input_invariant(
		&self,
		public_amount_var: &FpVar<F>,
		sum_ins_var: &FpVar<F>,
		sum_outs_var: &FpVar<F>,
	) -> Result<(), SynthesisError> {
		let res = sum_ins_var + public_amount_var.clone();
		res.enforce_equal(&sum_outs_var).unwrap();
		Ok(())
	}
	//TODO: Optional safety constraint to make sure extDataHash cannot be changed
}

impl<F, A, AG, H, HG, C, LHGT, HGT, L, LG, S, SG, const N: usize, const M: usize> Clone
	for VanchorCircuit<F, A, AG, H, HG, C, LHGT, HGT, L, LG, S, SG, N, M>
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
	fn clone(&self) -> Self {
		let public_amount = self.public_amount.clone();
		let ext_data_hash = self.ext_data_hash.clone();
		let arbitrary_input = self.arbitrary_input.clone();
		let leaf_private_inputs = self.leaf_private_inputs.clone();
		let leaf_public_inputs = self.leaf_public_inputs.clone();
		let set_private_inputs = self.set_private_inputs.clone();
		let root_set = self.root_set;
		let hasher_params = self.hasher_params.clone();
		let path = self.path.clone();
		let index = self.index.clone();
		let nullifier_hash = self.nullifier_hash.clone();

		let output_commitment = self.output_commitment.clone();
		let out_chain_id = self.out_chain_id.clone();
		let out_amount = self.out_amount.clone();
		let out_pubkey = self.out_pubkey.clone();
		let out_blinding = self.out_blinding.clone();
		Self::new(
			public_amount,
			ext_data_hash,
			arbitrary_input,
			leaf_private_inputs,
			leaf_public_inputs,
			set_private_inputs,
			root_set,
			hasher_params,
			path,
			index,
			nullifier_hash,
			output_commitment,
			out_chain_id,
			out_amount,
			out_pubkey,
			out_blinding,
		)
	}
}

impl<F, A, AG, H, HG, C, LHGT, HGT, L, LG, S, SG, const N: usize, const M: usize>
	ConstraintSynthesizer<F> for VanchorCircuit<F, A, AG, H, HG, C, LHGT, HGT, L, LG, S, SG, N, M>
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
	fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
		let public_amount = self.public_amount.clone();
		let arbitrary_input = self.arbitrary_input.clone();
		let leaf_private = self.leaf_private_inputs.clone(); // amount, blinding, private key
		let leaf_public = self.leaf_public_inputs.clone(); // chain id
												   //let set_private = self.set_private_inputs.clone(); // TODO
												   //let root_set = self.root_set.clone(); // TODO
		let hasher_params = self.hasher_params.clone();
		let path = self.path.clone();
		let index = self.index.clone();
		let nullifier_hash = self.nullifier_hash.clone();

		let output_commitment = self.output_commitment.clone();
		let out_chain_id = self.out_chain_id.clone();
		let out_amount = self.out_amount.clone();
		let out_pubkey = self.out_pubkey.clone();
		let out_blinding = self.out_blinding.clone();

		// Generating vars
		// Public inputs
		let mut leaf_public_var: Vec<LG::PublicVar> = Vec::with_capacity(N);
		let public_amount_var = FpVar::<F>::new_input(cs.clone(), || Ok(public_amount))?;

		let mut in_nullifier_var: Vec<LG::NullifierVar> = Vec::with_capacity(N);

		//let root_set_var = Vec::<FpVar<F>>::new_input(cs.clone(), || Ok(root_set))?;
		let arbitrary_input_var = AG::InputVar::new_input(cs.clone(), || Ok(arbitrary_input))?;

		// Constants
		let hasher_params_var = HG::ParametersVar::new_constant(cs.clone(), hasher_params)?;

		// Private inputs
		let mut leaf_private_var: Vec<LG::PrivateVar> = Vec::with_capacity(N);
		let mut in_path_elements_var: Vec<PathVar<F, C, HGT, LHGT, N>> = Vec::with_capacity(N);
		let mut in_path_indices_var: Vec<FpVar<F>> = Vec::with_capacity(N);

		// Outputs
		let mut out_amount_var: Vec<FpVar<F>> = Vec::with_capacity(N);
		let mut out_chain_id_var: Vec<FpVar<F>> = Vec::with_capacity(N);
		let mut out_pubkey_var: Vec<FpVar<F>> = Vec::with_capacity(N);
		let mut out_blinding_var: Vec<FpVar<F>> = Vec::with_capacity(N);
		let mut output_commitment_var: Vec<HG::OutputVar> = Vec::with_capacity(N);

		for i in 0..N {
			leaf_public_var[i] =
				LG::PublicVar::new_input(cs.clone(), || Ok(leaf_public[i].clone()))?;

			leaf_private_var[i] =
				LG::PrivateVar::new_input(cs.clone(), || Ok(leaf_private[i].clone()))?;
			in_nullifier_var[i] =
				LG::NullifierVar::new_input(cs.clone(), || Ok(nullifier_hash[i].clone()))?;

			in_path_elements_var[i] =
				PathVar::<F, C, HGT, LHGT, N>::new_witness(cs.clone(), || Ok(path[i].clone()))?;
			in_path_indices_var[i] = FpVar::<F>::new_witness(cs.clone(), || Ok(index[i].clone()))?;

			out_amount_var[i] = FpVar::<F>::new_witness(cs.clone(), || Ok(out_amount[i].clone()))?;
			out_chain_id_var[i] =
				FpVar::<F>::new_witness(cs.clone(), || Ok(out_chain_id[i].clone()))?;
			out_pubkey_var[i] = FpVar::<F>::new_witness(cs.clone(), || Ok(out_pubkey[i].clone()))?;
			out_blinding_var[i] =
				FpVar::<F>::new_witness(cs.clone(), || Ok(out_blinding[i].clone()))?;
			output_commitment_var[i] =
				HG::OutputVar::new_witness(cs.clone(), || Ok(output_commitment[i].clone()))?;
		}

		// verify correctness of transaction inputs
		let sum_ins_var = self
			.verify_input_var(
				&hasher_params_var,
				&leaf_private_var,
				&leaf_public_var,
				&in_path_indices_var,
				&in_path_elements_var,
				&in_nullifier_var,
			)
			.unwrap();

		// verify correctness of transaction outputs
		let sum_outs_var = self
			.verify_output_var(
				&hasher_params_var,
				&output_commitment_var,
				&out_chain_id_var,
				&out_amount_var,
				&out_pubkey_var,
				&out_blinding_var,
			)
			.unwrap();

		// check that there are no same nullifiers among all inputs
		self.verify_no_same_nul(&in_nullifier_var).unwrap();

		// verify amount invariant
		self.verify_input_invariant(&public_amount_var, &sum_ins_var, &sum_outs_var)
			.unwrap();
		// Check if target root is in set

		// optional safety constraint to make sure extDataHash cannot be changed
		AG::constrain(&arbitrary_input_var)?;

		Ok(())
	}
}

//#[cfg(feature = "default_poseidon")]
//#[cfg(test)]
//mod test {}
