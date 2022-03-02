use crate::Vec;

use ark_crypto_primitives::{crh::CRHGadget, CRH};
use ark_ec::TEModelParameters;
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
	merkle_tree::{constraints::PathVar, Config as MerkleConfig, Path},
	set::constraints::SetGadget,
};
use arkworks_utils::poseidon::PoseidonParameters;

pub struct VAnchorCircuit<
	F: PrimeField,
	// Hasher for the leaf creation,  Nullifier, Public key generation
	H: CRH,
	HG: CRHGadget<H, F>,
	// Merkle config and hasher gadget for the tree
	C: MerkleConfig,
	LHGT: CRHGadget<C::LeafH, F>,
	HGT: CRHGadget<C::H, F>,
	const K: usize,
	const N_INS: usize,
	const N_OUTS: usize,
	const M: usize,
> {
	public_amount: F,
	ext_data_hash: ArbitraryInput<F>,

	leaf_private_inputs: Vec<LeafPrivateInputs<F>>, // amount, blinding
	keypair_inputs: Vec<Keypair<F, H>>,
	leaf_public_input: LeafPublicInputs<F>, // chain_id
	root_set: [F; M],
	hasher_params_w2: H::Parameters,
	hasher_params_w4: H::Parameters,
	hasher_params_w5: H::Parameters,
	paths: Vec<Path<C, K>>,
	indices: Vec<F>,
	nullifier_hash: Vec<H::Output>,

	output_commitment: Vec<H::Output>,
	out_leaf_private: Vec<LeafPrivateInputs<F>>,
	out_leaf_public: Vec<LeafPublicInputs<F>>,
	out_pubkey: Vec<F>,

	_hasher: PhantomData<H>,
	_hasher_gadget: PhantomData<HG>,
	_leaf_hasher_gadget: PhantomData<LHGT>,
	_tree_hasher_gadget: PhantomData<HGT>,
	_merkle_config: PhantomData<C>,
}

impl<
		F,
		H,
		HG,
		C,
		LHGT,
		HGT,
		const K: usize,
		const N_INS: usize,
		const N_OUTS: usize,
		const M: usize,
	> VAnchorCircuit<F, H, HG, C, LHGT, HGT, K, N_INS, N_OUTS, M>
where
	F: PrimeField,
	H: CRH,
	HG: CRHGadget<H, F>,
	C: MerkleConfig,
	LHGT: CRHGadget<C::LeafH, F>,
	HGT: CRHGadget<C::H, F>,
{
	#[allow(clippy::too_many_arguments)]
	pub fn new(
		public_amount: F,
		ext_data_hash: ArbitraryInput<F>,
		leaf_private_inputs: Vec<LeafPrivateInputs<F>>,
		keypair_inputs: Vec<Keypair<F, H>>,
		leaf_public_input: LeafPublicInputs<F>,
		root_set: [F; M],
		hasher_params_w2: H::Parameters,
		hasher_params_w4: H::Parameters,
		hasher_params_w5: H::Parameters,
		paths: Vec<Path<C, K>>,
		indices: Vec<F>,
		nullifier_hash: Vec<H::Output>,
		output_commitment: Vec<H::Output>,
		out_leaf_private: Vec<LeafPrivateInputs<F>>,
		out_leaf_public: Vec<LeafPublicInputs<F>>,
		out_pubkey: Vec<F>,
	) -> Self {
		Self {
			public_amount,
			ext_data_hash,
			leaf_private_inputs,
			keypair_inputs,
			leaf_public_input,
			root_set,
			hasher_params_w2,
			hasher_params_w4,
			hasher_params_w5,
			paths,
			indices,
			nullifier_hash,
			output_commitment,
			out_leaf_private,
			out_leaf_public,
			out_pubkey,
			_hasher: PhantomData,
			_hasher_gadget: PhantomData,
			_leaf_hasher_gadget: PhantomData,
			_tree_hasher_gadget: PhantomData,
			_merkle_config: PhantomData,
		}
	}

	#[allow(clippy::too_many_arguments)]
	pub fn verify_input_var(
		hasher_params_w2_var: &HG::ParametersVar,
		hasher_params_w4_var: &HG::ParametersVar,
		hasher_params_w5_var: &HG::ParametersVar,
		leaf_private_var: &[LeafPrivateInputsVar<F>],
		inkeypair_var: &[KeypairVar<F, H, HG>],
		leaf_public_input_var: &LeafPublicInputsVar<F>,
		in_path_indices_var: &[FpVar<F>],
		in_path_elements_var: &[PathVar<F, C, HGT, LHGT, K>],
		in_nullifier_var: &[HG::OutputVar],
		set_gadget: &SetGadget<F>,
	) -> Result<FpVar<F>, SynthesisError> {
		let mut sums_ins_var = FpVar::<F>::zero();

		for tx in 0..N_INS {
			// Computing the public key
			let pub_key = inkeypair_var[tx].public_key(hasher_params_w2_var)?;
			// Computing the hash
			let in_utxo_hasher_var = VAnchorLeafGadget::<F, H, HG>::create_leaf(
				&leaf_private_var[tx],
				leaf_public_input_var,
				&pub_key,
				hasher_params_w5_var,
			)?;
			// End of computing the hash

			let signature = inkeypair_var[tx].signature(
				&in_utxo_hasher_var,
				&in_path_indices_var[tx],
				hasher_params_w4_var,
			)?;
			// Nullifier
			let nullifier_hash = VAnchorLeafGadget::<F, H, HG>::create_nullifier(
				&signature,
				&in_utxo_hasher_var,
				hasher_params_w4_var,
				&in_path_indices_var[tx],
			)?;

			nullifier_hash.enforce_equal(&in_nullifier_var[tx])?;

			// Add the roots and diffs signals to the vanchor circuit
			let roothash = &in_path_elements_var[tx].root_hash(&in_utxo_hasher_var)?;
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
		hasher_params_w5_var: &HG::ParametersVar,
		output_commitment_var: &[HG::OutputVar],
		leaf_private_var: &[LeafPrivateInputsVar<F>],
		leaf_public_var: &[LeafPublicInputsVar<F>],
		out_pubkey_var: &[FpVar<F>],
		limit_var: &FpVar<F>,
	) -> Result<FpVar<F>, SynthesisError> {
		let mut sums_outs_var = FpVar::<F>::zero();

		for tx in 0..N_OUTS {
			// Computing the hash
			let out_utxo_hasher_var = VAnchorLeafGadget::<F, H, HG>::create_leaf(
				&leaf_private_var[tx],
				&leaf_public_var[tx],
				&out_pubkey_var[tx],
				hasher_params_w5_var,
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
	pub fn verify_no_same_nul(in_nullifier_var: &[HG::OutputVar]) -> Result<(), SynthesisError> {
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
		H,
		HG,
		C,
		LHGT,
		HGT,
		const K: usize,
		const N_INS: usize,
		const N_OUTS: usize,
		const M: usize,
	> Clone for VAnchorCircuit<F, H, HG, C, LHGT, HGT, K, N_INS, N_OUTS, M>
where
	F: PrimeField,
	H: CRH,
	HG: CRHGadget<H, F>,
	C: MerkleConfig,
	LHGT: CRHGadget<C::LeafH, F>,
	HGT: CRHGadget<C::H, F>,
{
	fn clone(&self) -> Self {
		let public_amount = self.public_amount;
		let ext_data_hash = self.ext_data_hash.clone();
		let leaf_private_inputs = self.leaf_private_inputs.clone();
		let leaf_public_input = self.leaf_public_input.clone();
		let root_set = self.root_set;
		let hasher_params_w2 = self.hasher_params_w2.clone();
		let hasher_params_w4 = self.hasher_params_w4.clone();
		let hasher_params_w5 = self.hasher_params_w5.clone();
		let paths = self.paths.clone();
		let indices = self.indices.clone();
		let nullifier_hash = self.nullifier_hash.clone();
		let keypair_inputs = self.keypair_inputs.clone();
		let output_commitment = self.output_commitment.clone();
		let out_leaf_private = self.out_leaf_private.clone();
		let out_leaf_public = self.out_leaf_public.clone();
		let out_pubkey = self.out_pubkey.clone();

		Self::new(
			public_amount,
			ext_data_hash,
			leaf_private_inputs,
			keypair_inputs,
			leaf_public_input,
			root_set,
			hasher_params_w2,
			hasher_params_w4,
			hasher_params_w5,
			paths,
			indices,
			nullifier_hash,
			output_commitment,
			out_leaf_private,
			out_leaf_public,
			out_pubkey,
		)
	}
}

impl<
		F,
		H,
		HG,
		C,
		LHGT,
		HGT,
		const K: usize,
		const N_INS: usize,
		const N_OUTS: usize,
		const M: usize,
	> ConstraintSynthesizer<F> for VAnchorCircuit<F, H, HG, C, LHGT, HGT, K, N_INS, N_OUTS, M>
where
	F: PrimeField,
	H: CRH,
	HG: CRHGadget<H, F>,
	C: MerkleConfig,
	LHGT: CRHGadget<C::LeafH, F>,
	HGT: CRHGadget<C::H, F>,
{
	fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
		let public_amount = self.public_amount;
		let ext_data_hash = self.ext_data_hash;
		let leaf_private = self.leaf_private_inputs; // amount, blinding
		let keypair_inputs = self.keypair_inputs;
		let leaf_public_input = self.leaf_public_input; // chain id
		let root_set = self.root_set;
		let hasher_params_w2 = self.hasher_params_w2;
		let hasher_params_w4 = self.hasher_params_w4;
		let hasher_params_w5 = self.hasher_params_w5;
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
		let in_nullifier_var = Vec::<HG::OutputVar>::new_input(cs.clone(), || Ok(nullifier_hash))?;
		let output_commitment_var =
			Vec::<HG::OutputVar>::new_input(cs.clone(), || Ok(output_commitment))?;
		let leaf_public_input_var =
			LeafPublicInputsVar::new_input(cs.clone(), || Ok(leaf_public_input))?;
		let root_set_var = Vec::<FpVar<F>>::new_input(cs.clone(), || Ok(root_set))?;

		// Constants
		let limit_var: FpVar<F> = FpVar::<F>::new_constant(cs.clone(), limit)?;
		let hasher_params_w2_var = HG::ParametersVar::new_constant(cs.clone(), hasher_params_w2)?;
		let hasher_params_w4_var = HG::ParametersVar::new_constant(cs.clone(), hasher_params_w4)?;
		let hasher_params_w5_var = HG::ParametersVar::new_constant(cs.clone(), hasher_params_w5)?;

		// Private inputs
		let leaf_private_var =
			Vec::<LeafPrivateInputsVar<F>>::new_witness(cs.clone(), || Ok(leaf_private))?;
		let inkeypair_var =
			Vec::<KeypairVar<F, H, HG>>::new_witness(cs.clone(), || Ok(keypair_inputs))?;
		let in_path_elements_var =
			Vec::<PathVar<F, C, HGT, LHGT, K>>::new_witness(cs.clone(), || Ok(paths))?;
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
			&hasher_params_w2_var,
			&hasher_params_w4_var,
			&hasher_params_w5_var,
			&leaf_private_var,
			&inkeypair_var,
			&leaf_public_input_var,
			&in_path_indices_var,
			&in_path_elements_var,
			&in_nullifier_var,
			&set_gadget,
		)?;

		// verify correctness of transaction outputs
		let sum_outs_var = Self::verify_output_var(
			&hasher_params_w5_var,
			&output_commitment_var,
			&out_leaf_private_var,
			&out_leaf_public_var,
			&out_pubkey_var,
			&limit_var,
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

#[cfg(test)]
mod test {
	use ark_std::vec;

	use crate::{
		ark_std::{One, Zero},
		setup::{common::*, vanchor::VAnchorProverBn2542x2},
	};
	use ark_serialize::CanonicalDeserialize;
	use arkworks_utils::{
		poseidon::PoseidonParameters,
		utils::common::{
			setup_params_x5_2, setup_params_x5_3, setup_params_x5_4, setup_params_x5_5, Curve,
		},
	};

	use ark_bn254::{Bn254, Fr as BnFr};
	use ark_ff::UniformRand;
	use ark_groth16::{Groth16, Proof, VerifyingKey};

	use crate::prelude::ark_std::str::FromStr;
	use ark_snark::SNARK;
	use ark_std::test_rng;

	#[test]
	fn should_create_proof_for_random_circuit() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;
		let params2 = setup_params_x5_2::<BnFr>(curve);
		let params3 = setup_params_x5_3::<BnFr>(curve);
		let params4 = setup_params_x5_4::<BnFr>(curve);
		let params5 = setup_params_x5_5::<BnFr>(curve);

		// Set up a random circuit and make pk/vk pair
		let prover = VAnchorProverBn2542x2::new(params2, params3, params4, params5);
		let random_circuit = prover.clone().setup_random_circuit(rng).unwrap();
		let (proving_key, verifying_key) = setup_keys::<Bn254, _, _>(random_circuit, rng).unwrap();

		// Make a proof now
		let public_amount = BnFr::from(10u32);
		let ext_data_hash = BnFr::rand(rng);

		// Input Utxos
		let in_chain_id = BnFr::from(0u32);
		let in_amount = BnFr::from(5u32);
		let index = BnFr::from(0u32);
		let in_utxo1 = prover
			.new_utxo(in_chain_id, in_amount, Some(index), None, None, rng)
			.unwrap();
		let in_utxo2 = prover
			.new_utxo(in_chain_id, in_amount, Some(index), None, None, rng)
			.unwrap();
		let in_utxos = [in_utxo1, in_utxo2];

		// Output Utxos
		let out_chain_id = BnFr::from(0u32);
		let out_amount = BnFr::from(10u32);
		let out_utxo1 = prover
			.new_utxo(out_chain_id, out_amount, None, None, None, rng)
			.unwrap();
		let out_utxo2 = prover
			.new_utxo(out_chain_id, out_amount, None, None, None, rng)
			.unwrap();
		let out_utxos = [out_utxo1, out_utxo2];

		let leaf0 = in_utxo1.commitment;
		let (in_path0, _) = prover.setup_tree(&vec![leaf0], 0).unwrap();
		let root0 = in_path0.root_hash(&leaf0).unwrap().inner();
		let leaf1 = in_utxo2.commitment;
		let (in_path1, _) = prover.setup_tree(&vec![leaf1], 0).unwrap();
		let root1 = in_path1.root_hash(&leaf1).unwrap().inner();

		let in_leaves = [vec![leaf0], vec![leaf1]];
		let in_indices = [0; 2];
		let in_root_set = [root0, root1];

		let (circuit, .., pub_ins) = prover
			.setup_circuit_with_utxos(
				public_amount,
				ext_data_hash,
				in_root_set,
				in_indices,
				in_leaves,
				in_utxos,
				out_utxos,
			)
			.unwrap();

		let proof = prove::<Bn254, _, _>(circuit, &proving_key, rng).unwrap();
		let res = verify::<Bn254>(&pub_ins, &verifying_key, &proof).unwrap();

		assert!(res);
	}

	#[test]
	fn should_create_circuit_and_prove_groth16_2_input_2_output() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;
		let params2: PoseidonParameters<BnFr> = setup_params_x5_2(curve);
		let params3: PoseidonParameters<BnFr> = setup_params_x5_3(curve);
		let params4: PoseidonParameters<BnFr> = setup_params_x5_4(curve);
		let params5: PoseidonParameters<BnFr> = setup_params_x5_5(curve);
		let prover = VAnchorProverBn2542x2::new(params2, params3, params4, params5);

		let public_amount = BnFr::from(10u32);
		let ext_data_hash = BnFr::rand(rng);

		// Input Utxos
		let in_chain_id = BnFr::from(0u32);
		let in_amount = BnFr::from(5u32);
		let index = BnFr::from(0u32);
		let in_utxo1 = prover
			.new_utxo(in_chain_id, in_amount, Some(index), None, None, rng)
			.unwrap();
		let in_utxo2 = prover
			.new_utxo(in_chain_id, in_amount, Some(index), None, None, rng)
			.unwrap();
		let in_utxos = [in_utxo1, in_utxo2];

		// Output Utxos
		let out_chain_id = BnFr::from(0u32);
		let out_amount = BnFr::from(10u32);
		let out_utxo1 = prover
			.new_utxo(out_chain_id, out_amount, None, None, None, rng)
			.unwrap();
		let out_utxo2 = prover
			.new_utxo(out_chain_id, out_amount, None, None, None, rng)
			.unwrap();
		let out_utxos = [out_utxo1, out_utxo2];

		let leaf0 = in_utxo1.commitment;
		let (in_path0, _) = prover.setup_tree(&vec![leaf0], 0).unwrap();
		let root0 = in_path0.root_hash(&leaf0).unwrap().inner();
		let leaf1 = in_utxo2.commitment;
		let (in_path1, _) = prover.setup_tree(&vec![leaf1], 0).unwrap();
		let root1 = in_path1.root_hash(&leaf1).unwrap().inner();

		let in_leaves = [vec![leaf0], vec![leaf1]];
		let in_indices = [0; 2];
		let in_root_set = [root0, root1];

		let (circuit, .., pub_ins) = prover
			.setup_circuit_with_utxos(
				public_amount,
				ext_data_hash,
				in_root_set,
				in_indices,
				in_leaves,
				in_utxos,
				out_utxos,
			)
			.unwrap();

		let (proving_key, verifying_key) = setup_keys::<Bn254, _, _>(circuit.clone(), rng).unwrap();
		let proof = prove::<Bn254, _, _>(circuit, &proving_key, rng).unwrap();
		let res = verify::<Bn254>(&pub_ins, &verifying_key, &proof).unwrap();

		assert!(res);
	}

	#[test]
	fn should_fail_with_invalid_root() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;
		let params2: PoseidonParameters<BnFr> = setup_params_x5_2(curve);
		let params3: PoseidonParameters<BnFr> = setup_params_x5_3(curve);
		let params4: PoseidonParameters<BnFr> = setup_params_x5_4(curve);
		let params5: PoseidonParameters<BnFr> = setup_params_x5_5(curve);
		let prover = VAnchorProverBn2542x2::new(params2, params3, params4, params5);

		let public_amount = BnFr::from(10u32);
		let ext_data_hash = BnFr::rand(rng);

		// Input Utxos
		let in_chain_id = BnFr::from(0u32);
		let in_amount = BnFr::from(5u32);
		let index = BnFr::from(0u32);
		let in_utxo1 = prover
			.new_utxo(in_chain_id, in_amount, Some(index), None, None, rng)
			.unwrap();
		let in_utxo2 = prover
			.new_utxo(in_chain_id, in_amount, Some(index), None, None, rng)
			.unwrap();
		let in_utxos = [in_utxo1, in_utxo2];

		// Output Utxos
		let out_chain_id = BnFr::from(0u32);
		let out_amount = BnFr::from(10u32);
		let out_utxo1 = prover
			.new_utxo(out_chain_id, out_amount, None, None, None, rng)
			.unwrap();
		let out_utxo2 = prover
			.new_utxo(out_chain_id, out_amount, None, None, None, rng)
			.unwrap();
		let out_utxos = [out_utxo1, out_utxo2];

		let leaf0 = in_utxos[0].commitment;
		let leaf1 = in_utxos[1].commitment;

		let in_leaves = [vec![leaf0], vec![leaf1]];
		let in_indices = [0; 2];

		// Invalid root set
		let in_root_set = [BnFr::rand(rng); 2];

		let (circuit, .., pub_ins) = prover
			.setup_circuit_with_utxos(
				public_amount,
				ext_data_hash,
				in_root_set,
				in_indices,
				in_leaves,
				in_utxos,
				out_utxos,
			)
			.unwrap();

		let (proving_key, verifying_key) = setup_keys::<Bn254, _, _>(circuit.clone(), rng).unwrap();
		let proof = prove::<Bn254, _, _>(circuit, &proving_key, rng).unwrap();
		let res = verify::<Bn254>(&pub_ins, &verifying_key, &proof).unwrap();

		assert!(!res);
	}

	#[test]
	fn should_fail_with_invalid_nullifier() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;
		let params2: PoseidonParameters<BnFr> = setup_params_x5_2(curve);
		let params3: PoseidonParameters<BnFr> = setup_params_x5_3(curve);
		let params4: PoseidonParameters<BnFr> = setup_params_x5_4(curve);
		let params5: PoseidonParameters<BnFr> = setup_params_x5_5(curve);
		let prover = VAnchorProverBn2542x2::new(params2, params3, params4, params5);

		let public_amount = BnFr::from(10u32);
		let ext_data_hash = BnFr::rand(rng);

		// Input Utxos
		let in_chain_id = BnFr::from(0u32);
		let in_amount = BnFr::from(5u32);
		let index = BnFr::from(0u32);
		let mut in_utxo1 = prover
			.new_utxo(in_chain_id, in_amount, Some(index), None, None, rng)
			.unwrap();
		let in_utxo2 = prover
			.new_utxo(in_chain_id, in_amount, Some(index), None, None, rng)
			.unwrap();

		// Adding invalid nullifier
		in_utxo1.nullifier = Some(BnFr::rand(rng));

		let in_utxos = [in_utxo1, in_utxo2];

		// Output Utxos
		let out_chain_id = BnFr::from(0u32);
		let out_amount = BnFr::from(10u32);
		let out_utxo1 = prover
			.new_utxo(out_chain_id, out_amount, None, None, None, rng)
			.unwrap();
		let out_utxo2 = prover
			.new_utxo(out_chain_id, out_amount, None, None, None, rng)
			.unwrap();
		let out_utxos = [out_utxo1, out_utxo2];

		let leaf0 = in_utxos[0].commitment;
		let (in_path0, _) = prover.setup_tree(&vec![leaf0], 0).unwrap();
		let root0 = in_path0.root_hash(&leaf0).unwrap().inner();
		let leaf1 = in_utxos[1].commitment;
		let (in_path1, _) = prover.setup_tree(&vec![leaf1], 0).unwrap();
		let root1 = in_path1.root_hash(&leaf1).unwrap().inner();

		let in_leaves = [vec![leaf0], vec![leaf1]];
		let in_indices = [0; 2];
		let in_root_set = [root0, root1];

		let (circuit, .., pub_ins) = prover
			.setup_circuit_with_utxos(
				public_amount,
				ext_data_hash,
				in_root_set,
				in_indices,
				in_leaves,
				in_utxos,
				out_utxos,
			)
			.unwrap();

		let (proving_key, verifying_key) = setup_keys::<Bn254, _, _>(circuit.clone(), rng).unwrap();
		let proof = prove::<Bn254, _, _>(circuit, &proving_key, rng).unwrap();
		let res = verify::<Bn254>(&pub_ins, &verifying_key, &proof).unwrap();

		assert!(!res);
	}

	#[test]
	#[ignore]
	fn should_fail_with_same_nullifier() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;
		let params2: PoseidonParameters<BnFr> = setup_params_x5_2(curve);
		let params3: PoseidonParameters<BnFr> = setup_params_x5_3(curve);
		let params4: PoseidonParameters<BnFr> = setup_params_x5_4(curve);
		let params5: PoseidonParameters<BnFr> = setup_params_x5_5(curve);
		let prover = VAnchorProverBn2542x2::new(params2, params3, params4, params5);

		let public_amount = BnFr::from(0u32);
		let ext_data_hash = BnFr::rand(rng);

		// Input Utxos
		let in_chain_id = BnFr::from(0u32);
		let in_amount = BnFr::from(5u32);
		let index = BnFr::from(0u32);
		let in_utxo1 = prover
			.new_utxo(in_chain_id, in_amount, Some(index), None, None, rng)
			.unwrap();

		// Both inputs are the same -- attempt of double spending
		let in_utxos = [in_utxo1, in_utxo1];

		// Output Utxos
		let out_chain_id = BnFr::from(0u32);
		let out_amount = BnFr::from(10u32);
		let out_utxo1 = prover
			.new_utxo(out_chain_id, out_amount, None, None, None, rng)
			.unwrap();
		let out_utxo2 = prover
			.new_utxo(out_chain_id, out_amount, None, None, None, rng)
			.unwrap();
		let out_utxos = [out_utxo1, out_utxo2];

		let leaf0 = in_utxos[0].commitment;
		let (in_path0, _) = prover.setup_tree(&vec![leaf0], 0).unwrap();
		let root0 = in_path0.root_hash(&leaf0).unwrap().inner();
		let leaf1 = in_utxos[1].commitment;
		let (in_path1, _) = prover.setup_tree(&vec![leaf1], 0).unwrap();
		let root1 = in_path1.root_hash(&leaf1).unwrap().inner();

		let in_leaves = [vec![leaf0], vec![leaf1]];
		let in_indices = [0; 2];
		let in_root_set = [root0, root1];

		let (circuit, .., pub_ins) = prover
			.setup_circuit_with_utxos(
				public_amount,
				ext_data_hash,
				in_root_set,
				in_indices,
				in_leaves,
				in_utxos,
				out_utxos,
			)
			.unwrap();

		let (proving_key, verifying_key) = setup_keys::<Bn254, _, _>(circuit.clone(), rng).unwrap();
		let proof = prove::<Bn254, _, _>(circuit, &proving_key, rng).unwrap();
		let res = verify::<Bn254>(&pub_ins, &verifying_key, &proof).unwrap();

		assert!(!res);
	}

	#[test]
	fn should_fail_with_inconsistent_input_output_values() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;
		let params2: PoseidonParameters<BnFr> = setup_params_x5_2(curve);
		let params3: PoseidonParameters<BnFr> = setup_params_x5_3(curve);
		let params4: PoseidonParameters<BnFr> = setup_params_x5_4(curve);
		let params5: PoseidonParameters<BnFr> = setup_params_x5_5(curve);
		let prover = VAnchorProverBn2542x2::new(params2, params3, params4, params5);

		let public_amount = BnFr::from(10u32);
		let ext_data_hash = BnFr::rand(rng);

		// Input Utxos
		let in_chain_id = BnFr::from(0u32);
		// Input amount too high
		let in_amount = BnFr::from(10u32);
		let index = BnFr::from(0u32);
		let in_utxo1 = prover
			.new_utxo(in_chain_id, in_amount, Some(index), None, None, rng)
			.unwrap();
		let in_utxo2 = prover
			.new_utxo(in_chain_id, in_amount, Some(index), None, None, rng)
			.unwrap();
		let in_utxos = [in_utxo1, in_utxo2];

		// Output Utxos
		let out_chain_id = BnFr::from(0u32);
		let out_amount = BnFr::from(10u32);
		let out_utxo1 = prover
			.new_utxo(out_chain_id, out_amount, None, None, None, rng)
			.unwrap();
		let out_utxo2 = prover
			.new_utxo(out_chain_id, out_amount, None, None, None, rng)
			.unwrap();
		let out_utxos = [out_utxo1, out_utxo2];

		let leaf0 = in_utxos[0].commitment;
		let (in_path0, _) = prover.setup_tree(&vec![leaf0], 0).unwrap();
		let root0 = in_path0.root_hash(&leaf0).unwrap().inner();
		let leaf1 = in_utxos[1].commitment;
		let (in_path1, _) = prover.setup_tree(&vec![leaf1], 0).unwrap();
		let root1 = in_path1.root_hash(&leaf1).unwrap().inner();

		let in_leaves = [vec![leaf0], vec![leaf1]];
		let in_indices = [0; 2];
		let in_root_set = [root0, root1];

		let (circuit, .., pub_ins) = prover
			.setup_circuit_with_utxos(
				public_amount,
				ext_data_hash,
				in_root_set,
				in_indices,
				in_leaves,
				in_utxos,
				out_utxos,
			)
			.unwrap();

		let (proving_key, verifying_key) = setup_keys::<Bn254, _, _>(circuit.clone(), rng).unwrap();
		let proof = prove::<Bn254, _, _>(circuit, &proving_key, rng).unwrap();
		let res = verify::<Bn254>(&pub_ins, &verifying_key, &proof).unwrap();

		assert!(!res);
	}

	#[test]
	fn should_fail_with_big_amount() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;
		let params2: PoseidonParameters<BnFr> = setup_params_x5_2(curve);
		let params3: PoseidonParameters<BnFr> = setup_params_x5_3(curve);
		let params4: PoseidonParameters<BnFr> = setup_params_x5_4(curve);
		let params5: PoseidonParameters<BnFr> = setup_params_x5_5(curve);
		let prover = VAnchorProverBn2542x2::new(params2, params3, params4, params5);

		// 2^248
		let limit = BnFr::from_str(
			"452312848583266388373324160190187140051835877600158453279131187530910662656",
		)
		.unwrap();

		let public_amount = BnFr::zero();
		let ext_data_hash = BnFr::rand(rng);

		// Input Utxos
		let in_chain_id = BnFr::from(0u32);
		let in_amount = BnFr::from(limit + BnFr::one());
		let index = BnFr::from(0u32);
		let in_utxo1 = prover
			.new_utxo(in_chain_id, in_amount, Some(index), None, None, rng)
			.unwrap();
		let in_utxo2 = prover
			.new_utxo(in_chain_id, in_amount, Some(index), None, None, rng)
			.unwrap();
		let in_utxos = [in_utxo1, in_utxo2];

		// Output Utxos
		let out_chain_id = BnFr::from(0u32);
		let out_amount = BnFr::from(10u32);
		let out_utxo1 = prover
			.new_utxo(out_chain_id, out_amount, None, None, None, rng)
			.unwrap();
		let out_utxo2 = prover
			.new_utxo(out_chain_id, out_amount, None, None, None, rng)
			.unwrap();
		let out_utxos = [out_utxo1, out_utxo2];

		let leaf0 = in_utxos[0].commitment;
		let (in_path0, _) = prover.setup_tree(&vec![leaf0], 0).unwrap();
		let root0 = in_path0.root_hash(&leaf0).unwrap().inner();
		let leaf1 = in_utxos[1].commitment;
		let (in_path1, _) = prover.setup_tree(&vec![leaf1], 0).unwrap();
		let root1 = in_path1.root_hash(&leaf1).unwrap().inner();

		let in_leaves = [vec![leaf0], vec![leaf1]];
		let in_indices = [0; 2];
		let in_root_set = [root0, root1];

		let (circuit, .., pub_ins) = prover
			.setup_circuit_with_utxos(
				public_amount,
				ext_data_hash,
				in_root_set,
				in_indices,
				in_leaves,
				in_utxos,
				out_utxos,
			)
			.unwrap();

		let (proving_key, verifying_key) = setup_keys::<Bn254, _, _>(circuit.clone(), rng).unwrap();
		let proof = prove::<Bn254, _, _>(circuit, &proving_key, rng).unwrap();
		let res = verify::<Bn254>(&pub_ins, &verifying_key, &proof).unwrap();

		assert!(!res);
	}

	#[test]
	fn should_fail_with_invalid_public_input() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;
		let params2: PoseidonParameters<BnFr> = setup_params_x5_2(curve);
		let params3: PoseidonParameters<BnFr> = setup_params_x5_3(curve);
		let params4: PoseidonParameters<BnFr> = setup_params_x5_4(curve);
		let params5: PoseidonParameters<BnFr> = setup_params_x5_5(curve);
		let prover = VAnchorProverBn2542x2::new(params2, params3, params4, params5);

		let public_amount = BnFr::from(0u32);
		let ext_data_hash = BnFr::rand(rng);

		// Input Utxos
		let in_chain_id = BnFr::from(0u32);
		let in_amount = BnFr::from(5u32);
		let index = BnFr::from(0u32);
		let in_utxo1 = prover
			.new_utxo(in_chain_id, in_amount, Some(index), None, None, rng)
			.unwrap();
		let in_utxo2 = prover
			.new_utxo(in_chain_id, in_amount, Some(index), None, None, rng)
			.unwrap();
		let in_utxos = [in_utxo1, in_utxo2];

		// Output Utxos
		let out_chain_id = BnFr::from(0u32);
		let out_amount = BnFr::from(10u32);
		let out_utxo1 = prover
			.new_utxo(out_chain_id, out_amount, None, None, None, rng)
			.unwrap();
		let out_utxo2 = prover
			.new_utxo(out_chain_id, out_amount, None, None, None, rng)
			.unwrap();
		let out_utxos = [out_utxo1, out_utxo2];

		let leaf0 = in_utxos[0].commitment;
		let (in_path0, _) = prover.setup_tree(&vec![leaf0], 0).unwrap();
		let root0 = in_path0.root_hash(&leaf0).unwrap().inner();
		let leaf1 = in_utxos[1].commitment;
		let (in_path1, _) = prover.setup_tree(&vec![leaf1], 0).unwrap();
		let root1 = in_path1.root_hash(&leaf1).unwrap().inner();

		let in_leaves = [vec![leaf0], vec![leaf1]];
		let in_indices = [0; 2];
		let in_root_set = [root0, root1];

		let (circuit, .., pub_ins) = prover
			.setup_circuit_with_utxos(
				public_amount,
				ext_data_hash,
				in_root_set,
				in_indices,
				in_leaves,
				in_utxos,
				out_utxos,
			)
			.unwrap();

		let truncated_public_inputs = &pub_ins[2..];
		let (proving_key, verifying_key) = setup_keys::<Bn254, _, _>(circuit.clone(), rng).unwrap();
		let proof = prove::<Bn254, _, _>(circuit, &proving_key, rng).unwrap();

		let vk = VerifyingKey::<Bn254>::deserialize(&verifying_key[..]).unwrap();
		let proof = Proof::<Bn254>::deserialize(&proof[..]).unwrap();
		let res = Groth16::<Bn254>::verify(&vk, truncated_public_inputs, &proof);

		assert!(res.is_err());
	}
}
