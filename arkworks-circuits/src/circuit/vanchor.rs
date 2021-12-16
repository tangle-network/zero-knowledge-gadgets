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
	merkle_tree::{constraints::PathVar, Config as MerkleConfig, Path},
	set::membership::{
		constraints::{PrivateVar as SetPrivateInputsVar, SetMembershipGadget},
		Private as SetPrivateInputs,
	},
};

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
	leaf_public_input: LeafPublicInputs<F>,          // chain_id
	set_private_inputs: Vec<SetPrivateInputs<F, M>>, // diffs
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
		set_private_inputs: Vec<SetPrivateInputs<F, M>>,
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
			set_private_inputs,
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
		root_set_var: &[FpVar<F>],
		set_input_private_var: &[SetPrivateInputsVar<F, M>],
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
			let check = SetMembershipGadget::check_is_enabled(
				&roothash,
				&root_set_var.to_vec(),
				&set_input_private_var[tx],
				in_amount_tx,
			)?;
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

	//Check that there are no same nullifiers among all inputs
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
		let set_private_inputs = self.set_private_inputs.clone();
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
			set_private_inputs,
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
		let set_private = self.set_private_inputs;
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
		let set_input_private_var =
			Vec::<SetPrivateInputsVar<F, M>>::new_witness(cs.clone(), || Ok(set_private))?;
		let in_path_elements_var =
			Vec::<PathVar<F, C, HGT, LHGT, K>>::new_witness(cs.clone(), || Ok(paths))?;
		let in_path_indices_var = Vec::<FpVar<F>>::new_witness(cs.clone(), || Ok(indices))?;

		// Outputs
		let out_leaf_private_var =
			Vec::<LeafPrivateInputsVar<F>>::new_witness(cs.clone(), || Ok(out_leaf_private))?;
		let out_leaf_public_var =
			Vec::<LeafPublicInputsVar<F>>::new_witness(cs.clone(), || Ok(out_leaf_public))?;
		let out_pubkey_var = Vec::<FpVar<F>>::new_witness(cs, || Ok(out_pubkey))?;

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
			&root_set_var,
			&set_input_private_var,
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
	use crate::{
		ark_std::{One, Zero},
		setup::vanchor::VAnchorProverBn2542x2,
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
	fn should_create_circuit_and_prove_groth16_2_input_2_output() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;
		let params2: PoseidonParameters<BnFr> = setup_params_x5_2(curve);
		let params3: PoseidonParameters<BnFr> = setup_params_x5_3(curve);
		let params4: PoseidonParameters<BnFr> = setup_params_x5_4(curve);
		let params5: PoseidonParameters<BnFr> = setup_params_x5_5(curve);
		let prover = VAnchorProverBn2542x2::new(params2, params3, params4, params5);

		let public_amount = 6;
		let recipient = vec![1u8; 20];
		let relayer = vec![2u8; 20];
		let ext_amount = 10;
		let fee = 0;

		let in_chain_id = 0;
		let in_amounts = [2; 2];
		let out_chain_ids = [0; 2];
		let out_amounts = [5; 2];

		let (circuit, pub_ins, ..) = prover.setup_circuit_with_data(
			public_amount,
			recipient,
			relayer,
			ext_amount,
			fee,
			in_chain_id,
			in_amounts,
			out_chain_ids,
			out_amounts,
			rng,
		);

		let (proving_key, verifying_key) =
			VAnchorProverBn2542x2::setup_keys::<Bn254, _>(circuit.clone(), rng);
		let proof = VAnchorProverBn2542x2::prove::<Bn254, _>(circuit, &proving_key, rng);
		let res = VAnchorProverBn2542x2::verify::<Bn254>(&pub_ins, &verifying_key, &proof);

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
		let arbitrary_data = VAnchorProverBn2542x2::setup_arbitrary_data(ext_data_hash);

		let in_chain_ids = [0; 2];
		let in_amounts = [5; 2];
		let in_utxos = prover.new_utxos(in_chain_ids, in_amounts, rng);

		let out_chain_ids = [0; 2];
		let out_amounts = [5; 2];
		let out_utxos = prover.new_utxos(out_chain_ids, out_amounts, rng);

		let (in_indices, in_paths, in_set_private_inputs, _) =
			prover.setup_tree_and_set(&in_utxos.commitments);

		// Invalid root set
		let in_root_set = [BnFr::rand(rng); 2];

		let pub_ins = VAnchorProverBn2542x2::construct_public_inputs(
			in_utxos.leaf_publics[0].chain_id,
			public_amount,
			in_root_set.to_vec(),
			in_utxos.nullifiers.to_vec(),
			out_utxos.commitments.to_vec(),
			ext_data_hash,
		);

		let circuit = prover.setup_circuit(
			public_amount,
			arbitrary_data,
			in_utxos,
			in_indices,
			in_paths,
			in_set_private_inputs,
			in_root_set,
			out_utxos,
		);

		let (proving_key, verifying_key) =
			VAnchorProverBn2542x2::setup_keys::<Bn254, _>(circuit.clone(), rng);
		let proof = VAnchorProverBn2542x2::prove::<Bn254, _>(circuit, &proving_key, rng);
		let res = VAnchorProverBn2542x2::verify::<Bn254>(&pub_ins, &verifying_key, &proof);

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
		let arbitrary_data = VAnchorProverBn2542x2::setup_arbitrary_data(ext_data_hash);

		let in_chain_ids = [0; 2];
		let in_amounts = [5; 2];
		let mut in_utxos = prover.new_utxos(in_chain_ids, in_amounts, rng);

		// Adding invalid nullifier
		in_utxos.nullifiers[0] = BnFr::rand(rng);

		let out_chain_ids = [0; 2];
		let out_amounts = [5; 2];
		let out_utxos = prover.new_utxos(out_chain_ids, out_amounts, rng);

		let (in_indices, in_paths, in_set_private_inputs, in_root_set) =
			prover.setup_tree_and_set(&in_utxos.commitments);

		let pub_ins = VAnchorProverBn2542x2::construct_public_inputs(
			in_utxos.leaf_publics[0].chain_id,
			public_amount,
			in_root_set.to_vec(),
			in_utxos.nullifiers.to_vec(),
			out_utxos.commitments.to_vec(),
			ext_data_hash,
		);

		let circuit = prover.setup_circuit(
			public_amount,
			arbitrary_data,
			in_utxos,
			in_indices,
			in_paths,
			in_set_private_inputs,
			in_root_set,
			out_utxos,
		);

		let (proving_key, verifying_key) =
			VAnchorProverBn2542x2::setup_keys::<Bn254, _>(circuit.clone(), rng);
		let proof = VAnchorProverBn2542x2::prove::<Bn254, _>(circuit, &proving_key, rng);
		let res = VAnchorProverBn2542x2::verify::<Bn254>(&pub_ins, &verifying_key, &proof);

		assert!(!res);
	}

	#[test]
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
		let arbitrary_data = VAnchorProverBn2542x2::setup_arbitrary_data(ext_data_hash);

		let in_chain_ids = [0; 2];
		let in_amounts = [5; 2];
		let mut in_utxos = prover.new_utxos(in_chain_ids, in_amounts, rng);

		// Sinc the nullifiers are the same, everything else should also be
		in_utxos.keypairs[0] = in_utxos.keypairs[1].clone();
		in_utxos.leaf_privates[0] = in_utxos.leaf_privates[1].clone();
		in_utxos.nullifiers[0] = in_utxos.nullifiers[1].clone();
		in_utxos.commitments[0] = in_utxos.commitments[1].clone();

		let out_chain_ids = [0; 2];
		let out_amounts = [5; 2];
		let out_utxos = prover.new_utxos(out_chain_ids, out_amounts, rng);

		let (in_indices, in_paths, in_set_private_inputs, in_root_set) =
			prover.setup_tree_and_set(&in_utxos.commitments);

		let pub_ins = VAnchorProverBn2542x2::construct_public_inputs(
			in_utxos.leaf_publics[0].chain_id,
			public_amount,
			in_root_set.to_vec(),
			in_utxos.nullifiers.to_vec(),
			out_utxos.commitments.to_vec(),
			ext_data_hash,
		);

		let circuit = prover.setup_circuit(
			public_amount,
			arbitrary_data,
			in_utxos,
			in_indices,
			in_paths,
			in_set_private_inputs,
			in_root_set,
			out_utxos,
		);

		let (proving_key, verifying_key) =
			VAnchorProverBn2542x2::setup_keys::<Bn254, _>(circuit.clone(), rng);
		let proof = VAnchorProverBn2542x2::prove::<Bn254, _>(circuit, &proving_key, rng);
		let res = VAnchorProverBn2542x2::verify::<Bn254>(&pub_ins, &verifying_key, &proof);

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
		let arbitrary_data = VAnchorProverBn2542x2::setup_arbitrary_data(ext_data_hash);

		let in_chain_ids = [0; 2];
		let in_amounts = [10; 2];
		let in_utxos = prover.new_utxos(in_chain_ids, in_amounts, rng);

		let out_chain_ids = [0; 2];
		let out_amounts = [5; 2];
		let out_utxos = prover.new_utxos(out_chain_ids, out_amounts, rng);

		let (in_indices, in_paths, in_set_private_inputs, in_root_set) =
			prover.setup_tree_and_set(&in_utxos.commitments);

		let pub_ins = VAnchorProverBn2542x2::construct_public_inputs(
			in_utxos.leaf_publics[0].chain_id,
			public_amount,
			in_root_set.to_vec(),
			in_utxos.nullifiers.to_vec(),
			out_utxos.commitments.to_vec(),
			ext_data_hash,
		);

		let circuit = prover.setup_circuit(
			public_amount,
			arbitrary_data,
			in_utxos,
			in_indices,
			in_paths,
			in_set_private_inputs,
			in_root_set,
			out_utxos,
		);

		let (proving_key, verifying_key) =
			VAnchorProverBn2542x2::setup_keys::<Bn254, _>(circuit.clone(), rng);
		let proof = VAnchorProverBn2542x2::prove::<Bn254, _>(circuit, &proving_key, rng);
		let res = VAnchorProverBn2542x2::verify::<Bn254>(&pub_ins, &verifying_key, &proof);

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
		let arbitrary_data = VAnchorProverBn2542x2::setup_arbitrary_data(ext_data_hash);

		let in_chain_ids = [BnFr::from(0u32); 2];
		let in_amounts = [limit + BnFr::one(); 2];
		let in_utxos = prover.new_utxos_f(in_chain_ids, in_amounts, rng);

		let out_chain_ids = [BnFr::from(0u32); 2];
		let out_amounts = [limit + BnFr::one(); 2];
		let out_utxos = prover.new_utxos_f(out_chain_ids, out_amounts, rng);

		let (in_indices, in_paths, in_set_private_inputs, in_root_set) =
			prover.setup_tree_and_set(&in_utxos.commitments);

		let pub_ins = VAnchorProverBn2542x2::construct_public_inputs(
			in_utxos.leaf_publics[0].chain_id,
			public_amount,
			in_root_set.to_vec(),
			in_utxos.nullifiers.to_vec(),
			out_utxos.commitments.to_vec(),
			ext_data_hash,
		);

		let circuit = prover.setup_circuit(
			public_amount,
			arbitrary_data,
			in_utxos,
			in_indices,
			in_paths,
			in_set_private_inputs,
			in_root_set,
			out_utxos,
		);

		let (proving_key, verifying_key) =
			VAnchorProverBn2542x2::setup_keys::<Bn254, _>(circuit.clone(), rng);
		let proof = VAnchorProverBn2542x2::prove::<Bn254, _>(circuit, &proving_key, rng);
		let res = VAnchorProverBn2542x2::verify::<Bn254>(&pub_ins, &verifying_key, &proof);

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
		let arbitrary_data = VAnchorProverBn2542x2::setup_arbitrary_data(ext_data_hash);

		let in_chain_ids = [0; 2];
		let in_amounts = [5; 2];
		let in_utxos = prover.new_utxos(in_chain_ids, in_amounts, rng);

		let out_chain_ids = [0; 2];
		let out_amounts = [5; 2];
		let out_utxos = prover.new_utxos(out_chain_ids, out_amounts, rng);

		let (in_indices, in_paths, in_set_private_inputs, in_root_set) =
			prover.setup_tree_and_set(&in_utxos.commitments);

		let pub_ins = VAnchorProverBn2542x2::construct_public_inputs(
			in_utxos.leaf_publics[0].chain_id,
			public_amount,
			in_root_set.to_vec(),
			in_utxos.nullifiers.to_vec(),
			out_utxos.commitments.to_vec(),
			ext_data_hash,
		);

		let circuit = prover.setup_circuit(
			public_amount,
			arbitrary_data,
			in_utxos,
			in_indices,
			in_paths,
			in_set_private_inputs,
			in_root_set,
			out_utxos,
		);

		let truncated_public_inputs = &pub_ins[2..];
		let (proving_key, verifying_key) =
			VAnchorProverBn2542x2::setup_keys::<Bn254, _>(circuit.clone(), rng);
		let proof = VAnchorProverBn2542x2::prove::<Bn254, _>(circuit, &proving_key, rng);

		let vk = VerifyingKey::<Bn254>::deserialize(&verifying_key[..]).unwrap();
		let proof = Proof::<Bn254>::deserialize(&proof[..]).unwrap();
		let res = Groth16::<Bn254>::verify(&vk, truncated_public_inputs, &proof);

		assert!(res.is_err());
	}
}
