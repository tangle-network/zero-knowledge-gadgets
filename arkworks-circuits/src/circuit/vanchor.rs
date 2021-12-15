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
	use super::*;
	use crate::{
		ark_std::{One, Zero},
		setup::{
			bridge::*,
			common::*,
			vanchor::{setup_vanchor_arbitrary_data, VAnchorProverBn2542x2},
		},
	};
	use arkworks_gadgets::{
		keypair::vanchor::Keypair,
		leaf::vanchor::VAnchorLeaf,
		merkle_tree::{Config as MerkleConfig, SparseMerkleTree},
		poseidon::{constraints::CRHGadget as PCRHGadget, CRH as PCRH},
	};
	use arkworks_utils::{
		poseidon::PoseidonParameters,
		utils::common::{
			setup_params_x5_2, setup_params_x5_3, setup_params_x5_4, setup_params_x5_5, Curve,
		},
	};

	use ark_bn254::{Bn254, Fr as BnFr};
	use ark_ff::{to_bytes, UniformRand};
	use ark_groth16::Groth16;

	use crate::prelude::ark_std::{rc::Rc, str::FromStr};
	use ark_snark::SNARK;
	use ark_std::test_rng;
	pub const TEST_K: usize = 30;
	pub const TEST_N_INS_2: usize = 2;
	pub const TEST_N_OUTS_2: usize = 2;
	pub const TEST_M: usize = 2;

	type PoseidonCRH = PCRH<BnFr>;
	type PoseidonCRHGadget = PCRHGadget<BnFr>;

	type KeyPair = Keypair<BnFr, PoseidonCRH>;
	type Leaf = VAnchorLeaf<BnFr, PoseidonCRH>;
	#[allow(non_camel_case_types)]
	#[derive(Clone, PartialEq)]
	pub struct TreeConfig_x5<F: PrimeField>(PhantomData<F>);
	impl<F: PrimeField> MerkleConfig for TreeConfig_x5<F> {
		type H = PoseidonCRH_x5_3<F>;
		type LeafH = LeafCRH<F>;

		const HEIGHT: u8 = (TEST_K as u8);
	}
	#[allow(non_camel_case_types)]
	pub type Tree_x5<BnFr> = SparseMerkleTree<TreeConfig_x5<BnFr>>;

	type VACircuit = VAnchorCircuit<
		BnFr,
		PoseidonCRH,
		PoseidonCRHGadget,
		TreeConfig_x5<BnFr>,
		LeafCRHGadget<BnFr>,
		PoseidonCRH_x5_3Gadget<BnFr>,
		TEST_K,
		TEST_N_INS_2,
		TEST_N_OUTS_2,
		TEST_M,
	>;

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

	#[should_panic]
	#[test]
	fn should_fail_with_invalid_nullifier() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;
		let hasher_params_w5: PoseidonParameters<BnFr> = setup_params_x5_5(curve);
		let hasher_params_w4: PoseidonParameters<BnFr> = setup_params_x5_4(curve);
		let params3: PoseidonParameters<BnFr> = setup_params_x5_3(curve);
		let hasher_params_w2: PoseidonParameters<BnFr> = setup_params_x5_2(curve);
		let chain_id = BnFr::zero();

		let in_amount_1 = BnFr::one();
		let blinding_1 = BnFr::rand(rng);
		let in_amount_2 = BnFr::one() + BnFr::one();
		let blinding_2 = BnFr::rand(rng);
		let leaf_private_1 = LeafPrivateInputs::<BnFr>::new(in_amount_1, blinding_1);
		let leaf_private_2 = LeafPrivateInputs::<BnFr>::new(in_amount_2, blinding_2);
		let leaf_private_inputs = vec![leaf_private_1.clone(), leaf_private_2.clone()];

		let leaf_public_input = LeafPublicInputs::<BnFr>::new(chain_id.clone());

		let private_key_1 = BnFr::rand(rng);
		let keypair_1 = KeyPair::new(private_key_1.clone());
		let privkey = to_bytes![private_key_1].unwrap();
		let public_key_1 = PoseidonCRH::evaluate(&hasher_params_w2, &privkey).unwrap();
		let private_key_2 = BnFr::rand(rng);
		let keypair_2 = KeyPair::new(private_key_2.clone());
		let privkey = to_bytes![private_key_2].unwrap();
		let public_key_2 = PoseidonCRH::evaluate(&hasher_params_w2, &privkey).unwrap();
		let keypair_inputs = vec![keypair_1.clone(), keypair_2.clone()];

		let leaf_1 = Leaf::create_leaf(
			&leaf_private_1,
			&leaf_public_input,
			&public_key_1,
			&hasher_params_w5,
		)
		.unwrap();
		let commitment_1 = leaf_1.clone();
		let leaf_2 = Leaf::create_leaf(
			&leaf_private_2,
			&leaf_public_input,
			&public_key_2,
			&hasher_params_w5,
		)
		.unwrap();

		let inner_params = Rc::new(params3.clone());
		let leaves = [leaf_1, leaf_2];
		let tree = Tree_x5::new_sequential(inner_params, Rc::new(()), &leaves).unwrap();

		let path_1 = tree.generate_membership_proof(0);
		let path_2 = tree.generate_membership_proof(1);
		let paths = vec![path_1.clone(), path_2.clone()];

		let public_amount = BnFr::one();

		let ext_data_hash_1 = setup_vanchor_arbitrary_data(commitment_1);
		let ext_data_hash = ext_data_hash_1; // We used it as a sample value for ext_data_hash in the tests
		let root = tree.root().inner();

		let mut root_set = [BnFr::rand(rng); TEST_M];
		root_set[0] = root;
		assert_eq!(root_set.len(), TEST_M);
		let index_0: BnFr = path_1.get_index(&tree.root(), &leaf_1).unwrap();
		let index_1: BnFr = path_1.get_index(&tree.root(), &leaf_2).unwrap();
		assert_eq!(index_0, BnFr::zero());
		assert_eq!(index_1, BnFr::one());
		let indices = vec![index_0, index_1];

		let nullifier_hash_1 = BnFr::rand(rng);
		let signature = keypair_2
			.signature(&leaf_2, &index_1, &hasher_params_w4)
			.unwrap();
		let nullifier_hash_2 =
			Leaf::create_nullifier(&signature, &leaf_2, &hasher_params_w4, &index_1).unwrap();
		let nullifier_hash = vec![nullifier_hash_1, nullifier_hash_2];

		let set_private_inputs_1 = setup_set(&root, &root_set);
		let set_private_inputs = vec![set_private_inputs_1.clone(), set_private_inputs_1.clone()];

		let out_chain_id_1 = BnFr::one();
		let out_amount_1 = public_amount + leaf_private_1.amount;
		let out_pubkey_1 = BnFr::rand(rng);
		let out_blinding_1 = BnFr::rand(rng);

		let out_chain_id_2 = BnFr::one();
		let out_amount_2 = leaf_private_2.amount;
		let out_pubkey_2 = BnFr::rand(rng);
		let out_blinding_2 = BnFr::rand(rng);

		let out_leaf_private_1 = LeafPrivateInputs::<BnFr>::new(out_amount_1, out_blinding_1);
		let out_leaf_private_2 = LeafPrivateInputs::<BnFr>::new(out_amount_2, out_blinding_2);
		let out_leaf_private = vec![out_leaf_private_1.clone(), out_leaf_private_2.clone()];

		let out_leaf_public_1 = LeafPublicInputs::<BnFr>::new(out_chain_id_1);
		let out_leaf_public_2 = LeafPublicInputs::<BnFr>::new(out_chain_id_2);
		let out_leaf_public = vec![out_leaf_public_1.clone(), out_leaf_public_2.clone()];

		let output_commitment_1 = Leaf::create_leaf(
			&out_leaf_private_1,
			&out_leaf_public_1,
			&out_pubkey_1,
			&hasher_params_w5,
		)
		.unwrap();

		let output_commitment_2 = Leaf::create_leaf(
			&out_leaf_private_2,
			&out_leaf_public_2,
			&out_pubkey_2,
			&hasher_params_w5,
		)
		.unwrap();

		let out_pubkey = vec![out_pubkey_1, out_pubkey_2];
		let output_commitment = vec![output_commitment_1, output_commitment_2];
		let circuit = VACircuit::new(
			public_amount.clone(),
			ext_data_hash.clone(),
			leaf_private_inputs,
			keypair_inputs,
			leaf_public_input,
			set_private_inputs,
			root_set.clone(),
			hasher_params_w2,
			hasher_params_w4,
			hasher_params_w5,
			paths,
			indices,
			nullifier_hash.clone(),
			output_commitment.clone(),
			out_leaf_private,
			out_leaf_public,
			out_pubkey,
		);

		let mut public_inputs = Vec::new();
		public_inputs.push(public_amount);
		public_inputs.push(ext_data_hash.ext_data);
		public_inputs.extend(nullifier_hash);
		public_inputs.extend(output_commitment);
		public_inputs.push(chain_id);
		public_inputs.extend(root_set);

		let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), rng).unwrap();
		let proof = Groth16::<Bn254>::prove(&pk, circuit.clone(), rng).unwrap();
		let res = Groth16::<Bn254>::verify(&vk, &public_inputs, &proof).unwrap();

		assert!(res);
	}

	#[should_panic]
	#[test]
	fn should_fail_with_same_nullifier() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;
		let hasher_params_w5: PoseidonParameters<BnFr> = setup_params_x5_5(curve);
		let hasher_params_w4: PoseidonParameters<BnFr> = setup_params_x5_4(curve);
		let params3: PoseidonParameters<BnFr> = setup_params_x5_3(curve);
		let hasher_params_w2: PoseidonParameters<BnFr> = setup_params_x5_2(curve);
		let chain_id = BnFr::zero();

		let in_amount_1 = BnFr::one();
		let blinding_1 = BnFr::rand(rng);
		let in_amount_2 = BnFr::one() + BnFr::one();
		let blinding_2 = BnFr::rand(rng);
		let leaf_private_1 = LeafPrivateInputs::<BnFr>::new(in_amount_1, blinding_1);
		let leaf_private_2 = LeafPrivateInputs::<BnFr>::new(in_amount_2, blinding_2);
		let leaf_private_inputs = vec![leaf_private_1.clone(), leaf_private_2.clone()];

		let leaf_public_input = LeafPublicInputs::<BnFr>::new(chain_id.clone());

		let private_key_1 = BnFr::rand(rng);
		let keypair_1 = KeyPair::new(private_key_1.clone());
		let privkey = to_bytes![private_key_1].unwrap();
		let public_key_1 = PoseidonCRH::evaluate(&hasher_params_w2, &privkey).unwrap();
		let private_key_2 = BnFr::rand(rng);
		let keypair_2 = KeyPair::new(private_key_2.clone());
		let privkey = to_bytes![private_key_2].unwrap();
		let public_key_2 = PoseidonCRH::evaluate(&hasher_params_w2, &privkey).unwrap();
		let keypair_inputs = vec![keypair_1.clone(), keypair_2.clone()];

		let leaf_1 = Leaf::create_leaf(
			&leaf_private_1,
			&leaf_public_input,
			&public_key_1,
			&hasher_params_w5,
		)
		.unwrap();
		let commitment_1 = leaf_1.clone();
		let leaf_2 = Leaf::create_leaf(
			&leaf_private_2,
			&leaf_public_input,
			&public_key_2,
			&hasher_params_w5,
		)
		.unwrap();

		let inner_params = Rc::new(params3.clone());
		let leaves = [leaf_1, leaf_2];
		let tree = Tree_x5::new_sequential(inner_params, Rc::new(()), &leaves).unwrap();

		let path_1 = tree.generate_membership_proof(0);
		let path_2 = tree.generate_membership_proof(1);
		let paths = vec![path_1.clone(), path_2.clone()];

		let public_amount = BnFr::one();

		let ext_data_hash_1 = setup_vanchor_arbitrary_data(commitment_1);
		let ext_data_hash = ext_data_hash_1; // We used it as a sample value for ext_data_hash in the tests
		let root = tree.root().inner();

		let mut root_set = [BnFr::rand(rng); TEST_M];
		root_set[0] = root;
		assert_eq!(root_set.len(), TEST_M);
		let index_0: BnFr = path_1.get_index(&tree.root(), &leaf_1).unwrap();
		let index_1: BnFr = path_1.get_index(&tree.root(), &leaf_2).unwrap();
		assert_eq!(index_0, BnFr::zero());
		assert_eq!(index_1, BnFr::one());
		let indices = vec![index_0, index_1];

		let signature = keypair_1
			.signature(&leaf_1, &index_0, &hasher_params_w4)
			.unwrap();
		let nullifier_hash_1 =
			Leaf::create_nullifier(&signature, &leaf_1, &hasher_params_w4, &index_0).unwrap();
		let nullifier_hash = vec![nullifier_hash_1, nullifier_hash_1];

		let set_private_inputs_1 = setup_set(&root, &root_set);
		let set_private_inputs = vec![set_private_inputs_1.clone(), set_private_inputs_1.clone()];

		let out_chain_id_1 = BnFr::one();
		let out_amount_1 = public_amount + leaf_private_1.amount;
		let out_pubkey_1 = BnFr::rand(rng);
		let out_blinding_1 = BnFr::rand(rng);

		let out_chain_id_2 = BnFr::one();
		let out_amount_2 = leaf_private_2.amount;
		let out_pubkey_2 = BnFr::rand(rng);
		let out_blinding_2 = BnFr::rand(rng);

		let out_leaf_private_1 = LeafPrivateInputs::<BnFr>::new(out_amount_1, out_blinding_1);
		let out_leaf_private_2 = LeafPrivateInputs::<BnFr>::new(out_amount_2, out_blinding_2);
		let out_leaf_private = vec![out_leaf_private_1.clone(), out_leaf_private_2.clone()];

		let out_leaf_public_1 = LeafPublicInputs::<BnFr>::new(out_chain_id_1);
		let out_leaf_public_2 = LeafPublicInputs::<BnFr>::new(out_chain_id_2);
		let out_leaf_public = vec![out_leaf_public_1.clone(), out_leaf_public_2.clone()];

		let output_commitment_1 = Leaf::create_leaf(
			&out_leaf_private_1,
			&out_leaf_public_1,
			&out_pubkey_1,
			&hasher_params_w5,
		)
		.unwrap();

		let output_commitment_2 = Leaf::create_leaf(
			&out_leaf_private_2,
			&out_leaf_public_2,
			&out_pubkey_2,
			&hasher_params_w5,
		)
		.unwrap();

		let out_pubkey = vec![out_pubkey_1, out_pubkey_2];
		let output_commitment = vec![output_commitment_1, output_commitment_2];
		let circuit = VACircuit::new(
			public_amount.clone(),
			ext_data_hash.clone(),
			leaf_private_inputs,
			keypair_inputs,
			leaf_public_input,
			set_private_inputs,
			root_set.clone(),
			hasher_params_w2,
			hasher_params_w4,
			hasher_params_w5,
			paths,
			indices,
			nullifier_hash.clone(),
			output_commitment.clone(),
			out_leaf_private,
			out_leaf_public,
			out_pubkey,
		);

		let mut public_inputs = Vec::new();
		public_inputs.push(public_amount);
		public_inputs.push(ext_data_hash.ext_data);
		public_inputs.extend(nullifier_hash);
		public_inputs.extend(output_commitment);
		public_inputs.push(chain_id);
		public_inputs.extend(root_set);

		let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), rng).unwrap();
		let proof = Groth16::<Bn254>::prove(&pk, circuit.clone(), rng).unwrap();
		let res = Groth16::<Bn254>::verify(&vk, &public_inputs, &proof).unwrap();

		assert!(res);
	}

	#[should_panic]
	#[test]
	fn should_fail_with_inconsistent_input_output_values() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;
		let hasher_params_w5: PoseidonParameters<BnFr> = setup_params_x5_5(curve);
		let hasher_params_w4: PoseidonParameters<BnFr> = setup_params_x5_4(curve);
		let params3: PoseidonParameters<BnFr> = setup_params_x5_3(curve);
		let hasher_params_w2: PoseidonParameters<BnFr> = setup_params_x5_2(curve);
		let chain_id = BnFr::zero();

		let in_amount_1 = BnFr::one();
		let blinding_1 = BnFr::rand(rng);
		let in_amount_2 = BnFr::one() + BnFr::one();
		let blinding_2 = BnFr::rand(rng);
		let leaf_private_1 = LeafPrivateInputs::<BnFr>::new(in_amount_1, blinding_1);
		let leaf_private_2 = LeafPrivateInputs::<BnFr>::new(in_amount_2, blinding_2);
		let leaf_private_inputs = vec![leaf_private_1.clone(), leaf_private_2.clone()];

		let leaf_public_input = LeafPublicInputs::<BnFr>::new(chain_id.clone());

		let private_key_1 = BnFr::rand(rng);
		let keypair_1 = KeyPair::new(private_key_1.clone());
		let privkey = to_bytes![private_key_1].unwrap();
		let public_key_1 = PoseidonCRH::evaluate(&hasher_params_w2, &privkey).unwrap();
		let private_key_2 = BnFr::rand(rng);
		let keypair_2 = KeyPair::new(private_key_2.clone());
		let privkey = to_bytes![private_key_2].unwrap();
		let public_key_2 = PoseidonCRH::evaluate(&hasher_params_w2, &privkey).unwrap();
		let keypair_inputs = vec![keypair_1.clone(), keypair_2.clone()];

		let leaf_1 = Leaf::create_leaf(
			&leaf_private_1,
			&leaf_public_input,
			&public_key_1,
			&hasher_params_w5,
		)
		.unwrap();
		let commitment_1 = leaf_1.clone();
		let leaf_2 = Leaf::create_leaf(
			&leaf_private_2,
			&leaf_public_input,
			&public_key_2,
			&hasher_params_w5,
		)
		.unwrap();

		let inner_params = Rc::new(params3.clone());
		let leaves = [leaf_1, leaf_2];
		let tree = Tree_x5::new_sequential(inner_params, Rc::new(()), &leaves).unwrap();

		let path_1 = tree.generate_membership_proof(0);
		let path_2 = tree.generate_membership_proof(1);
		let paths = vec![path_1.clone(), path_2.clone()];

		let public_amount = BnFr::one();

		let ext_data_hash_1 = setup_vanchor_arbitrary_data(commitment_1);
		let ext_data_hash = ext_data_hash_1; // We used it as a sample value for ext_data_hash in the tests
		let root = tree.root().inner();

		let mut root_set = [BnFr::rand(rng); TEST_M];
		root_set[0] = root;
		assert_eq!(root_set.len(), TEST_M);
		let index_0: BnFr = path_1.get_index(&tree.root(), &leaf_1).unwrap();
		let index_1: BnFr = path_1.get_index(&tree.root(), &leaf_2).unwrap();
		assert_eq!(index_0, BnFr::zero());
		assert_eq!(index_1, BnFr::one());
		let indices = vec![index_0, index_1];

		let signature = keypair_1
			.signature(&leaf_1, &index_0, &hasher_params_w4)
			.unwrap();
		let nullifier_hash_1 =
			Leaf::create_nullifier(&signature, &leaf_1, &hasher_params_w4, &index_0).unwrap();
		let signature = keypair_2
			.signature(&leaf_2, &index_1, &hasher_params_w4)
			.unwrap();
		let nullifier_hash_2 =
			Leaf::create_nullifier(&signature, &leaf_2, &hasher_params_w4, &index_1).unwrap();
		let nullifier_hash = vec![nullifier_hash_1, nullifier_hash_2];
		assert_ne!(nullifier_hash_1, nullifier_hash_2);

		let set_private_inputs_1 = setup_set(&root, &root_set);
		let set_private_inputs = vec![set_private_inputs_1.clone(), set_private_inputs_1.clone()];

		let out_chain_id_1 = BnFr::one();
		let out_amount_1 = public_amount + leaf_private_1.amount
		// Here is the cause of invalidation
			+ public_amount;
		let out_pubkey_1 = BnFr::rand(rng);
		let out_blinding_1 = BnFr::rand(rng);

		let out_chain_id_2 = BnFr::one();
		let out_amount_2 = leaf_private_2.amount;
		let out_pubkey_2 = BnFr::rand(rng);
		let out_blinding_2 = BnFr::rand(rng);

		let out_leaf_private_1 = LeafPrivateInputs::<BnFr>::new(out_amount_1, out_blinding_1);
		let out_leaf_private_2 = LeafPrivateInputs::<BnFr>::new(out_amount_2, out_blinding_2);
		let out_leaf_private = vec![out_leaf_private_1.clone(), out_leaf_private_2.clone()];

		let out_leaf_public_1 = LeafPublicInputs::<BnFr>::new(out_chain_id_1);
		let out_leaf_public_2 = LeafPublicInputs::<BnFr>::new(out_chain_id_2);
		let out_leaf_public = vec![out_leaf_public_1.clone(), out_leaf_public_2.clone()];

		let output_commitment_1 = Leaf::create_leaf(
			&out_leaf_private_1,
			&out_leaf_public_1,
			&out_pubkey_1,
			&hasher_params_w5,
		)
		.unwrap();

		let output_commitment_2 = Leaf::create_leaf(
			&out_leaf_private_2,
			&out_leaf_public_2,
			&out_pubkey_2,
			&hasher_params_w5,
		)
		.unwrap();

		let out_pubkey = vec![out_pubkey_1, out_pubkey_2];
		let output_commitment = vec![output_commitment_1, output_commitment_2];
		let circuit = VACircuit::new(
			public_amount.clone(),
			ext_data_hash.clone(),
			leaf_private_inputs,
			keypair_inputs,
			leaf_public_input,
			set_private_inputs,
			root_set.clone(),
			hasher_params_w2,
			hasher_params_w4,
			hasher_params_w5,
			paths,
			indices,
			nullifier_hash.clone(),
			output_commitment.clone(),
			out_leaf_private,
			out_leaf_public,
			out_pubkey,
		);

		let mut public_inputs = Vec::new();
		public_inputs.push(public_amount);
		public_inputs.push(ext_data_hash.ext_data);
		public_inputs.extend(nullifier_hash);
		public_inputs.extend(output_commitment);
		public_inputs.push(chain_id);
		public_inputs.extend(root_set);

		let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), rng).unwrap();
		let proof = Groth16::<Bn254>::prove(&pk, circuit.clone(), rng).unwrap();
		let res = Groth16::<Bn254>::verify(&vk, &public_inputs, &proof).unwrap();

		assert!(res);
	}

	#[should_panic]
	#[test]
	fn should_fail_with_big_amount() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;
		let hasher_params_w5: PoseidonParameters<BnFr> = setup_params_x5_5(curve);
		let hasher_params_w4: PoseidonParameters<BnFr> = setup_params_x5_4(curve);
		let params3: PoseidonParameters<BnFr> = setup_params_x5_3(curve);
		let hasher_params_w2: PoseidonParameters<BnFr> = setup_params_x5_2(curve);
		let chain_id = BnFr::zero();

		let limit: BnFr = BnFr::from_str(
			"452312848583266388373324160190187140051835877600158453279131187530910662656",
		)
		.unwrap_or_default();
		// check the previous conversion is done correctly
		assert_ne!(limit, BnFr::default());

		let in_amount_1 = BnFr::one() + limit;
		let blinding_1 = BnFr::rand(rng);
		let in_amount_2 = BnFr::one() + BnFr::one();
		let blinding_2 = BnFr::rand(rng);
		let leaf_private_1 = LeafPrivateInputs::<BnFr>::new(in_amount_1, blinding_1);
		let leaf_private_2 = LeafPrivateInputs::<BnFr>::new(in_amount_2, blinding_2);
		let leaf_private_inputs = vec![leaf_private_1.clone(), leaf_private_2.clone()];

		let leaf_public_input = LeafPublicInputs::<BnFr>::new(chain_id.clone());

		let private_key_1 = BnFr::rand(rng);
		let keypair_1 = KeyPair::new(private_key_1.clone());
		let privkey = to_bytes![private_key_1].unwrap();
		let public_key_1 = PoseidonCRH::evaluate(&hasher_params_w2, &privkey).unwrap();
		let private_key_2 = BnFr::rand(rng);
		let keypair_2 = KeyPair::new(private_key_2.clone());
		let privkey = to_bytes![private_key_2].unwrap();
		let public_key_2 = PoseidonCRH::evaluate(&hasher_params_w2, &privkey).unwrap();
		let keypair_inputs = vec![keypair_1.clone(), keypair_2.clone()];

		let leaf_1 = Leaf::create_leaf(
			&leaf_private_1,
			&leaf_public_input,
			&public_key_1,
			&hasher_params_w5,
		)
		.unwrap();
		let commitment_1 = leaf_1.clone();
		let leaf_2 = Leaf::create_leaf(
			&leaf_private_2,
			&leaf_public_input,
			&public_key_2,
			&hasher_params_w5,
		)
		.unwrap();

		let inner_params = Rc::new(params3.clone());
		let leaves = [leaf_1, leaf_2];
		let tree = Tree_x5::new_sequential(inner_params, Rc::new(()), &leaves).unwrap();

		let path_1 = tree.generate_membership_proof(0);
		let path_2 = tree.generate_membership_proof(1);
		let paths = vec![path_1.clone(), path_2.clone()];

		let public_amount = BnFr::one();

		let ext_data_hash_1 = setup_vanchor_arbitrary_data(commitment_1);
		let ext_data_hash = ext_data_hash_1; // We used it as a sample value for ext_data_hash in the tests
		let root = tree.root().inner();

		let mut root_set = [BnFr::rand(rng); TEST_M];
		root_set[0] = root;
		assert_eq!(root_set.len(), TEST_M);
		let index_0: BnFr = path_1.get_index(&tree.root(), &leaf_1).unwrap();
		let index_1: BnFr = path_1.get_index(&tree.root(), &leaf_2).unwrap();
		assert_eq!(index_0, BnFr::zero());
		assert_eq!(index_1, BnFr::one());
		let indices = vec![index_0, index_1];

		let signature = keypair_1
			.signature(&leaf_1, &index_0, &hasher_params_w4)
			.unwrap();
		let nullifier_hash_1 =
			Leaf::create_nullifier(&signature, &leaf_1, &hasher_params_w4, &index_0).unwrap();
		let signature = keypair_2
			.signature(&leaf_2, &index_1, &hasher_params_w4)
			.unwrap();
		let nullifier_hash_2 =
			Leaf::create_nullifier(&signature, &leaf_2, &hasher_params_w4, &index_1).unwrap();
		let nullifier_hash = vec![nullifier_hash_1, nullifier_hash_2];
		assert_ne!(nullifier_hash_1, nullifier_hash_2);

		let set_private_inputs_1 = setup_set(&root, &root_set);
		let set_private_inputs = vec![set_private_inputs_1.clone(), set_private_inputs_1.clone()];

		let out_chain_id_1 = BnFr::one();
		let out_amount_1 = public_amount + &leaf_private_1.amount;
		let out_pubkey_1 = BnFr::rand(rng);
		let out_blinding_1 = BnFr::rand(rng);

		let out_chain_id_2 = BnFr::one();
		let out_amount_2 = leaf_private_2.amount;
		let out_pubkey_2 = BnFr::rand(rng);
		let out_blinding_2 = BnFr::rand(rng);

		let out_leaf_private_1 = LeafPrivateInputs::<BnFr>::new(out_amount_1, out_blinding_1);
		let out_leaf_private_2 = LeafPrivateInputs::<BnFr>::new(out_amount_2, out_blinding_2);
		let out_leaf_private = vec![out_leaf_private_1.clone(), out_leaf_private_2.clone()];

		let out_leaf_public_1 = LeafPublicInputs::<BnFr>::new(out_chain_id_1);
		let out_leaf_public_2 = LeafPublicInputs::<BnFr>::new(out_chain_id_2);
		let out_leaf_public = vec![out_leaf_public_1.clone(), out_leaf_public_2.clone()];

		let output_commitment_1 = Leaf::create_leaf(
			&out_leaf_private_1,
			&out_leaf_public_1,
			&out_pubkey_1,
			&hasher_params_w5,
		)
		.unwrap();

		let output_commitment_2 = Leaf::create_leaf(
			&out_leaf_private_2,
			&out_leaf_public_2,
			&out_pubkey_2,
			&hasher_params_w5,
		)
		.unwrap();

		let out_pubkey = vec![out_pubkey_1, out_pubkey_2];
		let output_commitment = vec![output_commitment_1, output_commitment_2];
		let circuit = VACircuit::new(
			public_amount.clone(),
			ext_data_hash.clone(),
			leaf_private_inputs,
			keypair_inputs,
			leaf_public_input,
			set_private_inputs,
			root_set.clone(),
			hasher_params_w2,
			hasher_params_w4,
			hasher_params_w5,
			paths,
			indices,
			nullifier_hash.clone(),
			output_commitment.clone(),
			out_leaf_private,
			out_leaf_public,
			out_pubkey,
		);

		let mut public_inputs = Vec::new();
		public_inputs.push(public_amount);
		public_inputs.push(ext_data_hash.ext_data);
		public_inputs.extend(nullifier_hash);
		public_inputs.extend(output_commitment);
		public_inputs.push(chain_id);
		public_inputs.extend(root_set);

		let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), rng).unwrap();
		let proof = Groth16::<Bn254>::prove(&pk, circuit.clone(), rng).unwrap();
		let res = Groth16::<Bn254>::verify(&vk, &public_inputs, &proof).unwrap();

		assert!(res);
	}

	#[should_panic]
	#[test]
	fn should_fail_with_invalid_public_input() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;
		let hasher_params_w5: PoseidonParameters<BnFr> = setup_params_x5_5(curve);
		let hasher_params_w4: PoseidonParameters<BnFr> = setup_params_x5_4(curve);
		let params3: PoseidonParameters<BnFr> = setup_params_x5_3(curve);
		let hasher_params_w2: PoseidonParameters<BnFr> = setup_params_x5_2(curve);
		let chain_id = BnFr::one();

		let in_amount_1 = BnFr::one();
		let blinding_1 = BnFr::rand(rng);
		let in_amount_2 = BnFr::one() + BnFr::one();
		let blinding_2 = BnFr::rand(rng);
		let leaf_private_1 = LeafPrivateInputs::<BnFr>::new(in_amount_1, blinding_1);
		let leaf_private_2 = LeafPrivateInputs::<BnFr>::new(in_amount_2, blinding_2);
		let leaf_private_inputs = vec![leaf_private_1.clone(), leaf_private_2.clone()];

		let leaf_public_input = LeafPublicInputs::<BnFr>::new(chain_id.clone());

		let private_key_1 = BnFr::rand(rng);
		let keypair_1 = KeyPair::new(private_key_1.clone());
		let privkey = to_bytes![private_key_1].unwrap();
		let public_key_1 = PoseidonCRH::evaluate(&hasher_params_w2, &privkey).unwrap();
		let private_key_2 = BnFr::rand(rng);
		let keypair_2 = KeyPair::new(private_key_2.clone());
		let privkey = to_bytes![private_key_2].unwrap();
		let public_key_2 = PoseidonCRH::evaluate(&hasher_params_w2, &privkey).unwrap();
		let keypair_inputs = vec![keypair_1.clone(), keypair_2.clone()];

		let leaf_1 = Leaf::create_leaf(
			&leaf_private_1,
			&leaf_public_input,
			&public_key_1,
			&hasher_params_w5,
		)
		.unwrap();
		let commitment_1 = leaf_1.clone();
		let leaf_2 = Leaf::create_leaf(
			&leaf_private_2,
			&leaf_public_input,
			&public_key_2,
			&hasher_params_w5,
		)
		.unwrap();

		let inner_params = Rc::new(params3.clone());
		let leaves = [leaf_1, leaf_2];
		let tree = Tree_x5::new_sequential(inner_params, Rc::new(()), &leaves).unwrap();

		let path_1 = tree.generate_membership_proof(0);
		let path_2 = tree.generate_membership_proof(1);
		let paths = vec![path_1.clone(), path_2.clone()];

		let public_amount = BnFr::one();

		let ext_data_hash_1 = setup_vanchor_arbitrary_data(commitment_1);
		let ext_data_hash = ext_data_hash_1; // We used it as a sample value for ext_data_hash in the tests
		let root = tree.root().inner();

		let mut root_set = [BnFr::rand(rng); TEST_M];
		root_set[0] = root;
		assert_eq!(root_set.len(), TEST_M);
		let index_0: BnFr = path_1.get_index(&tree.root(), &leaf_1).unwrap();
		let index_1: BnFr = path_1.get_index(&tree.root(), &leaf_2).unwrap();
		assert_eq!(index_0, BnFr::zero());
		assert_eq!(index_1, BnFr::one());
		let indices = vec![index_0, index_1];

		let signature = keypair_1
			.signature(&leaf_1, &index_0, &hasher_params_w4)
			.unwrap();
		let nullifier_hash_1 =
			Leaf::create_nullifier(&signature, &leaf_1, &hasher_params_w4, &index_0).unwrap();
		let signature = keypair_2
			.signature(&leaf_2, &index_1, &hasher_params_w4)
			.unwrap();
		let nullifier_hash_2 =
			Leaf::create_nullifier(&signature, &leaf_2, &hasher_params_w4, &index_1).unwrap();
		let nullifier_hash = vec![nullifier_hash_1, nullifier_hash_2];
		assert_ne!(nullifier_hash_1, nullifier_hash_2);

		let set_private_inputs_1 = setup_set(&root, &root_set);
		let set_private_inputs = vec![set_private_inputs_1.clone(), set_private_inputs_1.clone()];

		let out_chain_id_1 = BnFr::one();
		let out_amount_1 = public_amount + leaf_private_1.amount;
		let out_pubkey_1 = BnFr::rand(rng);
		let out_blinding_1 = BnFr::rand(rng);

		let out_chain_id_2 = BnFr::one();
		let out_amount_2 = leaf_private_2.amount;
		let out_pubkey_2 = BnFr::rand(rng);
		let out_blinding_2 = BnFr::rand(rng);

		let out_leaf_private_1 = LeafPrivateInputs::<BnFr>::new(out_amount_1, out_blinding_1);
		let out_leaf_private_2 = LeafPrivateInputs::<BnFr>::new(out_amount_2, out_blinding_2);
		let out_leaf_private = vec![out_leaf_private_1.clone(), out_leaf_private_2.clone()];

		let out_leaf_public_1 = LeafPublicInputs::<BnFr>::new(out_chain_id_1);
		let out_leaf_public_2 = LeafPublicInputs::<BnFr>::new(out_chain_id_2);
		let out_leaf_public = vec![out_leaf_public_1.clone(), out_leaf_public_2.clone()];

		let output_commitment_1 = Leaf::create_leaf(
			&out_leaf_private_1,
			&out_leaf_public_1,
			&out_pubkey_1,
			&hasher_params_w5,
		)
		.unwrap();

		let output_commitment_2 = Leaf::create_leaf(
			&out_leaf_private_2,
			&out_leaf_public_2,
			&out_pubkey_2,
			&hasher_params_w5,
		)
		.unwrap();

		let out_pubkey = vec![out_pubkey_1, out_pubkey_2];
		let output_commitment = vec![output_commitment_1, output_commitment_2];
		let circuit = VACircuit::new(
			public_amount.clone(),
			ext_data_hash.clone(),
			leaf_private_inputs,
			keypair_inputs,
			leaf_public_input,
			set_private_inputs,
			root_set.clone(),
			hasher_params_w2,
			hasher_params_w4,
			hasher_params_w5,
			paths,
			indices,
			nullifier_hash.clone(),
			output_commitment.clone(),
			out_leaf_private,
			out_leaf_public,
			out_pubkey,
		);

		let mut public_inputs = Vec::new();
		public_inputs.push(public_amount);
		public_inputs.push(ext_data_hash.ext_data);
		public_inputs.extend(nullifier_hash);
		public_inputs.extend(output_commitment);
		public_inputs.push(chain_id);
		public_inputs.extend(root_set);

		let truncated_public_inputs = public_inputs[2..].to_vec();
		let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), rng).unwrap();
		let proof = Groth16::<Bn254>::prove(&pk, circuit.clone(), rng).unwrap();
		let res = Groth16::<Bn254>::verify(&vk, &truncated_public_inputs, &proof).unwrap();

		assert!(res);
	}
}
