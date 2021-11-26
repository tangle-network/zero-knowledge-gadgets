use crate::{
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
	Vec,
};
use ark_crypto_primitives::{crh::CRHGadget, CRH};
use ark_ff::fields::PrimeField;
use ark_r1cs_std::{eq::EqGadget, fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::{cmp::Ordering::Less, marker::PhantomData};

pub struct VAnchorCircuit<
	F: PrimeField,
	// Hasher for the leaf creation,  Nullifier, Public key generation
	H2: CRH,
	HG2: CRHGadget<H2, F>,
	H4: CRH,
	HG4: CRHGadget<H4, F>,
	H5: CRH,
	HG5: CRHGadget<H5, F>,
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
	keypair_inputs: Vec<Keypair<F, H2>>,
	leaf_public_input: LeafPublicInputs<F>,          // chain_id
	set_private_inputs: Vec<SetPrivateInputs<F, M>>, // diffs
	root_set: [F; M],
	hasher_params_w2: H2::Parameters,
	hasher_params_w4: H4::Parameters,
	hasher_params_w5: H5::Parameters,
	paths: Vec<Path<C, K>>,
	indices: Vec<F>,
	nullifier_hash: Vec<H4::Output>,

	output_commitment: Vec<H5::Output>,
	out_leaf_private: Vec<LeafPrivateInputs<F>>,
	out_leaf_public: Vec<LeafPublicInputs<F>>,
	out_pubkey: Vec<F>,

	_hasher2: PhantomData<H2>,
	_hasher2_gadget: PhantomData<HG2>,
	_hasher4: PhantomData<H4>,
	_hasher4_gadget: PhantomData<HG4>,
	_hasher5: PhantomData<H5>,
	_hasher5_gadget: PhantomData<HG5>,
	_leaf_hasher_gadget: PhantomData<LHGT>,
	_tree_hasher_gadget: PhantomData<HGT>,
	_merkle_config: PhantomData<C>,
}

impl<
		F,
		H2,
		HG2,
		H4,
		HG4,
		H5,
		HG5,
		C,
		LHGT,
		HGT,
		const K: usize,
		const N_INS: usize,
		const N_OUTS: usize,
		const M: usize,
	> VAnchorCircuit<F, H2, HG2, H4, HG4, H5, HG5, C, LHGT, HGT, K, N_INS, N_OUTS, M>
where
	F: PrimeField,
	H2: CRH,
	HG2: CRHGadget<H2, F>,
	H4: CRH,
	HG4: CRHGadget<H4, F>,
	H5: CRH,
	HG5: CRHGadget<H5, F>,
	C: MerkleConfig,
	LHGT: CRHGadget<C::LeafH, F>,
	HGT: CRHGadget<C::H, F>,
{
	pub fn new(
		public_amount: F,
		ext_data_hash: ArbitraryInput<F>,
		leaf_private_inputs: Vec<LeafPrivateInputs<F>>,
		keypair_inputs: Vec<Keypair<F, H2>>,
		leaf_public_input: LeafPublicInputs<F>,
		set_private_inputs: Vec<SetPrivateInputs<F, M>>,
		root_set: [F; M],
		hasher_params_w2: H2::Parameters,
		hasher_params_w4: H4::Parameters,
		hasher_params_w5: H5::Parameters,
		paths: Vec<Path<C, K>>,
		indices: Vec<F>,
		nullifier_hash: Vec<H4::Output>,
		output_commitment: Vec<H5::Output>,
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
			_hasher2: PhantomData,
			_hasher2_gadget: PhantomData,
			_hasher4: PhantomData,
			_hasher4_gadget: PhantomData,
			_hasher5: PhantomData,
			_hasher5_gadget: PhantomData,
			_leaf_hasher_gadget: PhantomData,
			_tree_hasher_gadget: PhantomData,
			_merkle_config: PhantomData,
		}
	}

	pub fn verify_input_var(
		hasher_params_w2_var: &HG2::ParametersVar,
		hasher_params_w4_var: &HG4::ParametersVar,
		hasher_params_w5_var: &HG5::ParametersVar,
		leaf_private_var: &Vec<LeafPrivateInputsVar<F>>,
		inkeypair_var: &Vec<KeypairVar<F, H2, HG2>>,
		leaf_public_input_var: &LeafPublicInputsVar<F>,
		in_path_indices_var: &Vec<FpVar<F>>,
		in_path_elements_var: &Vec<PathVar<F, C, HGT, LHGT, K>>,
		in_nullifier_var: &Vec<HG4::OutputVar>,
		root_set_var: &Vec<FpVar<F>>,
		set_input_private_var: &Vec<SetPrivateInputsVar<F, M>>,
	) -> Result<FpVar<F>, SynthesisError> {
		let mut sums_ins_var = FpVar::<F>::zero();

		for tx in 0..N_INS {
			// Computing the public key
			let pub_key = inkeypair_var[tx].public_key(hasher_params_w2_var)?;
			// Computing the hash
			let in_utxo_hasher_var = VAnchorLeafGadget::<F, H4, HG4, H5, HG5>::create_leaf(
				&leaf_private_var[tx],
				&leaf_public_input_var,
				&pub_key,
				&hasher_params_w5_var,
			)?;
			// End of computing the hash

			let signature = inkeypair_var[tx].signature::<FpVar<F>, H4, HG4, H5, HG5>(
				&in_utxo_hasher_var,
				&in_path_indices_var[tx],
				&hasher_params_w4_var,
			)?;
			// Nullifier
			let nullifier_hash = VAnchorLeafGadget::<F, H4, HG4, H5, HG5>::create_nullifier(
				&signature,
				&in_utxo_hasher_var,
				&hasher_params_w4_var,
				&in_path_indices_var[tx],
			)?;

			nullifier_hash.enforce_equal(&in_nullifier_var[tx])?;

			// Add the roots and diffs signals to the vanchor circuit
			let roothash = &in_path_elements_var[tx].root_hash(&in_utxo_hasher_var)?;
			let in_amount_tx = &leaf_private_var[tx].amount;
			let check = SetMembershipGadget::check_is_enabled(
				&roothash,
				&root_set_var,
				&set_input_private_var[tx],
				&in_amount_tx,
			)?;
			check.enforce_equal(&Boolean::TRUE)?;

			sums_ins_var += in_amount_tx;
		}
		Ok(sums_ins_var)
	}

	// Verify correctness of transaction outputs
	pub fn verify_output_var(
		hasher_params_w5_var: &HG5::ParametersVar,
		output_commitment_var: &Vec<HG5::OutputVar>,
		leaf_private_var: &Vec<LeafPrivateInputsVar<F>>,
		leaf_public_var: &Vec<LeafPublicInputsVar<F>>,
		out_pubkey_var: &Vec<FpVar<F>>,
		limit_var: &FpVar<F>,
	) -> Result<FpVar<F>, SynthesisError> {
		let mut sums_outs_var = FpVar::<F>::zero();

		for tx in 0..N_OUTS {
			// Computing the hash
			let out_utxo_hasher_var = VAnchorLeafGadget::<F, H4, HG4, H5, HG5>::create_leaf(
				&leaf_private_var[tx],
				&leaf_public_var[tx],
				&out_pubkey_var[tx],
				&hasher_params_w5_var,
			)?;
			// End of computing the hash
			let out_amount_var = &leaf_private_var[tx].amount;
			out_utxo_hasher_var.enforce_equal(&output_commitment_var[tx])?;

			// Check that amount is less than 2^248 in the field (to prevent overflow)
			out_amount_var.enforce_cmp_unchecked(&limit_var, Less, false)?;

			sums_outs_var = sums_outs_var + out_amount_var;
		}
		Ok(sums_outs_var)
	}

	//Check that there are no same nullifiers among all inputs
	pub fn verify_no_same_nul(
		in_nullifier_var: &Vec<HG4::OutputVar>,
	) -> Result<(), SynthesisError> {
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
		res.enforce_equal(&sum_outs_var)?;
		Ok(())
	}
}

impl<
		F,
		H2,
		HG2,
		H4,
		HG4,
		H5,
		HG5,
		C,
		LHGT,
		HGT,
		const K: usize,
		const N_INS: usize,
		const N_OUTS: usize,
		const M: usize,
	> Clone for VAnchorCircuit<F, H2, HG2, H4, HG4, H5, HG5, C, LHGT, HGT, K, N_INS, N_OUTS, M>
where
	F: PrimeField,
	H2: CRH,
	HG2: CRHGadget<H2, F>,
	H4: CRH,
	HG4: CRHGadget<H4, F>,
	H5: CRH,
	HG5: CRHGadget<H5, F>,
	C: MerkleConfig,
	LHGT: CRHGadget<C::LeafH, F>,
	HGT: CRHGadget<C::H, F>,
{
	fn clone(&self) -> Self {
		let public_amount = self.public_amount.clone();
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
		H2,
		HG2,
		H4,
		HG4,
		H5,
		HG5,
		C,
		LHGT,
		HGT,
		const K: usize,
		const N_INS: usize,
		const N_OUTS: usize,
		const M: usize,
	> ConstraintSynthesizer<F>
	for VAnchorCircuit<F, H2, HG2, H4, HG4, H5, HG5, C, LHGT, HGT, K, N_INS, N_OUTS, M>
where
	F: PrimeField,
	H2: CRH,
	HG2: CRHGadget<H2, F>,
	H4: CRH,
	HG4: CRHGadget<H4, F>,
	H5: CRH,
	HG5: CRHGadget<H5, F>,
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
		let leaf_public_input_var =
			LeafPublicInputsVar::new_input(cs.clone(), || Ok(leaf_public_input))?;
		let public_amount_var = FpVar::<F>::new_input(cs.clone(), || Ok(public_amount))?;
		let root_set_var = Vec::<FpVar<F>>::new_input(cs.clone(), || Ok(root_set))?;
		let in_nullifier_var = Vec::<HG4::OutputVar>::new_input(cs.clone(), || Ok(nullifier_hash))?;
		let output_commitment_var =
			Vec::<HG5::OutputVar>::new_input(cs.clone(), || Ok(output_commitment))?;

		let arbitrary_input_var = ArbitraryInputVar::new_input(cs.clone(), || Ok(ext_data_hash))?;

		// Constants
		let limit_var: FpVar<F> = FpVar::<F>::new_constant(cs.clone(), limit)?;
		let hasher_params_w2_var = HG2::ParametersVar::new_constant(cs.clone(), hasher_params_w2)?;
		let hasher_params_w4_var = HG4::ParametersVar::new_constant(cs.clone(), hasher_params_w4)?;
		let hasher_params_w5_var = HG5::ParametersVar::new_constant(cs.clone(), hasher_params_w5)?;

		// Private inputs
		let leaf_private_var =
			Vec::<LeafPrivateInputsVar<F>>::new_witness(cs.clone(), || Ok(leaf_private))?;
		let inkeypair_var =
			Vec::<KeypairVar<F, H2, HG2>>::new_witness(cs.clone(), || Ok(keypair_inputs))?;
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
		let out_pubkey_var = Vec::<FpVar<F>>::new_witness(cs.clone(), || Ok(out_pubkey))?;

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

#[cfg(feature = "default_poseidon")]
#[cfg(test)]
mod test {
	use super::*;
	use crate::{
		ark_std::{One, Zero},
		keypair::vanchor::Keypair,
		leaf::vanchor::VAnchorLeaf,
		merkle_tree::{Config as MerkleConfig, SparseMerkleTree},
		poseidon::{constraints::CRHGadget as PCRHGadget, PoseidonParameters, CRH as PCRH},
		setup::{bridge::*, common::*, vanchor::setup_vanchor_arbitrary_data},
	};
	use ark_bn254::{Bn254, Fr as BnFr};
	use ark_ff::{to_bytes, UniformRand};
	use ark_groth16::Groth16;

	use ark_snark::SNARK;
	use ark_std::test_rng;
	use std::{rc::Rc, str::FromStr};

	pub const TEST_K: usize = 30;
	pub const TEST_N_INS_2: usize = 2;
	pub const TEST_N_OUTS_2: usize = 2;
	pub const TEST_M: usize = 2;

	type PoseidonCRH2 = PCRH<BnFr>;
	type PoseidonCRH4 = PCRH<BnFr>;
	type PoseidonCRH5 = PCRH<BnFr>;

	type PoseidonCRH2Gadget = PCRHGadget<BnFr>;
	type PoseidonCRH4Gadget = PCRHGadget<BnFr>;
	type PoseidonCRH5Gadget = PCRHGadget<BnFr>;

	type KeyPair = Keypair<BnFr, PoseidonCRH2>;
	type Leaf = VAnchorLeaf<BnFr, PoseidonCRH4, PoseidonCRH5>;
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
		PoseidonCRH2,
		PoseidonCRH2Gadget,
		PoseidonCRH4,
		PoseidonCRH4Gadget,
		PoseidonCRH5,
		PoseidonCRH5Gadget,
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
		let public_key_1 = PoseidonCRH2::evaluate(&hasher_params_w2, &privkey).unwrap();
		let private_key_2 = BnFr::rand(rng);
		let keypair_2 = KeyPair::new(private_key_2.clone());
		let privkey = to_bytes![private_key_2].unwrap();
		let public_key_2 = PoseidonCRH2::evaluate(&hasher_params_w2, &privkey).unwrap();
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
			.signature::<PoseidonCRH4, PoseidonCRH5>(&leaf_1, &index_0, &hasher_params_w4)
			.unwrap();
		let nullifier_hash_1 =
			Leaf::create_nullifier(&signature, &leaf_1, &hasher_params_w4, &index_0).unwrap();
		let signature = keypair_2
			.signature::<PoseidonCRH4, PoseidonCRH5>(&leaf_2, &index_1, &hasher_params_w4)
			.unwrap();
		let nullifier_hash_2 =
			Leaf::create_nullifier(&signature, &leaf_2, &hasher_params_w4, &index_1).unwrap();
		let nullifier_hash = vec![nullifier_hash_1, nullifier_hash_2];

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
		public_inputs.push(chain_id);
		public_inputs.push(public_amount);
		public_inputs.extend(root_set);
		public_inputs.extend(nullifier_hash);
		public_inputs.extend(output_commitment);
		public_inputs.push(ext_data_hash.ext_data);

		let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), rng).unwrap();
		let proof = Groth16::<Bn254>::prove(&pk, circuit.clone(), rng).unwrap();
		let res = Groth16::<Bn254>::verify(&vk, &public_inputs, &proof).unwrap();

		assert!(res);
	}

	#[should_panic]
	#[test]
	fn should_fail_with_invalid_root() {
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
		let public_key_1 = PoseidonCRH2::evaluate(&hasher_params_w2, &privkey).unwrap();
		let private_key_2 = BnFr::rand(rng);
		let keypair_2 = KeyPair::new(private_key_2.clone());
		let privkey = to_bytes![private_key_2].unwrap();
		let public_key_2 = PoseidonCRH2::evaluate(&hasher_params_w2, &privkey).unwrap();
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
		let root = BnFr::rand(rng);

		let root_set = [root; TEST_M];

		let index_0: BnFr = path_1.get_index(&tree.root(), &leaf_1).unwrap();
		let index_1: BnFr = path_1.get_index(&tree.root(), &leaf_2).unwrap();
		assert_eq!(index_0, BnFr::zero());
		assert_eq!(index_1, BnFr::one());
		let indices = vec![index_0, index_1];

		let signature = keypair_1
			.signature::<PoseidonCRH4, PoseidonCRH5>(&leaf_1, &index_0, &hasher_params_w4)
			.unwrap();
		let nullifier_hash_1 =
			Leaf::create_nullifier(&signature, &leaf_1, &hasher_params_w4, &index_0).unwrap();
		let signature = keypair_2
			.signature::<PoseidonCRH4, PoseidonCRH5>(&leaf_2, &index_1, &hasher_params_w4)
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
		public_inputs.push(chain_id);
		public_inputs.push(public_amount);
		public_inputs.extend(root_set);
		public_inputs.extend(nullifier_hash);
		public_inputs.extend(output_commitment);
		public_inputs.push(ext_data_hash.ext_data);

		let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), rng).unwrap();
		let proof = Groth16::<Bn254>::prove(&pk, circuit.clone(), rng).unwrap();
		let res = Groth16::<Bn254>::verify(&vk, &public_inputs, &proof).unwrap();

		assert!(res);
	}

	#[should_panic]
	#[test]
	fn should_fail_with_invalid_set() {
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
		let public_key_1 = PoseidonCRH2::evaluate(&hasher_params_w2, &privkey).unwrap();
		let private_key_2 = BnFr::rand(rng);
		let keypair_2 = KeyPair::new(private_key_2.clone());
		let privkey = to_bytes![private_key_2].unwrap();
		let public_key_2 = PoseidonCRH2::evaluate(&hasher_params_w2, &privkey).unwrap();
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
		let root = BnFr::rand(rng);

		let mut root_set = [BnFr::rand(rng); TEST_M];
		root_set[0] = root;
		assert_eq!(root_set.len(), TEST_M);
		let index_0: BnFr = path_1.get_index(&tree.root(), &leaf_1).unwrap();
		let index_1: BnFr = path_1.get_index(&tree.root(), &leaf_2).unwrap();
		assert_eq!(index_0, BnFr::zero());
		assert_eq!(index_1, BnFr::one());
		let indices = vec![index_0, index_1];

		let signature = keypair_1
			.signature::<PoseidonCRH4, PoseidonCRH5>(&leaf_1, &index_0, &hasher_params_w4)
			.unwrap();
		let nullifier_hash_1 =
			Leaf::create_nullifier(&signature, &leaf_1, &hasher_params_w4, &index_0).unwrap();
		let signature = keypair_2
			.signature::<PoseidonCRH4, PoseidonCRH5>(&leaf_2, &index_1, &hasher_params_w4)
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
		public_inputs.push(chain_id);
		public_inputs.push(public_amount);
		public_inputs.extend(root_set);
		public_inputs.extend(nullifier_hash);
		public_inputs.extend(output_commitment);
		public_inputs.push(ext_data_hash.ext_data);

		let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), rng).unwrap();
		let proof = Groth16::<Bn254>::prove(&pk, circuit.clone(), rng).unwrap();
		let res = Groth16::<Bn254>::verify(&vk, &public_inputs, &proof).unwrap();

		assert!(res);
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
		let public_key_1 = PoseidonCRH2::evaluate(&hasher_params_w2, &privkey).unwrap();
		let private_key_2 = BnFr::rand(rng);
		let keypair_2 = KeyPair::new(private_key_2.clone());
		let privkey = to_bytes![private_key_2].unwrap();
		let public_key_2 = PoseidonCRH2::evaluate(&hasher_params_w2, &privkey).unwrap();
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
			.signature::<PoseidonCRH4, PoseidonCRH5>(&leaf_2, &index_1, &hasher_params_w4)
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
		public_inputs.push(chain_id);
		public_inputs.push(public_amount);
		public_inputs.extend(root_set);
		public_inputs.extend(nullifier_hash);
		public_inputs.extend(output_commitment);
		public_inputs.push(ext_data_hash.ext_data);

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
		let public_key_1 = PoseidonCRH2::evaluate(&hasher_params_w2, &privkey).unwrap();
		let private_key_2 = BnFr::rand(rng);
		let keypair_2 = KeyPair::new(private_key_2.clone());
		let privkey = to_bytes![private_key_2].unwrap();
		let public_key_2 = PoseidonCRH2::evaluate(&hasher_params_w2, &privkey).unwrap();
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
			.signature::<PoseidonCRH4, PoseidonCRH5>(&leaf_1, &index_0, &hasher_params_w4)
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
		public_inputs.push(chain_id);
		public_inputs.push(public_amount);
		public_inputs.extend(root_set);
		public_inputs.extend(nullifier_hash);
		public_inputs.extend(output_commitment);
		public_inputs.push(ext_data_hash.ext_data);

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
		let public_key_1 = PoseidonCRH2::evaluate(&hasher_params_w2, &privkey).unwrap();
		let private_key_2 = BnFr::rand(rng);
		let keypair_2 = KeyPair::new(private_key_2.clone());
		let privkey = to_bytes![private_key_2].unwrap();
		let public_key_2 = PoseidonCRH2::evaluate(&hasher_params_w2, &privkey).unwrap();
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
			.signature::<PoseidonCRH4, PoseidonCRH5>(&leaf_1, &index_0, &hasher_params_w4)
			.unwrap();
		let nullifier_hash_1 =
			Leaf::create_nullifier(&signature, &leaf_1, &hasher_params_w4, &index_0).unwrap();
		let signature = keypair_2
			.signature::<PoseidonCRH4, PoseidonCRH5>(&leaf_2, &index_1, &hasher_params_w4)
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
		public_inputs.push(chain_id);
		public_inputs.push(public_amount);
		public_inputs.extend(root_set);
		public_inputs.extend(nullifier_hash);
		public_inputs.extend(output_commitment);
		public_inputs.push(ext_data_hash.ext_data);

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
		let public_key_1 = PoseidonCRH2::evaluate(&hasher_params_w2, &privkey).unwrap();
		let private_key_2 = BnFr::rand(rng);
		let keypair_2 = KeyPair::new(private_key_2.clone());
		let privkey = to_bytes![private_key_2].unwrap();
		let public_key_2 = PoseidonCRH2::evaluate(&hasher_params_w2, &privkey).unwrap();
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
			.signature::<PoseidonCRH4, PoseidonCRH5>(&leaf_1, &index_0, &hasher_params_w4)
			.unwrap();
		let nullifier_hash_1 =
			Leaf::create_nullifier(&signature, &leaf_1, &hasher_params_w4, &index_0).unwrap();
		let signature = keypair_2
			.signature::<PoseidonCRH4, PoseidonCRH5>(&leaf_2, &index_1, &hasher_params_w4)
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
		public_inputs.push(chain_id);
		public_inputs.push(public_amount);
		public_inputs.extend(root_set);
		public_inputs.extend(nullifier_hash);
		public_inputs.extend(output_commitment);
		public_inputs.push(ext_data_hash.ext_data);

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
		let public_key_1 = PoseidonCRH2::evaluate(&hasher_params_w2, &privkey).unwrap();
		let private_key_2 = BnFr::rand(rng);
		let keypair_2 = KeyPair::new(private_key_2.clone());
		let privkey = to_bytes![private_key_2].unwrap();
		let public_key_2 = PoseidonCRH2::evaluate(&hasher_params_w2, &privkey).unwrap();
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
			.signature::<PoseidonCRH4, PoseidonCRH5>(&leaf_1, &index_0, &hasher_params_w4)
			.unwrap();
		let nullifier_hash_1 =
			Leaf::create_nullifier(&signature, &leaf_1, &hasher_params_w4, &index_0).unwrap();
		let signature = keypair_2
			.signature::<PoseidonCRH4, PoseidonCRH5>(&leaf_2, &index_1, &hasher_params_w4)
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
		public_inputs.push(chain_id);
		public_inputs.push(public_amount);
		public_inputs.extend(root_set);
		public_inputs.extend(nullifier_hash);
		public_inputs.extend(output_commitment);
		public_inputs.push(ext_data_hash.ext_data);

		let truncated_public_inputs = public_inputs[2..].to_vec();
		let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), rng).unwrap();
		let proof = Groth16::<Bn254>::prove(&pk, circuit.clone(), rng).unwrap();
		let res = Groth16::<Bn254>::verify(&vk, &truncated_public_inputs, &proof).unwrap();

		assert!(res);
	}

	pub const TEST_N_INS_1: usize = 1;
	pub const TEST_N_OUTS_1: usize = 1;
	type VACircuit1_1 = VAnchorCircuit<
		BnFr,
		PoseidonCRH2,
		PoseidonCRH2Gadget,
		PoseidonCRH4,
		PoseidonCRH4Gadget,
		PoseidonCRH5,
		PoseidonCRH5Gadget,
		TreeConfig_x5<BnFr>,
		LeafCRHGadget<BnFr>,
		PoseidonCRH_x5_3Gadget<BnFr>,
		TEST_K,
		TEST_N_INS_1,
		TEST_N_OUTS_1,
		TEST_M,
	>;

	#[test]
	fn should_create_circuit_and_prove_groth16_1_input_1_output() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;
		let hasher_params_w5: PoseidonParameters<BnFr> = setup_params_x5_5(curve);
		let hasher_params_w4: PoseidonParameters<BnFr> = setup_params_x5_4(curve);
		let params3: PoseidonParameters<BnFr> = setup_params_x5_3(curve);
		let hasher_params_w2: PoseidonParameters<BnFr> = setup_params_x5_2(curve);
		let chain_id = BnFr::zero();

		let in_amount_1 = BnFr::one();
		let blinding_1 = BnFr::rand(rng);
		let leaf_private_1 = LeafPrivateInputs::<BnFr>::new(in_amount_1, blinding_1);
		let leaf_private_inputs = vec![leaf_private_1.clone()];

		let leaf_public_input = LeafPublicInputs::<BnFr>::new(chain_id.clone());

		let private_key_1 = BnFr::rand(rng);
		let keypair_1 = KeyPair::new(private_key_1.clone());
		let privkey = to_bytes![private_key_1].unwrap();
		let public_key_1 = PoseidonCRH2::evaluate(&hasher_params_w2, &privkey).unwrap();
		let keypair_inputs = vec![keypair_1.clone()];

		let leaf_1 = Leaf::create_leaf(
			&leaf_private_1,
			&leaf_public_input,
			&public_key_1,
			&hasher_params_w5,
		)
		.unwrap();
		let commitment_1 = leaf_1.clone();

		let inner_params = Rc::new(params3.clone());
		let leaves = [leaf_1];
		let tree = Tree_x5::new_sequential(inner_params, Rc::new(()), &leaves).unwrap();

		let path_1 = tree.generate_membership_proof(0);
		let paths = vec![path_1.clone()];

		let public_amount = BnFr::one();

		let ext_data_hash_1 = setup_vanchor_arbitrary_data(commitment_1);
		let ext_data_hash = ext_data_hash_1; // We used it as a sample value for ext_data_hash in the tests
		let root = tree.root().inner();

		let mut root_set = [BnFr::rand(rng); TEST_M];
		root_set[0] = root;
		assert_eq!(root_set.len(), TEST_M);
		let index_0: BnFr = path_1.get_index(&tree.root(), &leaf_1).unwrap();
		let indices = vec![index_0];

		let signature = keypair_1
			.signature::<PoseidonCRH4, PoseidonCRH5>(&leaf_1, &index_0, &hasher_params_w4)
			.unwrap();
		let nullifier_hash_1 =
			Leaf::create_nullifier(&signature, &leaf_1, &hasher_params_w4, &index_0).unwrap();
		let nullifier_hash = vec![nullifier_hash_1];

		let set_private_inputs_1 = setup_set(&root, &root_set);
		let set_private_inputs = vec![set_private_inputs_1.clone(), set_private_inputs_1.clone()];

		let out_chain_id_1 = BnFr::one();
		let out_amount_1 = public_amount + leaf_private_1.amount;
		let out_pubkey_1 = BnFr::rand(rng);
		let out_blinding_1 = BnFr::rand(rng);

		let out_leaf_private_1 = LeafPrivateInputs::<BnFr>::new(out_amount_1, out_blinding_1);
		let out_leaf_private = vec![out_leaf_private_1.clone()];

		let out_leaf_public_1 = LeafPublicInputs::<BnFr>::new(out_chain_id_1);
		let out_leaf_public = vec![out_leaf_public_1.clone()];

		let output_commitment_1 = Leaf::create_leaf(
			&out_leaf_private_1,
			&out_leaf_public_1,
			&out_pubkey_1,
			&hasher_params_w5,
		)
		.unwrap();

		let out_pubkey = vec![out_pubkey_1];
		let output_commitment = vec![output_commitment_1];
		let circuit = VACircuit1_1::new(
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
		public_inputs.push(chain_id);
		public_inputs.push(public_amount);
		public_inputs.extend(root_set);
		public_inputs.extend(nullifier_hash);
		public_inputs.extend(output_commitment);
		public_inputs.push(ext_data_hash.ext_data);

		let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), rng).unwrap();
		let proof = Groth16::<Bn254>::prove(&pk, circuit.clone(), rng).unwrap();
		let res = Groth16::<Bn254>::verify(&vk, &public_inputs, &proof).unwrap();

		assert!(res);
	}

	type VACircuit1_2 = VAnchorCircuit<
		BnFr,
		PoseidonCRH2,
		PoseidonCRH2Gadget,
		PoseidonCRH4,
		PoseidonCRH4Gadget,
		PoseidonCRH5,
		PoseidonCRH5Gadget,
		TreeConfig_x5<BnFr>,
		LeafCRHGadget<BnFr>,
		PoseidonCRH_x5_3Gadget<BnFr>,
		TEST_K,
		TEST_N_INS_1,
		TEST_N_OUTS_2,
		TEST_M,
	>;
	#[test]
	fn should_create_circuit_and_prove_groth16_1_input_2_output() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;
		let hasher_params_w5: PoseidonParameters<BnFr> = setup_params_x5_5(curve);
		let hasher_params_w4: PoseidonParameters<BnFr> = setup_params_x5_4(curve);
		let params3: PoseidonParameters<BnFr> = setup_params_x5_3(curve);
		let hasher_params_w2: PoseidonParameters<BnFr> = setup_params_x5_2(curve);
		let chain_id = BnFr::zero();

		let in_amount_1 = BnFr::one();
		let blinding_1 = BnFr::rand(rng);
		let leaf_private_1 = LeafPrivateInputs::<BnFr>::new(in_amount_1, blinding_1);
		let leaf_private_inputs = vec![leaf_private_1.clone()];

		let leaf_public_input = LeafPublicInputs::<BnFr>::new(chain_id.clone());

		let private_key_1 = BnFr::rand(rng);
		let keypair_1 = KeyPair::new(private_key_1.clone());
		let privkey = to_bytes![private_key_1].unwrap();
		let public_key_1 = PoseidonCRH2::evaluate(&hasher_params_w2, &privkey).unwrap();
		let keypair_inputs = vec![keypair_1.clone()];

		let leaf_1 = Leaf::create_leaf(
			&leaf_private_1,
			&leaf_public_input,
			&public_key_1,
			&hasher_params_w5,
		)
		.unwrap();
		let commitment_1 = leaf_1.clone();

		let inner_params = Rc::new(params3.clone());
		let leaves = [leaf_1];
		let tree = Tree_x5::new_sequential(inner_params, Rc::new(()), &leaves).unwrap();

		let path_1 = tree.generate_membership_proof(0);
		let paths = vec![path_1.clone()];

		let public_amount = BnFr::one();

		let ext_data_hash_1 = setup_vanchor_arbitrary_data(commitment_1);
		let ext_data_hash = ext_data_hash_1; // We used it as a sample value for ext_data_hash in the tests
		let root = tree.root().inner();

		let mut root_set = [BnFr::rand(rng); TEST_M];
		root_set[0] = root;
		assert_eq!(root_set.len(), TEST_M);
		let index_0: BnFr = path_1.get_index(&tree.root(), &leaf_1).unwrap();
		let indices = vec![index_0];

		let signature = keypair_1
			.signature::<PoseidonCRH4, PoseidonCRH5>(&leaf_1, &index_0, &hasher_params_w4)
			.unwrap();
		let nullifier_hash_1 =
			Leaf::create_nullifier(&signature, &leaf_1, &hasher_params_w4, &index_0).unwrap();
		let nullifier_hash = vec![nullifier_hash_1];

		let set_private_inputs_1 = setup_set(&root, &root_set);
		let set_private_inputs = vec![set_private_inputs_1.clone(), set_private_inputs_1.clone()];

		let out_chain_id_1 = BnFr::one();
		let out_amount_1 = public_amount + leaf_private_1.amount - BnFr::one();
		let out_pubkey_1 = BnFr::rand(rng);
		let out_blinding_1 = BnFr::rand(rng);

		let out_chain_id_2 = BnFr::one();
		let out_amount_2 = BnFr::one();
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
		let circuit = VACircuit1_2::new(
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
		public_inputs.push(chain_id);
		public_inputs.push(public_amount);
		public_inputs.extend(root_set);
		public_inputs.extend(nullifier_hash);
		public_inputs.extend(output_commitment);
		public_inputs.push(ext_data_hash.ext_data);

		let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), rng).unwrap();
		let proof = Groth16::<Bn254>::prove(&pk, circuit.clone(), rng).unwrap();
		let res = Groth16::<Bn254>::verify(&vk, &public_inputs, &proof).unwrap();

		assert!(res);
	}

	type VACircuit2_1 = VAnchorCircuit<
		BnFr,
		PoseidonCRH2,
		PoseidonCRH2Gadget,
		PoseidonCRH4,
		PoseidonCRH4Gadget,
		PoseidonCRH5,
		PoseidonCRH5Gadget,
		TreeConfig_x5<BnFr>,
		LeafCRHGadget<BnFr>,
		PoseidonCRH_x5_3Gadget<BnFr>,
		TEST_K,
		TEST_N_INS_2,
		TEST_N_OUTS_1,
		TEST_M,
	>;

	#[test]
	fn should_create_circuit_and_prove_groth16_2_input_1_output() {
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
		let public_key_1 = PoseidonCRH2::evaluate(&hasher_params_w2, &privkey).unwrap();
		let private_key_2 = BnFr::rand(rng);
		let keypair_2 = KeyPair::new(private_key_2.clone());
		let privkey = to_bytes![private_key_2].unwrap();
		let public_key_2 = PoseidonCRH2::evaluate(&hasher_params_w2, &privkey).unwrap();
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
			.signature::<PoseidonCRH4, PoseidonCRH5>(&leaf_1, &index_0, &hasher_params_w4)
			.unwrap();
		let nullifier_hash_1 =
			Leaf::create_nullifier(&signature, &leaf_1, &hasher_params_w4, &index_0).unwrap();
		let signature = keypair_2
			.signature::<PoseidonCRH4, PoseidonCRH5>(&leaf_2, &index_1, &hasher_params_w4)
			.unwrap();
		let nullifier_hash_2 =
			Leaf::create_nullifier(&signature, &leaf_2, &hasher_params_w4, &index_1).unwrap();
		let nullifier_hash = vec![nullifier_hash_1, nullifier_hash_2];
		assert_ne!(nullifier_hash_1, nullifier_hash_2);

		let set_private_inputs_1 = setup_set(&root, &root_set);
		let set_private_inputs = vec![set_private_inputs_1.clone(), set_private_inputs_1.clone()];

		let out_chain_id_1 = BnFr::one();
		let out_amount_1 = public_amount + leaf_private_1.amount + leaf_private_2.amount;
		let out_pubkey_1 = BnFr::rand(rng);
		let out_blinding_1 = BnFr::rand(rng);

		let out_leaf_private_1 = LeafPrivateInputs::<BnFr>::new(out_amount_1, out_blinding_1);
		let out_leaf_private = vec![out_leaf_private_1.clone()];

		let out_leaf_public_1 = LeafPublicInputs::<BnFr>::new(out_chain_id_1);
		let out_leaf_public = vec![out_leaf_public_1.clone()];

		let output_commitment_1 = Leaf::create_leaf(
			&out_leaf_private_1,
			&out_leaf_public_1,
			&out_pubkey_1,
			&hasher_params_w5,
		)
		.unwrap();

		let out_pubkey = vec![out_pubkey_1];
		let output_commitment = vec![output_commitment_1];
		let circuit = VACircuit2_1::new(
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
		public_inputs.push(chain_id);
		public_inputs.push(public_amount);
		public_inputs.extend(root_set);
		public_inputs.extend(nullifier_hash);
		public_inputs.extend(output_commitment);
		public_inputs.push(ext_data_hash.ext_data);

		let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), rng).unwrap();
		let proof = Groth16::<Bn254>::prove(&pk, circuit.clone(), rng).unwrap();
		let res = Groth16::<Bn254>::verify(&vk, &public_inputs, &proof).unwrap();

		assert!(res);
	}

	pub const TEST_N_INS_8: usize = 8;
	pub const TEST_N_OUTS_8: usize = 8;

	type VACircuit8_8 = VAnchorCircuit<
		BnFr,
		PoseidonCRH2,
		PoseidonCRH2Gadget,
		PoseidonCRH4,
		PoseidonCRH4Gadget,
		PoseidonCRH5,
		PoseidonCRH5Gadget,
		TreeConfig_x5<BnFr>,
		LeafCRHGadget<BnFr>,
		PoseidonCRH_x5_3Gadget<BnFr>,
		TEST_K,
		TEST_N_INS_8,
		TEST_N_OUTS_8,
		TEST_M,
	>;
	// This test considers two different batch of inputs from two different
	// chains. Therefore two different trees are used
	#[test]
	fn should_create_circuit_and_prove_groth16_8_input_8_output() {
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
		let in_amount_3 = BnFr::one();
		let blinding_3 = BnFr::rand(rng);
		let in_amount_4 = BnFr::one() + BnFr::one();
		let blinding_4 = BnFr::rand(rng);
		let in_amount_5 = BnFr::one();
		let blinding_5 = BnFr::rand(rng);
		let in_amount_6 = BnFr::one() + BnFr::one();
		let blinding_6 = BnFr::rand(rng);
		let in_amount_7 = BnFr::one();
		let blinding_7 = BnFr::rand(rng);
		let in_amount_8 = BnFr::one() + BnFr::one();
		let blinding_8 = BnFr::rand(rng);
		let leaf_private_1 = LeafPrivateInputs::<BnFr>::new(in_amount_1, blinding_1);
		let leaf_private_2 = LeafPrivateInputs::<BnFr>::new(in_amount_2, blinding_2);
		let leaf_private_3 = LeafPrivateInputs::<BnFr>::new(in_amount_3, blinding_3);
		let leaf_private_4 = LeafPrivateInputs::<BnFr>::new(in_amount_4, blinding_4);
		let leaf_private_5 = LeafPrivateInputs::<BnFr>::new(in_amount_5, blinding_5);
		let leaf_private_6 = LeafPrivateInputs::<BnFr>::new(in_amount_6, blinding_6);
		let leaf_private_7 = LeafPrivateInputs::<BnFr>::new(in_amount_7, blinding_7);
		let leaf_private_8 = LeafPrivateInputs::<BnFr>::new(in_amount_8, blinding_8);
		let leaf_private_inputs = vec![
			leaf_private_1.clone(),
			leaf_private_2.clone(),
			leaf_private_3.clone(),
			leaf_private_4.clone(),
			leaf_private_5.clone(),
			leaf_private_6.clone(),
			leaf_private_7.clone(),
			leaf_private_8.clone(),
		];

		let leaf_public_input = LeafPublicInputs::<BnFr>::new(chain_id.clone());

		let private_key_1 = BnFr::rand(rng);
		let privkey = to_bytes![private_key_1].unwrap();
		let public_key_1 = PoseidonCRH2::evaluate(&hasher_params_w2, &privkey).unwrap();
		let private_key_2 = BnFr::rand(rng);
		let privkey = to_bytes![private_key_2].unwrap();
		let public_key_2 = PoseidonCRH2::evaluate(&hasher_params_w2, &privkey).unwrap();
		let private_key_3 = BnFr::rand(rng);
		let privkey = to_bytes![private_key_3].unwrap();
		let public_key_3 = PoseidonCRH2::evaluate(&hasher_params_w2, &privkey).unwrap();
		let private_key_4 = BnFr::rand(rng);
		let privkey = to_bytes![private_key_4].unwrap();
		let public_key_4 = PoseidonCRH2::evaluate(&hasher_params_w2, &privkey).unwrap();
		let private_key_5 = BnFr::rand(rng);
		let privkey = to_bytes![private_key_5].unwrap();
		let public_key_5 = PoseidonCRH2::evaluate(&hasher_params_w2, &privkey).unwrap();
		let private_key_6 = BnFr::rand(rng);
		let privkey = to_bytes![private_key_6].unwrap();
		let public_key_6 = PoseidonCRH2::evaluate(&hasher_params_w2, &privkey).unwrap();
		let private_key_7 = BnFr::rand(rng);
		let privkey = to_bytes![private_key_7].unwrap();
		let public_key_7 = PoseidonCRH2::evaluate(&hasher_params_w2, &privkey).unwrap();
		let private_key_8 = BnFr::rand(rng);
		let privkey = to_bytes![private_key_8].unwrap();
		let public_key_8 = PoseidonCRH2::evaluate(&hasher_params_w2, &privkey).unwrap();
		let keypair_1 = KeyPair::new(private_key_1.clone());
		let keypair_2 = KeyPair::new(private_key_2.clone());
		let keypair_3 = KeyPair::new(private_key_3.clone());
		let keypair_4 = KeyPair::new(private_key_4.clone());
		let keypair_5 = KeyPair::new(private_key_5.clone());
		let keypair_6 = KeyPair::new(private_key_6.clone());
		let keypair_7 = KeyPair::new(private_key_7.clone());
		let keypair_8 = KeyPair::new(private_key_8.clone());
		let keypair_inputs = vec![
			keypair_1.clone(),
			keypair_2.clone(),
			keypair_3.clone(),
			keypair_4.clone(),
			keypair_5.clone(),
			keypair_6.clone(),
			keypair_7.clone(),
			keypair_8.clone(),
		];

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
		let leaf_3 = Leaf::create_leaf(
			&leaf_private_3,
			&leaf_public_input,
			&public_key_3,
			&hasher_params_w5,
		)
		.unwrap();
		let leaf_4 = Leaf::create_leaf(
			&leaf_private_4,
			&leaf_public_input,
			&public_key_4,
			&hasher_params_w5,
		)
		.unwrap();
		let leaf_5 = Leaf::create_leaf(
			&leaf_private_5,
			&leaf_public_input,
			&public_key_5,
			&hasher_params_w5,
		)
		.unwrap();
		let leaf_6 = Leaf::create_leaf(
			&leaf_private_6,
			&leaf_public_input,
			&public_key_6,
			&hasher_params_w5,
		)
		.unwrap();
		let leaf_7 = Leaf::create_leaf(
			&leaf_private_7,
			&leaf_public_input,
			&public_key_7,
			&hasher_params_w5,
		)
		.unwrap();
		let leaf_8 = Leaf::create_leaf(
			&leaf_private_8,
			&leaf_public_input,
			&public_key_8,
			&hasher_params_w5,
		)
		.unwrap();

		let inner_params = Rc::new(params3.clone());
		let leaves_on_chain_1 = [leaf_1, leaf_2, leaf_3, leaf_4];
		let leaves_on_chain_2 = [leaf_5, leaf_6, leaf_7, leaf_8];
		let tree_1 =
			Tree_x5::new_sequential(inner_params.clone(), Rc::new(()), &leaves_on_chain_1).unwrap();
		let tree_2 =
			Tree_x5::new_sequential(inner_params, Rc::new(()), &leaves_on_chain_2).unwrap();

		let path_1 = tree_1.generate_membership_proof(0);
		let path_2 = tree_1.generate_membership_proof(1);
		let path_3 = tree_1.generate_membership_proof(2);
		let path_4 = tree_1.generate_membership_proof(3);
		let path_5 = tree_2.generate_membership_proof(0);
		let path_6 = tree_2.generate_membership_proof(1);
		let path_7 = tree_2.generate_membership_proof(2);
		let path_8 = tree_2.generate_membership_proof(3);
		let paths = vec![
			path_1.clone(),
			path_2.clone(),
			path_3.clone(),
			path_4.clone(),
			path_5.clone(),
			path_6.clone(),
			path_7.clone(),
			path_8.clone(),
		];

		let public_amount = BnFr::one();

		let ext_data_hash_1 = setup_vanchor_arbitrary_data(commitment_1);
		let ext_data_hash = ext_data_hash_1; // We used it as a sample value for ext_data_hash in the tests
		let root_1 = tree_1.root().inner();
		let root_2 = tree_2.root().inner();

		let mut root_set = [BnFr::rand(rng); TEST_M];
		root_set[0] = root_1;
		root_set[1] = root_2;
		assert_eq!(root_set.len(), TEST_M);
		let index_0: BnFr = path_1.get_index(&tree_1.root(), &leaf_1).unwrap();
		let index_1: BnFr = path_2.get_index(&tree_1.root(), &leaf_2).unwrap();
		let index_2: BnFr = path_3.get_index(&tree_1.root(), &leaf_3).unwrap();
		let index_3: BnFr = path_4.get_index(&tree_1.root(), &leaf_4).unwrap();
		let index_4: BnFr = path_5.get_index(&tree_2.root(), &leaf_5).unwrap();
		let index_5: BnFr = path_6.get_index(&tree_2.root(), &leaf_6).unwrap();
		let index_6: BnFr = path_7.get_index(&tree_2.root(), &leaf_7).unwrap();
		let index_7: BnFr = path_8.get_index(&tree_2.root(), &leaf_8).unwrap();
		let indices = vec![
			index_0, index_1, index_2, index_3, index_4, index_5, index_6, index_7,
		];

		let signature = keypair_1
			.signature::<PoseidonCRH4, PoseidonCRH5>(&leaf_1, &index_0, &hasher_params_w4)
			.unwrap();
		let nullifier_hash_1 =
			Leaf::create_nullifier(&signature, &leaf_1, &hasher_params_w4, &index_0).unwrap();
		let signature = keypair_2
			.signature::<PoseidonCRH4, PoseidonCRH5>(&leaf_2, &index_1, &hasher_params_w4)
			.unwrap();
		let nullifier_hash_2 =
			Leaf::create_nullifier(&signature, &leaf_2, &hasher_params_w4, &index_1).unwrap();
		let signature = keypair_3
			.signature::<PoseidonCRH4, PoseidonCRH5>(&leaf_3, &index_2, &hasher_params_w4)
			.unwrap();
		let nullifier_hash_3 =
			Leaf::create_nullifier(&signature, &leaf_3, &hasher_params_w4, &index_2).unwrap();
		let signature = keypair_4
			.signature::<PoseidonCRH4, PoseidonCRH5>(&leaf_4, &index_3, &hasher_params_w4)
			.unwrap();
		let nullifier_hash_4 =
			Leaf::create_nullifier(&signature, &leaf_4, &hasher_params_w4, &index_3).unwrap();
		let signature = keypair_5
			.signature::<PoseidonCRH4, PoseidonCRH5>(&leaf_5, &index_4, &hasher_params_w4)
			.unwrap();
		let nullifier_hash_5 =
			Leaf::create_nullifier(&signature, &leaf_5, &hasher_params_w4, &index_4).unwrap();
		let signature = keypair_6
			.signature::<PoseidonCRH4, PoseidonCRH5>(&leaf_6, &index_5, &hasher_params_w4)
			.unwrap();
		let nullifier_hash_6 =
			Leaf::create_nullifier(&signature, &leaf_6, &hasher_params_w4, &index_5).unwrap();
		let signature = keypair_7
			.signature::<PoseidonCRH4, PoseidonCRH5>(&leaf_7, &index_6, &hasher_params_w4)
			.unwrap();
		let nullifier_hash_7 =
			Leaf::create_nullifier(&signature, &leaf_7, &hasher_params_w4, &index_6).unwrap();
		let signature = keypair_8
			.signature::<PoseidonCRH4, PoseidonCRH5>(&leaf_8, &index_7, &hasher_params_w4)
			.unwrap();
		let nullifier_hash_8 =
			Leaf::create_nullifier(&signature, &leaf_8, &hasher_params_w4, &index_7).unwrap();
		let nullifier_hash = vec![
			nullifier_hash_1,
			nullifier_hash_2,
			nullifier_hash_3,
			nullifier_hash_4,
			nullifier_hash_5,
			nullifier_hash_6,
			nullifier_hash_7,
			nullifier_hash_8,
		];

		let set_private_inputs_1 = setup_set(&root_1, &root_set);
		let set_private_inputs_2 = setup_set(&root_2, &root_set);
		let set_private_inputs = vec![
			set_private_inputs_1.clone(),
			set_private_inputs_1.clone(),
			set_private_inputs_1.clone(),
			set_private_inputs_1.clone(),
			set_private_inputs_2.clone(),
			set_private_inputs_2.clone(),
			set_private_inputs_2.clone(),
			set_private_inputs_2.clone(),
		];

		let out_chain_id_1 = BnFr::one();
		let out_amount_1 = public_amount + leaf_private_1.amount;
		let out_pubkey_1 = BnFr::rand(rng);
		let out_blinding_1 = BnFr::rand(rng);
		let bytes = to_bytes![out_chain_id_1, out_amount_1, out_pubkey_1, out_blinding_1].unwrap();
		let output_commitment_1 = PoseidonCRH5::evaluate(&hasher_params_w5, &bytes).unwrap();

		let out_chain_id_2 = BnFr::one();
		let out_amount_2 = leaf_private_2.amount;
		let out_pubkey_2 = BnFr::rand(rng);
		let out_blinding_2 = BnFr::rand(rng);
		let bytes = to_bytes![out_chain_id_2, out_amount_2, out_pubkey_2, out_blinding_2].unwrap();
		let output_commitment_2 = PoseidonCRH5::evaluate(&hasher_params_w5, &bytes).unwrap();

		let out_chain_id_3 = BnFr::one();
		let out_amount_3 = leaf_private_3.amount;
		let out_pubkey_3 = BnFr::rand(rng);
		let out_blinding_3 = BnFr::rand(rng);
		let bytes = to_bytes![out_chain_id_3, out_amount_3, out_pubkey_3, out_blinding_3].unwrap();
		let output_commitment_3 = PoseidonCRH5::evaluate(&hasher_params_w5, &bytes).unwrap();

		let out_chain_id_4 = BnFr::one();
		let out_amount_4 = leaf_private_4.amount;
		let out_pubkey_4 = BnFr::rand(rng);
		let out_blinding_4 = BnFr::rand(rng);
		let bytes = to_bytes![out_chain_id_4, out_amount_4, out_pubkey_4, out_blinding_4].unwrap();
		let output_commitment_4 = PoseidonCRH5::evaluate(&hasher_params_w5, &bytes).unwrap();

		let out_chain_id_5 = BnFr::one();
		let out_amount_5 = leaf_private_5.amount;
		let out_pubkey_5 = BnFr::rand(rng);
		let out_blinding_5 = BnFr::rand(rng);
		let bytes = to_bytes![out_chain_id_5, out_amount_5, out_pubkey_5, out_blinding_5].unwrap();
		let output_commitment_5 = PoseidonCRH5::evaluate(&hasher_params_w5, &bytes).unwrap();

		let out_chain_id_6 = BnFr::one();
		let out_amount_6 = leaf_private_6.amount;
		let out_pubkey_6 = BnFr::rand(rng);
		let out_blinding_6 = BnFr::rand(rng);
		let bytes = to_bytes![out_chain_id_6, out_amount_6, out_pubkey_6, out_blinding_6].unwrap();
		let output_commitment_6 = PoseidonCRH5::evaluate(&hasher_params_w5, &bytes).unwrap();

		let out_chain_id_7 = BnFr::one();
		let out_amount_7 = leaf_private_7.amount;
		let out_pubkey_7 = BnFr::rand(rng);
		let out_blinding_7 = BnFr::rand(rng);
		let bytes = to_bytes![out_chain_id_7, out_amount_7, out_pubkey_7, out_blinding_7].unwrap();
		let output_commitment_7 = PoseidonCRH5::evaluate(&hasher_params_w5, &bytes).unwrap();

		let out_chain_id_8 = BnFr::one();
		let out_amount_8 = leaf_private_8.amount;
		let out_pubkey_8 = BnFr::rand(rng);
		let out_blinding_8 = BnFr::rand(rng);
		let bytes = to_bytes![out_chain_id_8, out_amount_8, out_pubkey_8, out_blinding_8].unwrap();
		let output_commitment_8 = PoseidonCRH5::evaluate(&hasher_params_w5, &bytes).unwrap();

		let out_leaf_private_1 = LeafPrivateInputs::<BnFr>::new(out_amount_1, out_blinding_1);
		let out_leaf_private_2 = LeafPrivateInputs::<BnFr>::new(out_amount_2, out_blinding_2);
		let out_leaf_private_3 = LeafPrivateInputs::<BnFr>::new(out_amount_3, out_blinding_3);
		let out_leaf_private_4 = LeafPrivateInputs::<BnFr>::new(out_amount_4, out_blinding_4);
		let out_leaf_private_5 = LeafPrivateInputs::<BnFr>::new(out_amount_5, out_blinding_5);
		let out_leaf_private_6 = LeafPrivateInputs::<BnFr>::new(out_amount_6, out_blinding_6);
		let out_leaf_private_7 = LeafPrivateInputs::<BnFr>::new(out_amount_7, out_blinding_7);
		let out_leaf_private_8 = LeafPrivateInputs::<BnFr>::new(out_amount_8, out_blinding_8);
		let out_leaf_private = vec![
			out_leaf_private_1.clone(),
			out_leaf_private_2.clone(),
			out_leaf_private_3.clone(),
			out_leaf_private_4.clone(),
			out_leaf_private_5.clone(),
			out_leaf_private_6.clone(),
			out_leaf_private_7.clone(),
			out_leaf_private_8.clone(),
		];

		let out_leaf_public_1 = LeafPublicInputs::<BnFr>::new(out_chain_id_1);
		let out_leaf_public_2 = LeafPublicInputs::<BnFr>::new(out_chain_id_2);
		let out_leaf_public_3 = LeafPublicInputs::<BnFr>::new(out_chain_id_3);
		let out_leaf_public_4 = LeafPublicInputs::<BnFr>::new(out_chain_id_4);
		let out_leaf_public_5 = LeafPublicInputs::<BnFr>::new(out_chain_id_5);
		let out_leaf_public_6 = LeafPublicInputs::<BnFr>::new(out_chain_id_6);
		let out_leaf_public_7 = LeafPublicInputs::<BnFr>::new(out_chain_id_7);
		let out_leaf_public_8 = LeafPublicInputs::<BnFr>::new(out_chain_id_8);
		let out_leaf_public = vec![
			out_leaf_public_1.clone(),
			out_leaf_public_2.clone(),
			out_leaf_public_3.clone(),
			out_leaf_public_4.clone(),
			out_leaf_public_5.clone(),
			out_leaf_public_6.clone(),
			out_leaf_public_7.clone(),
			out_leaf_public_8.clone(),
		];

		let out_pubkey = vec![
			out_pubkey_1,
			out_pubkey_2,
			out_pubkey_3,
			out_pubkey_4,
			out_pubkey_5,
			out_pubkey_6,
			out_pubkey_7,
			out_pubkey_8,
		];

		let output_commitment = vec![
			output_commitment_1,
			output_commitment_2,
			output_commitment_3,
			output_commitment_4,
			output_commitment_5,
			output_commitment_6,
			output_commitment_7,
			output_commitment_8,
		];
		let circuit = VACircuit8_8::new(
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
		public_inputs.push(chain_id);
		public_inputs.push(public_amount);
		public_inputs.extend(root_set);
		public_inputs.extend(nullifier_hash);
		public_inputs.extend(output_commitment);
		public_inputs.push(ext_data_hash.ext_data);

		let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), rng).unwrap();
		let proof = Groth16::<Bn254>::prove(&pk, circuit.clone(), rng).unwrap();
		let res = Groth16::<Bn254>::verify(&vk, &public_inputs, &proof).unwrap();

		assert!(res);
	}

	pub const TEST_N_OUTS_4: usize = 4;

	type VACircuit8_4 = VAnchorCircuit<
		BnFr,
		PoseidonCRH2,
		PoseidonCRH2Gadget,
		PoseidonCRH4,
		PoseidonCRH4Gadget,
		PoseidonCRH5,
		PoseidonCRH5Gadget,
		TreeConfig_x5<BnFr>,
		LeafCRHGadget<BnFr>,
		PoseidonCRH_x5_3Gadget<BnFr>,
		TEST_K,
		TEST_N_INS_8,
		TEST_N_OUTS_4,
		TEST_M,
	>;
	#[test]
	fn should_create_circuit_and_prove_groth16_8_input_4_output() {
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
		let in_amount_3 = BnFr::one();
		let blinding_3 = BnFr::rand(rng);
		let in_amount_4 = BnFr::one() + BnFr::one();
		let blinding_4 = BnFr::rand(rng);
		let in_amount_5 = BnFr::one();
		let blinding_5 = BnFr::rand(rng);
		let in_amount_6 = BnFr::one() + BnFr::one();
		let blinding_6 = BnFr::rand(rng);
		let in_amount_7 = BnFr::one();
		let blinding_7 = BnFr::rand(rng);
		let in_amount_8 = BnFr::one() + BnFr::one();
		let blinding_8 = BnFr::rand(rng);
		let leaf_private_1 = LeafPrivateInputs::<BnFr>::new(in_amount_1, blinding_1);
		let leaf_private_2 = LeafPrivateInputs::<BnFr>::new(in_amount_2, blinding_2);
		let leaf_private_3 = LeafPrivateInputs::<BnFr>::new(in_amount_3, blinding_3);
		let leaf_private_4 = LeafPrivateInputs::<BnFr>::new(in_amount_4, blinding_4);
		let leaf_private_5 = LeafPrivateInputs::<BnFr>::new(in_amount_5, blinding_5);
		let leaf_private_6 = LeafPrivateInputs::<BnFr>::new(in_amount_6, blinding_6);
		let leaf_private_7 = LeafPrivateInputs::<BnFr>::new(in_amount_7, blinding_7);
		let leaf_private_8 = LeafPrivateInputs::<BnFr>::new(in_amount_8, blinding_8);
		let leaf_private_inputs = vec![
			leaf_private_1.clone(),
			leaf_private_2.clone(),
			leaf_private_3.clone(),
			leaf_private_4.clone(),
			leaf_private_5.clone(),
			leaf_private_6.clone(),
			leaf_private_7.clone(),
			leaf_private_8.clone(),
		];

		let leaf_public_input = LeafPublicInputs::<BnFr>::new(chain_id.clone());

		let private_key_1 = BnFr::rand(rng);
		let privkey = to_bytes![private_key_1].unwrap();
		let public_key_1 = PoseidonCRH2::evaluate(&hasher_params_w2, &privkey).unwrap();
		let private_key_2 = BnFr::rand(rng);
		let privkey = to_bytes![private_key_2].unwrap();
		let public_key_2 = PoseidonCRH2::evaluate(&hasher_params_w2, &privkey).unwrap();
		let private_key_3 = BnFr::rand(rng);
		let privkey = to_bytes![private_key_3].unwrap();
		let public_key_3 = PoseidonCRH2::evaluate(&hasher_params_w2, &privkey).unwrap();
		let private_key_4 = BnFr::rand(rng);
		let privkey = to_bytes![private_key_4].unwrap();
		let public_key_4 = PoseidonCRH2::evaluate(&hasher_params_w2, &privkey).unwrap();
		let private_key_5 = BnFr::rand(rng);
		let privkey = to_bytes![private_key_5].unwrap();
		let public_key_5 = PoseidonCRH2::evaluate(&hasher_params_w2, &privkey).unwrap();
		let private_key_6 = BnFr::rand(rng);
		let privkey = to_bytes![private_key_6].unwrap();
		let public_key_6 = PoseidonCRH2::evaluate(&hasher_params_w2, &privkey).unwrap();
		let private_key_7 = BnFr::rand(rng);
		let privkey = to_bytes![private_key_7].unwrap();
		let public_key_7 = PoseidonCRH2::evaluate(&hasher_params_w2, &privkey).unwrap();
		let private_key_8 = BnFr::rand(rng);
		let privkey = to_bytes![private_key_8].unwrap();
		let public_key_8 = PoseidonCRH2::evaluate(&hasher_params_w2, &privkey).unwrap();
		let keypair_1 = KeyPair::new(private_key_1.clone());
		let keypair_2 = KeyPair::new(private_key_2.clone());
		let keypair_3 = KeyPair::new(private_key_3.clone());
		let keypair_4 = KeyPair::new(private_key_4.clone());
		let keypair_5 = KeyPair::new(private_key_5.clone());
		let keypair_6 = KeyPair::new(private_key_6.clone());
		let keypair_7 = KeyPair::new(private_key_7.clone());
		let keypair_8 = KeyPair::new(private_key_8.clone());
		let keypair_inputs = vec![
			keypair_1.clone(),
			keypair_2.clone(),
			keypair_3.clone(),
			keypair_4.clone(),
			keypair_5.clone(),
			keypair_6.clone(),
			keypair_7.clone(),
			keypair_8.clone(),
		];

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
		let leaf_3 = Leaf::create_leaf(
			&leaf_private_3,
			&leaf_public_input,
			&public_key_3,
			&hasher_params_w5,
		)
		.unwrap();
		let leaf_4 = Leaf::create_leaf(
			&leaf_private_4,
			&leaf_public_input,
			&public_key_4,
			&hasher_params_w5,
		)
		.unwrap();
		let leaf_5 = Leaf::create_leaf(
			&leaf_private_5,
			&leaf_public_input,
			&public_key_5,
			&hasher_params_w5,
		)
		.unwrap();
		let leaf_6 = Leaf::create_leaf(
			&leaf_private_6,
			&leaf_public_input,
			&public_key_6,
			&hasher_params_w5,
		)
		.unwrap();
		let leaf_7 = Leaf::create_leaf(
			&leaf_private_7,
			&leaf_public_input,
			&public_key_7,
			&hasher_params_w5,
		)
		.unwrap();
		let leaf_8 = Leaf::create_leaf(
			&leaf_private_8,
			&leaf_public_input,
			&public_key_8,
			&hasher_params_w5,
		)
		.unwrap();

		let inner_params = Rc::new(params3.clone());
		let leaves_on_chain_1 = [leaf_1, leaf_2, leaf_3, leaf_4];
		let leaves_on_chain_2 = [leaf_5, leaf_6, leaf_7, leaf_8];
		let tree_1 =
			Tree_x5::new_sequential(inner_params.clone(), Rc::new(()), &leaves_on_chain_1).unwrap();
		let tree_2 =
			Tree_x5::new_sequential(inner_params, Rc::new(()), &leaves_on_chain_2).unwrap();

		let path_1 = tree_1.generate_membership_proof(0);
		let path_2 = tree_1.generate_membership_proof(1);
		let path_3 = tree_1.generate_membership_proof(2);
		let path_4 = tree_1.generate_membership_proof(3);
		let path_5 = tree_2.generate_membership_proof(0);
		let path_6 = tree_2.generate_membership_proof(1);
		let path_7 = tree_2.generate_membership_proof(2);
		let path_8 = tree_2.generate_membership_proof(3);
		let paths = vec![
			path_1.clone(),
			path_2.clone(),
			path_3.clone(),
			path_4.clone(),
			path_5.clone(),
			path_6.clone(),
			path_7.clone(),
			path_8.clone(),
		];

		let public_amount = BnFr::one();

		let ext_data_hash_1 = setup_vanchor_arbitrary_data(commitment_1);
		let ext_data_hash = ext_data_hash_1; // We used it as a sample value for ext_data_hash in the tests
		let root_1 = tree_1.root().inner();
		let root_2 = tree_2.root().inner();

		let mut root_set = [BnFr::rand(rng); TEST_M];
		root_set[0] = root_1;
		root_set[1] = root_2;
		assert_eq!(root_set.len(), TEST_M);
		let index_0: BnFr = path_1.get_index(&tree_1.root(), &leaf_1).unwrap();
		let index_1: BnFr = path_2.get_index(&tree_1.root(), &leaf_2).unwrap();
		let index_2: BnFr = path_3.get_index(&tree_1.root(), &leaf_3).unwrap();
		let index_3: BnFr = path_4.get_index(&tree_1.root(), &leaf_4).unwrap();
		let index_4: BnFr = path_5.get_index(&tree_2.root(), &leaf_5).unwrap();
		let index_5: BnFr = path_6.get_index(&tree_2.root(), &leaf_6).unwrap();
		let index_6: BnFr = path_7.get_index(&tree_2.root(), &leaf_7).unwrap();
		let index_7: BnFr = path_8.get_index(&tree_2.root(), &leaf_8).unwrap();
		let indices = vec![
			index_0, index_1, index_2, index_3, index_4, index_5, index_6, index_7,
		];

		let signature = keypair_1
			.signature::<PoseidonCRH4, PoseidonCRH5>(&leaf_1, &index_0, &hasher_params_w4)
			.unwrap();
		let nullifier_hash_1 =
			Leaf::create_nullifier(&signature, &leaf_1, &hasher_params_w4, &index_0).unwrap();
		let signature = keypair_2
			.signature::<PoseidonCRH4, PoseidonCRH5>(&leaf_2, &index_1, &hasher_params_w4)
			.unwrap();
		let nullifier_hash_2 =
			Leaf::create_nullifier(&signature, &leaf_2, &hasher_params_w4, &index_1).unwrap();
		let signature = keypair_3
			.signature::<PoseidonCRH4, PoseidonCRH5>(&leaf_3, &index_2, &hasher_params_w4)
			.unwrap();
		let nullifier_hash_3 =
			Leaf::create_nullifier(&signature, &leaf_3, &hasher_params_w4, &index_2).unwrap();
		let signature = keypair_4
			.signature::<PoseidonCRH4, PoseidonCRH5>(&leaf_4, &index_3, &hasher_params_w4)
			.unwrap();
		let nullifier_hash_4 =
			Leaf::create_nullifier(&signature, &leaf_4, &hasher_params_w4, &index_3).unwrap();
		let signature = keypair_5
			.signature::<PoseidonCRH4, PoseidonCRH5>(&leaf_5, &index_4, &hasher_params_w4)
			.unwrap();
		let nullifier_hash_5 =
			Leaf::create_nullifier(&signature, &leaf_5, &hasher_params_w4, &index_4).unwrap();
		let signature = keypair_6
			.signature::<PoseidonCRH4, PoseidonCRH5>(&leaf_6, &index_5, &hasher_params_w4)
			.unwrap();
		let nullifier_hash_6 =
			Leaf::create_nullifier(&signature, &leaf_6, &hasher_params_w4, &index_5).unwrap();
		let signature = keypair_7
			.signature::<PoseidonCRH4, PoseidonCRH5>(&leaf_7, &index_6, &hasher_params_w4)
			.unwrap();
		let nullifier_hash_7 =
			Leaf::create_nullifier(&signature, &leaf_7, &hasher_params_w4, &index_6).unwrap();
		let signature = keypair_8
			.signature::<PoseidonCRH4, PoseidonCRH5>(&leaf_8, &index_7, &hasher_params_w4)
			.unwrap();
		let nullifier_hash_8 =
			Leaf::create_nullifier(&signature, &leaf_8, &hasher_params_w4, &index_7).unwrap();

		let nullifier_hash = vec![
			nullifier_hash_1,
			nullifier_hash_2,
			nullifier_hash_3,
			nullifier_hash_4,
			nullifier_hash_5,
			nullifier_hash_6,
			nullifier_hash_7,
			nullifier_hash_8,
		];

		let set_private_inputs_1 = setup_set(&root_1, &root_set);
		let set_private_inputs_2 = setup_set(&root_2, &root_set);
		let set_private_inputs = vec![
			set_private_inputs_1.clone(),
			set_private_inputs_1.clone(),
			set_private_inputs_1.clone(),
			set_private_inputs_1.clone(),
			set_private_inputs_2.clone(),
			set_private_inputs_2.clone(),
			set_private_inputs_2.clone(),
			set_private_inputs_2.clone(),
		];

		let out_chain_id_1 = BnFr::one();
		let out_amount_1 = public_amount + leaf_private_1.amount;
		let out_pubkey_1 = BnFr::rand(rng);
		let out_blinding_1 = BnFr::rand(rng);
		let bytes = to_bytes![out_chain_id_1, out_amount_1, out_pubkey_1, out_blinding_1].unwrap();
		let output_commitment_1 = PoseidonCRH5::evaluate(&hasher_params_w5, &bytes).unwrap();

		let out_chain_id_2 = BnFr::one();
		let out_amount_2 = leaf_private_2.amount;
		let out_pubkey_2 = BnFr::rand(rng);
		let out_blinding_2 = BnFr::rand(rng);
		let bytes = to_bytes![out_chain_id_2, out_amount_2, out_pubkey_2, out_blinding_2].unwrap();
		let output_commitment_2 = PoseidonCRH5::evaluate(&hasher_params_w5, &bytes).unwrap();

		let out_chain_id_3 = BnFr::one();
		let out_amount_3 = leaf_private_3.amount;
		let out_pubkey_3 = BnFr::rand(rng);
		let out_blinding_3 = BnFr::rand(rng);
		let bytes = to_bytes![out_chain_id_3, out_amount_3, out_pubkey_3, out_blinding_3].unwrap();
		let output_commitment_3 = PoseidonCRH5::evaluate(&hasher_params_w5, &bytes).unwrap();

		let out_chain_id_4 = BnFr::one();
		let out_amount_4 = leaf_private_4.amount
			+ leaf_private_5.amount
			+ leaf_private_6.amount
			+ leaf_private_7.amount
			+ leaf_private_8.amount;
		let out_pubkey_4 = BnFr::rand(rng);
		let out_blinding_4 = BnFr::rand(rng);
		let bytes = to_bytes![out_chain_id_4, out_amount_4, out_pubkey_4, out_blinding_4].unwrap();
		let output_commitment_4 = PoseidonCRH5::evaluate(&hasher_params_w5, &bytes).unwrap();

		let out_leaf_private_1 = LeafPrivateInputs::<BnFr>::new(out_amount_1, out_blinding_1);
		let out_leaf_private_2 = LeafPrivateInputs::<BnFr>::new(out_amount_2, out_blinding_2);
		let out_leaf_private_3 = LeafPrivateInputs::<BnFr>::new(out_amount_3, out_blinding_3);
		let out_leaf_private_4 = LeafPrivateInputs::<BnFr>::new(out_amount_4, out_blinding_4);
		let out_leaf_private = vec![
			out_leaf_private_1.clone(),
			out_leaf_private_2.clone(),
			out_leaf_private_3.clone(),
			out_leaf_private_4.clone(),
		];

		let out_leaf_public_1 = LeafPublicInputs::<BnFr>::new(out_chain_id_1);
		let out_leaf_public_2 = LeafPublicInputs::<BnFr>::new(out_chain_id_2);
		let out_leaf_public_3 = LeafPublicInputs::<BnFr>::new(out_chain_id_3);
		let out_leaf_public_4 = LeafPublicInputs::<BnFr>::new(out_chain_id_4);
		let out_leaf_public = vec![
			out_leaf_public_1.clone(),
			out_leaf_public_2.clone(),
			out_leaf_public_3.clone(),
			out_leaf_public_4.clone(),
		];

		let out_pubkey = vec![out_pubkey_1, out_pubkey_2, out_pubkey_3, out_pubkey_4];

		let output_commitment = vec![
			output_commitment_1,
			output_commitment_2,
			output_commitment_3,
			output_commitment_4,
		];
		let circuit = VACircuit8_4::new(
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
		public_inputs.push(chain_id);
		public_inputs.push(public_amount);
		public_inputs.extend(root_set);
		public_inputs.extend(nullifier_hash);
		public_inputs.extend(output_commitment);
		public_inputs.push(ext_data_hash.ext_data);

		let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), rng).unwrap();
		let proof = Groth16::<Bn254>::prove(&pk, circuit.clone(), rng).unwrap();
		let res = Groth16::<Bn254>::verify(&vk, &public_inputs, &proof).unwrap();

		assert!(res);
	}
}
