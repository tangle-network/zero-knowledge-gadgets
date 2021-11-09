use crate::{Vec, arbitrary::{constraints::ArbitraryGadget, Arbitrary}, keypair::{constraints::KeypairCreationGadget, vanchor::constraints::KeypairVar}, leaf::{constraints::VanchorLeafCreationGadget, VanchorLeafCreation}, merkle_tree::{
		constraints::{NodeVar, PathVar},
		Config as MerkleConfig, Path,
	}, set::{Set, SetGadget}};
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
	L: VanchorLeafCreation<H,F>,
	LG: VanchorLeafCreationGadget<F, H, HG, L>,
	// Set of merkle roots
	S: Set<F, M>,
	SG: SetGadget<F, S, M>,
	const N: usize,
	const M: usize,
> {
	arbitrary_input: A::Input,
	leaf_private_inputs: L::Private, // amount, blinding, privkey
	leaf_public_inputs: L::Public,   // pubkey, chain_id
	set_private_inputs: S::Private,
	root_set: [F; M],
	hasher_params: H::Parameters,
	path: Path<C, N>,
	index: F, // TODO: Temporary, we may need to compute it from path
	nullifier_hash: L::Nullifier,
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
	L: VanchorLeafCreation<H,F>,
	LG: VanchorLeafCreationGadget<F, H, HG, L>,
	S: Set<F, M>,
	SG: SetGadget<F, S, M>,
{
	pub fn new(
		arbitrary_input: A::Input,
		leaf_private_inputs: L::Private,
		leaf_public_inputs: L::Public,
		set_private_inputs: S::Private,
		root_set: [F; M],
		hasher_params: H::Parameters,
		path: Path<C, N>,
		index: F,
		nullifier_hash: L::Nullifier,
	) -> Self {
		Self {
			arbitrary_input,
			leaf_private_inputs,
			leaf_public_inputs,
			set_private_inputs,
			root_set,
			hasher_params,
			path,
			index,
			nullifier_hash,
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
	pub fn verify_input_var_embeded(
		&mut self,
		hg4: HG::ParametersVar,
		in_private_key_var: Vec<FpVar<F>>,
		chain_id_var: FpVar<F>,
		in_amount_var: Vec<FpVar<F>>,
		in_blinding_var: Vec<FpVar<F>>,
		in_path_indices_var: Vec<FpVar<F>>,
		in_path_elements_var: Vec<PathVar<F, C, HGT, LHGT, N>>,
		in_nullifier_var: Vec<HG::OutputVar>,
		out_amount_var: Vec<FpVar<F>>,
		// ...
	) -> Result<FpVar<F>, SynthesisError> {
		let mut sums_ins_var = FpVar::<F>::zero();
		let mut in_utxo_hasher_var: Vec<HG::OutputVar> = Vec::with_capacity(N);
		let mut nullifier_hash: Vec<HG::OutputVar> = Vec::with_capacity(N);

		let mut inkeypair: Vec<KeypairVar<H, HG, L, LG, F>> = Vec::with_capacity(N);
		for tx in 0..N {
			inkeypair[tx] = KeypairCreationGadget::<H, HG, F, L, LG>::new_from_key(
				&hg4,
				&in_private_key_var[tx],
			)
			.unwrap();
			// Computing the hash
			let mut bytes = Vec::new();
			bytes.extend(chain_id_var.to_bytes()?);
			bytes.extend(in_amount_var[tx].to_bytes()?);
			bytes.extend(inkeypair[tx].public_key_var().unwrap().to_bytes()?);
			bytes.extend(in_blinding_var[tx].to_bytes()?);

			in_utxo_hasher_var[tx] = HG::evaluate(&hg4, &bytes)?;
			// End of computing the hash

			// Nullifier
			let mut bytes = Vec::new();
			bytes.extend(in_utxo_hasher_var[tx].to_bytes()?);
			bytes.extend(in_path_indices_var[tx].to_bytes()?);
			bytes.extend(in_private_key_var[tx].to_bytes()?);

			nullifier_hash[tx] = HG::evaluate(&hg4, &bytes)?;

			nullifier_hash[tx].enforce_equal(&in_nullifier_var[tx])?;
			// add the roots and diffs signals to the bridge circuit
			// TODO:

			sums_ins_var = sums_ins_var + out_amount_var[tx].clone();
		}
		Ok(sums_ins_var)
	}

	//TODO: Verify correctness of transaction outputs
	pub fn verify_output_var(
		&mut self,
		hg4: HG::ParametersVar,
		output_commitment_var: Vec<HG::OutputVar>,
		out_chain_id_var: Vec<FpVar<F>>,
		out_amount_var: Vec<FpVar<F>>,
		out_pubkey_var: Vec<FpVar<F>>,
		out_blinding_var: Vec<FpVar<F>>,
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
			in_utxo_hasher_var_out[tx] = HG::evaluate(&hg4, &bytes)?;
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
	pub fn verify_no_sam_nul(
		in_nullifier_var: Vec<HG::OutputVar>,
	) -> Result<(), SynthesisError> {
		let mut same_nullifiers: Vec<HG::OutputVar> = Vec::with_capacity(2);
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
		public_amount_var: FpVar<F>,
		sum_ins_var: FpVar<F>,
		sum_outs_var: FpVar<F>,
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
	L: VanchorLeafCreation<H,F>,
	LG: VanchorLeafCreationGadget<F, H, HG, L>,
	S: Set<F, M>,
	SG: SetGadget<F, S, M>,
{
	fn clone(&self) -> Self {
		let arbitrary_input = self.arbitrary_input.clone();
		let leaf_private_inputs = self.leaf_private_inputs.clone();
		let leaf_public_inputs = self.leaf_public_inputs.clone();
		let set_private_inputs = self.set_private_inputs.clone();
		let root_set = self.root_set;
		let hasher_params = self.hasher_params.clone();
		let path = self.path.clone();
		let index = self.index.clone();
		let nullifier_hash = self.nullifier_hash.clone();
		Self::new(
			arbitrary_input,
			leaf_private_inputs,
			leaf_public_inputs,
			set_private_inputs,
			root_set,
			hasher_params,
			path,
			index,
			nullifier_hash,
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
	L: VanchorLeafCreation<H,F>,
	LG: VanchorLeafCreationGadget<F, H, HG, L>,
	S: Set<F, M>,
	SG: SetGadget<F, S, M>,
{
	fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
		let arbitrary_input = self.arbitrary_input;
		let leaf_private = self.leaf_private_inputs;
		let leaf_public = self.leaf_public_inputs;
		let set_private = self.set_private_inputs;
		let root_set = self.root_set;
		let hasher_params = self.hasher_params;
		let path = self.path;
		let index = self.index;
		let root = root_set[0];//TODO fix this
		let nullifier_hash = self.nullifier_hash;

		// Generating vars
		// Public inputs
		let leaf_public_var = LG::PublicVar::new_input(cs.clone(), || Ok(leaf_public))?;
		let nullifier_hash_var = LG::NullifierVar::new_input(cs.clone(), || Ok(nullifier_hash))?;
		let root_set_var = Vec::<FpVar<F>>::new_input(cs.clone(), || Ok(root_set))?;
		let arbitrary_input_var = AG::InputVar::new_input(cs.clone(), || Ok(arbitrary_input))?;
		// TODO: publicAmount

		// Constants
		let hasher_params_var = HG::ParametersVar::new_constant(cs.clone(), hasher_params)?;

		// Private inputs
		let leaf_private_var = LG::PrivateVar::new_witness(cs.clone(), || Ok(leaf_private))?;
		let set_input_private_var = SG::PrivateVar::new_witness(cs.clone(), || Ok(set_private))?;
		let path_var = PathVar::<F, C, HGT, LHGT, N>::new_witness(cs.clone(), || Ok(path))?;
		let index_var = FpVar::<F>::new_witness(cs.clone(), || Ok(index)).unwrap();

		let prk = LG::get_private_key(&leaf_private_var).unwrap();
		let mut bytes = Vec::<UInt8<F>>::new();
		bytes.extend(prk.to_bytes()?);
		//let bytes = to_bytes![prk.to_bytes()].unwrap();
		//let privkey_var = Vec::<UInt8<F>>::new_witness(cs.clone(), ||
		// Ok(bytes)).unwrap();
		let pubkey_var = HG::evaluate(&hasher_params_var, &bytes).unwrap();

		// Creating the leaf and checking the membership inside the tree
		let vanchor_leaf = LG::create_leaf(
			&leaf_private_var,
			&leaf_public_var,
			&hasher_params_var,
		)?;
		let vanchor_nullifier = LG::create_nullifier(
			&leaf_private_var,
			&vanchor_leaf,
			&hasher_params_var,
			&index_var,
		)?;
		// Check if target root is in set
		// Constraining arbitrary inputs
		AG::constrain(&arbitrary_input_var)?;

		// Enforcing constraints
		vanchor_nullifier.enforce_equal(&nullifier_hash_var)?;

		Ok(())
	}
}

#[cfg(feature = "default_poseidon")]
#[cfg(test)]
mod test {
	use super::*;
	use crate::setup::{bridge::*, common::*}; // TODO: Create a setup for Vanchor
	use ark_bls12_381::{Bls12_381, Fr as BlsFr};
	use ark_ff::UniformRand;
	use ark_groth16::Groth16;
	use ark_snark::SNARK;
	use ark_std::test_rng;

	// merkle proof path legth
	// TreeConfig_x5, x7 HEIGHT is hardcoded to 30
	pub const TEST_N: usize = 30;
	pub const TEST_M: usize = 2;

	#[test]
	fn setup_and_prove_vanchor_groth16() {
		let rng = &mut test_rng();
		let curve = Curve::Bls381;
		let (circuit, .., public_inputs) =
			setup_random_circuit_x5::<_, BlsFr, TEST_N, TEST_M>(rng, curve);

		let (pk, vk) =
			setup_groth16_circuit_x5::<_, Bls12_381, TEST_N, TEST_M>(rng, circuit.clone());
		let proof = prove_groth16_circuit_x5::<_, Bls12_381, TEST_N, TEST_M>(&pk, circuit, rng);

		let res = verify_groth16::<Bls12_381>(&vk, &public_inputs, &proof);
		assert!(res);
	}

	#[should_panic]
	#[test]
	fn should_fail_with_invalid_public_inputs() {
		let rng = &mut test_rng();
		let curve = Curve::Bls381;
		let (circuit, .., public_inputs) =
			setup_random_circuit_x5::<_, BlsFr, TEST_N, TEST_M>(rng, curve);

		type GrothSetup = Groth16<Bls12_381>;

		let (pk, vk) = GrothSetup::circuit_specific_setup(circuit.clone(), rng).unwrap();
		let proof = GrothSetup::prove(&pk, circuit, rng).unwrap();

		// Without chain_id and nullifier
		let pi = public_inputs[2..].to_vec();
		let res = GrothSetup::verify(&vk, &pi, &proof).unwrap();
		assert!(res);
	}

	#[should_panic]
	#[test]
	fn should_fail_with_invalid_root() {
		let rng = &mut test_rng();
		let curve = Curve::Bls381;
		let params5 = setup_params_x5_5(curve);
		let chain_id = BlsFr::rand(rng);
		let relayer = BlsFr::rand(rng);
		let recipient = BlsFr::rand(rng);
		let fee = BlsFr::rand(rng);
		let refund = BlsFr::rand(rng);
		let commitment = BlsFr::rand(rng);
		let (leaf_private, leaf_public, leaf, nullifier_hash) =
			setup_leaf_x5(chain_id, &params5, rng);

		let arbitrary_input = setup_arbitrary_data(recipient, relayer, fee, refund, commitment);
		let params3 = setup_params_x5_3(curve);
		let (_, path) = setup_tree_and_create_path_tree_x5(&[leaf], 0, &params3);
		let root = BlsFr::rand(rng);
		let roots = [root; TEST_M];
		let set_private_inputs = setup_set(&root, &roots);

		let circuit = Circuit_x5::new(
			arbitrary_input.clone(),
			leaf_private,
			leaf_public,
			set_private_inputs,
			roots,
			params5,
			path,
			root,
			nullifier_hash,
		);

		let mut public_inputs = Vec::new();
		public_inputs.push(chain_id);
		public_inputs.push(nullifier_hash);
		public_inputs.extend(&roots);
		public_inputs.push(root);
		public_inputs.push(arbitrary_input.recipient);
		public_inputs.push(arbitrary_input.relayer);
		public_inputs.push(arbitrary_input.fee);
		public_inputs.push(arbitrary_input.commitment);
		let (pk, vk) =
			setup_groth16_circuit_x5::<_, Bls12_381, TEST_N, TEST_M>(rng, circuit.clone());
		let proof = prove_groth16_circuit_x5::<_, Bls12_381, TEST_N, TEST_M>(&pk, circuit, rng);
		let res = verify_groth16::<Bls12_381>(&vk, &public_inputs, &proof);
		assert!(res);
	}

	#[should_panic]
	#[test]
	fn should_fail_with_invalid_set() {
		let rng = &mut test_rng();
		let curve = Curve::Bls381;
		let params5 = setup_params_x5_5(curve);
		let chain_id = BlsFr::rand(rng);
		let relayer = BlsFr::rand(rng);
		let recipient = BlsFr::rand(rng);
		let fee = BlsFr::rand(rng);
		let refund = BlsFr::rand(rng);
		let commitment = BlsFr::rand(rng);
		let (leaf_private, leaf_public, leaf, nullifier_hash) =
			setup_leaf_x5(chain_id, &params5, rng);

		let arbitrary_input = setup_arbitrary_data(recipient, relayer, fee, refund, commitment);
		let params3 = setup_params_x5_3(curve);
		let (_, path) = setup_tree_and_create_path_tree_x5(&[leaf], 0, &params3);
		let root = BlsFr::rand(rng);
		let mut roots = [BlsFr::rand(rng); TEST_M];
		roots[0] = root;
		let set_private_inputs = setup_set(&root, &roots);

		let circuit = Circuit_x5::new(
			arbitrary_input.clone(),
			leaf_private,
			leaf_public,
			set_private_inputs,
			roots.clone(),
			params5,
			path,
			root,
			nullifier_hash,
		);

		let mut public_inputs = Vec::new();
		public_inputs.push(chain_id);
		public_inputs.push(nullifier_hash);
		public_inputs.extend(&roots);
		public_inputs.push(root);
		public_inputs.push(arbitrary_input.recipient);
		public_inputs.push(arbitrary_input.relayer);
		public_inputs.push(arbitrary_input.fee);
		public_inputs.push(arbitrary_input.commitment);
		let (pk, vk) =
			setup_groth16_circuit_x5::<_, Bls12_381, TEST_N, TEST_M>(rng, circuit.clone());
		let proof = prove_groth16_circuit_x5::<_, Bls12_381, TEST_N, TEST_M>(&pk, circuit, rng);
		let res = verify_groth16::<Bls12_381>(&vk, &public_inputs, &proof);
		assert!(res);
	}

	#[should_panic]
	#[test]
	fn should_fail_with_invalid_leaf() {
		let rng = &mut test_rng();
		let curve = Curve::Bls381;
		let params5 = setup_params_x5_5(curve);
		let chain_id = BlsFr::rand(rng);
		let relayer = BlsFr::rand(rng);
		let recipient = BlsFr::rand(rng);
		let fee = BlsFr::rand(rng);
		let refund = BlsFr::rand(rng);
		let commitment = BlsFr::rand(rng);
		let (leaf_private, leaf_public, _, nullifier_hash) = setup_leaf_x5(chain_id, &params5, rng);
		let leaf = BlsFr::rand(rng);
		let arbitrary_input = setup_arbitrary_data(recipient, relayer, fee, refund, commitment);
		let params3 = setup_params_x5_3(curve);
		let (_, path) = setup_tree_and_create_path_tree_x5(&[leaf], 0, &params3);
		let root = BlsFr::rand(rng);
		let mut roots = [BlsFr::rand(rng); TEST_M];
		roots[0] = root;
		let set_private_inputs = setup_set(&root, &roots);

		let circuit = Circuit_x5::new(
			arbitrary_input.clone(),
			leaf_private,
			leaf_public,
			set_private_inputs,
			roots.clone(),
			params5,
			path,
			root,
			nullifier_hash,
		);

		let mut public_inputs = Vec::new();
		public_inputs.push(chain_id);
		public_inputs.push(nullifier_hash);
		public_inputs.extend(&roots);
		public_inputs.push(root);
		public_inputs.push(arbitrary_input.recipient);
		public_inputs.push(arbitrary_input.relayer);
		public_inputs.push(arbitrary_input.fee);
		public_inputs.push(arbitrary_input.commitment);
		let (pk, vk) =
			setup_groth16_circuit_x5::<_, Bls12_381, TEST_N, TEST_M>(rng, circuit.clone());
		let proof = prove_groth16_circuit_x5::<_, Bls12_381, TEST_N, TEST_M>(&pk, circuit, rng);
		let res = verify_groth16::<Bls12_381>(&vk, &public_inputs, &proof);
		assert!(res);
	}

	#[should_panic]
	#[test]
	fn should_fail_with_invalid_nullifier() {
		let rng = &mut test_rng();
		let curve = Curve::Bls381;
		let params5 = setup_params_x5_5(curve);
		let chain_id = BlsFr::rand(rng);
		let relayer = BlsFr::rand(rng);
		let recipient = BlsFr::rand(rng);
		let fee = BlsFr::rand(rng);
		let refund = BlsFr::rand(rng);
		let commitment = BlsFr::rand(rng);
		let (leaf_private, leaf_public, leaf, _) = setup_leaf_x5(chain_id, &params5, rng);
		let nullifier_hash = BlsFr::rand(rng);
		let arbitrary_input = setup_arbitrary_data(recipient, relayer, fee, refund, commitment);
		let params3 = setup_params_x5_3(curve);
		let (_, path) = setup_tree_and_create_path_tree_x5(&[leaf], 0, &params3);
		let root = BlsFr::rand(rng);
		let mut roots = [BlsFr::rand(rng); TEST_M];
		roots[0] = root;
		let set_private_inputs = setup_set(&root, &roots);

		let circuit = Circuit_x5::new(
			arbitrary_input.clone(),
			leaf_private,
			leaf_public,
			set_private_inputs,
			roots.clone(),
			params5,
			path,
			root,
			nullifier_hash,
		);

		let mut public_inputs = Vec::new();
		public_inputs.push(chain_id);
		public_inputs.push(nullifier_hash);
		public_inputs.extend(&roots);
		public_inputs.push(root);
		public_inputs.push(arbitrary_input.recipient);
		public_inputs.push(arbitrary_input.relayer);
		public_inputs.push(arbitrary_input.fee);
		public_inputs.push(arbitrary_input.commitment);
		let (pk, vk) =
			setup_groth16_circuit_x5::<_, Bls12_381, TEST_N, TEST_M>(rng, circuit.clone());
		let proof = prove_groth16_circuit_x5::<_, Bls12_381, TEST_N, TEST_M>(&pk, circuit, rng);
		let res = verify_groth16::<Bls12_381>(&vk, &public_inputs, &proof);
		assert!(res);
	}
}
