use crate::{
	arbitrary::bridge_data::{constraints::InputVar as ArbitraryInputVar, Input as ArbitraryInput},
	leaf::bridge::{
		constraints::{
			BridgeLeafGadget, PrivateVar as LeafPrivateInputsVar, PublicVar as LeafPublicInputsVar,
		},
		Private as LeafPrivateInputs, Public as LeafPublicInputs,
	},
	merkle_tree::{
		constraints::{NodeVar, PathVar},
		Config as MerkleConfig, Path,
	},
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
use ark_std::marker::PhantomData;

pub struct BridgeCircuit<
	F: PrimeField,
	// Hasher for the leaf creation
	H: CRH,
	HG: CRHGadget<H, F>,
	// Merkle config and hasher gadget for the tree
	C: MerkleConfig,
	LHGT: CRHGadget<C::LeafH, F>,
	HGT: CRHGadget<C::H, F>,
	const N: usize,
	const M: usize,
> {
	arbitrary_input: ArbitraryInput<F>,
	leaf_private_inputs: LeafPrivateInputs<F>,
	leaf_public_inputs: LeafPublicInputs<F>,
	set_private_inputs: SetPrivateInputs<F, M>,
	root_set: [F; M],
	hasher_params: H::Parameters,
	path: Path<C, N>,
	root: <C::H as CRH>::Output,
	nullifier_hash: H::Output,
	_hasher: PhantomData<H>,
	_hasher_gadget: PhantomData<HG>,
	_leaf_hasher_gadget: PhantomData<LHGT>,
	_tree_hasher_gadget: PhantomData<HGT>,
	_merkle_config: PhantomData<C>,
}

impl<F, H, HG, C, LHGT, HGT, const N: usize, const M: usize>
	BridgeCircuit<F, H, HG, C, LHGT, HGT, N, M>
where
	F: PrimeField,
	H: CRH,
	HG: CRHGadget<H, F>,
	C: MerkleConfig,
	LHGT: CRHGadget<C::LeafH, F>,
	HGT: CRHGadget<C::H, F>,
{
	pub fn new(
		arbitrary_input: ArbitraryInput<F>,
		leaf_private_inputs: LeafPrivateInputs<F>,
		leaf_public_inputs: LeafPublicInputs<F>,
		set_private_inputs: SetPrivateInputs<F, M>,
		root_set: [F; M],
		hasher_params: H::Parameters,
		path: Path<C, N>,
		root: <C::H as CRH>::Output,
		nullifier_hash: H::Output,
	) -> Self {
		Self {
			arbitrary_input,
			leaf_private_inputs,
			leaf_public_inputs,
			set_private_inputs,
			root_set,
			hasher_params,
			path,
			root,
			nullifier_hash,
			_hasher: PhantomData,
			_hasher_gadget: PhantomData,
			_leaf_hasher_gadget: PhantomData,
			_tree_hasher_gadget: PhantomData,
			_merkle_config: PhantomData,
		}
	}
}

impl<F, H, HG, C, LHGT, HGT, const N: usize, const M: usize> Clone
	for BridgeCircuit<F, H, HG, C, LHGT, HGT, N, M>
where
	F: PrimeField,
	H: CRH,
	HG: CRHGadget<H, F>,
	C: MerkleConfig,
	LHGT: CRHGadget<C::LeafH, F>,
	HGT: CRHGadget<C::H, F>,
{
	fn clone(&self) -> Self {
		let arbitrary_input = self.arbitrary_input.clone();
		let leaf_private_inputs = self.leaf_private_inputs.clone();
		let leaf_public_inputs = self.leaf_public_inputs.clone();
		let set_private_inputs = self.set_private_inputs.clone();
		let root_set = self.root_set;
		let hasher_params = self.hasher_params.clone();
		let path = self.path.clone();
		let root = self.root.clone();
		let nullifier_hash = self.nullifier_hash.clone();
		Self::new(
			arbitrary_input,
			leaf_private_inputs,
			leaf_public_inputs,
			set_private_inputs,
			root_set,
			hasher_params,
			path,
			root,
			nullifier_hash,
		)
	}
}

impl<F, H, HG, C, LHGT, HGT, const N: usize, const M: usize> ConstraintSynthesizer<F>
	for BridgeCircuit<F, H, HG, C, LHGT, HGT, N, M>
where
	F: PrimeField,
	H: CRH,
	HG: CRHGadget<H, F>,
	C: MerkleConfig,
	LHGT: CRHGadget<C::LeafH, F>,
	HGT: CRHGadget<C::H, F>,
{
	fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
		let arbitrary_input = self.arbitrary_input;
		let leaf_private = self.leaf_private_inputs;
		let leaf_public = self.leaf_public_inputs;
		let set_private = self.set_private_inputs;
		let root_set = self.root_set;
		let hasher_params = self.hasher_params;
		let path = self.path;
		let root = self.root;
		let nullifier_hash = self.nullifier_hash;

		// Generating vars
		// Public inputs
		let leaf_public_var = LeafPublicInputsVar::new_input(cs.clone(), || Ok(leaf_public))?;
		let nullifier_hash_var = HG::OutputVar::new_input(cs.clone(), || Ok(nullifier_hash))?;
		let root_set_var = Vec::<FpVar<F>>::new_input(cs.clone(), || Ok(root_set))?;
		let root_var = HGT::OutputVar::new_input(cs.clone(), || Ok(root))?;
		let arbitrary_input_var = ArbitraryInputVar::new_input(cs.clone(), || Ok(arbitrary_input))?;

		// Constants
		let hasher_params_var = HG::ParametersVar::new_constant(cs.clone(), hasher_params)?;

		// Private inputs
		let leaf_private_var = LeafPrivateInputsVar::new_witness(cs.clone(), || Ok(leaf_private))?;
		let set_input_private_var =
			SetPrivateInputsVar::new_witness(cs.clone(), || Ok(set_private))?;
		let path_var = PathVar::<F, C, HGT, LHGT, N>::new_witness(cs.clone(), || Ok(path))?;

		let leaf_gadget = BridgeLeafGadget::<F, H, HG>::new(leaf_private_var, leaf_public_var);
		// Creating the leaf and checking the membership inside the tree
		let bridge_leaf = leaf_gadget.create_leaf(&hasher_params_var)?;
		let bridge_nullifier = leaf_gadget.create_nullifier(&hasher_params_var)?;
		let is_member =
			path_var.check_membership(&NodeVar::Inner(root_var.clone()), &bridge_leaf)?;
		// Check if target root is in set
		let is_set_member =
			SetMembershipGadget::check(&root_var, &root_set_var, &set_input_private_var)?;
		// Constraining arbitrary inputs
		arbitrary_input_var.constrain()?;

		// Enforcing constraints
		is_member.enforce_equal(&Boolean::TRUE)?;
		is_set_member.enforce_equal(&Boolean::TRUE)?;
		bridge_nullifier.enforce_equal(&nullifier_hash_var)?;

		Ok(())
	}
}

#[cfg(feature = "default_poseidon")]
#[cfg(test)]
mod test {
	use super::*;
	use crate::setup::{bridge::*, common::*};
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
	fn setup_and_prove_bridge_groth16() {
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
