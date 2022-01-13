use crate::Vec;
use ark_crypto_primitives::{crh::CRHGadget, CRH};
use ark_ff::fields::PrimeField;
use ark_r1cs_std::{eq::EqGadget, fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::marker::PhantomData;
use arkworks_gadgets::{
	arbitrary::anchor_data::{constraints::InputVar as ArbitraryInputVar, Input as ArbitraryInput},
	leaf::anchor::{
		constraints::{
			AnchorLeafGadget, PrivateVar as LeafPrivateInputsVar, PublicVar as LeafPublicInputsVar,
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
};

pub struct AnchorCircuit<
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
	AnchorCircuit<F, H, HG, C, LHGT, HGT, N, M>
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
	for AnchorCircuit<F, H, HG, C, LHGT, HGT, N, M>
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
	for AnchorCircuit<F, H, HG, C, LHGT, HGT, N, M>
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
		let path_var = PathVar::<F, C, HGT, LHGT, N>::new_witness(cs, || Ok(path))?;

		// Creating the leaf and checking the membership inside the tree
		let anchor_leaf = AnchorLeafGadget::<F, H, HG>::create_leaf(
			&leaf_private_var,
			&leaf_public_var,
			&hasher_params_var,
		)?;
		let anchor_nullifier =
			AnchorLeafGadget::<F, H, HG>::create_nullifier(&leaf_private_var, &hasher_params_var)?;
		let is_member =
			path_var.check_membership(&NodeVar::Inner(root_var.clone()), &anchor_leaf)?;
		// Check if target root is in set
		let is_set_member =
			SetMembershipGadget::check(&root_var, &root_set_var, &set_input_private_var)?;
		// Constraining arbitrary inputs
		arbitrary_input_var.constrain()?;

		// Enforcing constraints
		is_member.enforce_equal(&Boolean::TRUE)?;
		is_set_member.enforce_equal(&Boolean::TRUE)?;
		anchor_nullifier.enforce_equal(&nullifier_hash_var)?;

		Ok(())
	}
}

#[cfg(test)]
mod test {
	use crate::setup::{anchor::*, common::*};
	use ark_bn254::{Bn254, Fr as Bn254Fr};
	use ark_ff::UniformRand;
	use ark_groth16::Groth16;
	use ark_snark::SNARK;
	use ark_std::test_rng;
	use arkworks_utils::utils::common::{setup_params_x5_3, setup_params_x5_4, Curve};

	// merkle proof path legth
	// TreeConfig_x5, x7 HEIGHT is hardcoded to 30
	pub const TEST_N: usize = 30;
	pub const TEST_M: usize = 2;
	type AnchorSetup30_2 = AnchorProverSetup<Bn254Fr, TEST_M, TEST_N>;

	#[test]
	fn setup_and_prove_anchor_groth16() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;

		let params3 = setup_params_x5_3::<Bn254Fr>(curve);
		let params4 = setup_params_x5_4::<Bn254Fr>(curve);
		let anchor_setup = AnchorSetup30_2::new(params3, params4);
		let (circuit, .., public_inputs) = anchor_setup.setup_random_circuit(rng).unwrap();

		let (pk, vk) = setup_keys::<Bn254, _, _>(circuit.clone(), rng).unwrap();
		let proof = prove::<Bn254, _, _>(circuit, &pk, rng).unwrap();
		let res = verify::<Bn254>(&public_inputs, &vk, &proof).unwrap();
		assert!(res);
	}

	#[test]
	fn should_fail_with_invalid_public_inputs() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;
		let params3 = setup_params_x5_3::<Bn254Fr>(curve);
		let params4 = setup_params_x5_4::<Bn254Fr>(curve);
		let anchor_setup = AnchorSetup30_2::new(params3, params4);
		let (circuit, .., public_inputs) = anchor_setup.setup_random_circuit(rng).unwrap();

		type GrothSetup = Groth16<Bn254>;

		let (pk, vk) = GrothSetup::circuit_specific_setup(circuit.clone(), rng).unwrap();
		let proof = GrothSetup::prove(&pk, circuit, rng).unwrap();

		// Without chain_id and nullifier
		let pi = public_inputs[2..].to_vec();
		let res = GrothSetup::verify(&vk, &pi, &proof);
		assert!(res.is_err());
	}

	#[test]
	fn should_fail_with_invalid_root() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;
		let params3 = setup_params_x5_3(curve);
		let params4 = setup_params_x5_4(curve);

		let chain_id = Bn254Fr::rand(rng);
		let relayer = Bn254Fr::rand(rng);
		let recipient = Bn254Fr::rand(rng);
		let fee = Bn254Fr::rand(rng);
		let refund = Bn254Fr::rand(rng);
		let commitment = Bn254Fr::rand(rng);

		let prover = AnchorSetup30_2::new(params3, params4.clone());
		let arbitrary_input =
			AnchorSetup30_2::setup_arbitrary_data(recipient, relayer, fee, refund, commitment);
		let (leaf_private, leaf_public, leaf, nullifier_hash) =
			prover.setup_leaf(chain_id, rng).unwrap();
		let leaves = vec![leaf];
		let index = 0;
		let (_, path) = prover.setup_tree_and_path(&leaves, index).unwrap();
		// Invalid root, but set is valid since it contains root
		let root = Bn254Fr::rand(rng);
		let roots_new = [root; TEST_M];
		let set_private_inputs = AnchorSetup30_2::setup_set(&root, &roots_new).unwrap();

		let mc = Circuit_x5::new(
			arbitrary_input.clone(),
			leaf_private,
			leaf_public,
			set_private_inputs,
			roots_new,
			params4,
			path,
			root.clone(),
			nullifier_hash,
		);
		let public_inputs = AnchorSetup30_2::construct_public_inputs(
			chain_id,
			nullifier_hash,
			roots_new,
			root,
			recipient,
			relayer,
			fee,
			refund,
			commitment,
		);

		let (pk, vk) = setup_keys::<Bn254, _, _>(mc.clone(), rng).unwrap();
		let proof = prove::<Bn254, _, _>(mc, &pk, rng).unwrap();
		let res = verify::<Bn254>(&public_inputs, &vk, &proof).unwrap();
		assert!(!res);
	}

	#[test]
	fn should_fail_with_invalid_set() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;
		let params3 = setup_params_x5_3(curve);
		let params4 = setup_params_x5_4(curve);

		let chain_id = Bn254Fr::rand(rng);
		let relayer = Bn254Fr::rand(rng);
		let recipient = Bn254Fr::rand(rng);
		let fee = Bn254Fr::rand(rng);
		let refund = Bn254Fr::rand(rng);
		let commitment = Bn254Fr::rand(rng);

		let prover = AnchorSetup30_2::new(params3, params4.clone());
		let arbitrary_input =
			AnchorSetup30_2::setup_arbitrary_data(recipient, relayer, fee, refund, commitment);
		let (leaf_private, leaf_public, leaf, nullifier_hash) =
			prover.setup_leaf(chain_id, rng).unwrap();
		let leaves = vec![leaf];
		let index = 0;
		let (tree, path) = prover.setup_tree_and_path(&leaves, index).unwrap();
		let root = tree.root().inner();
		// Invalid set
		let roots_new = [Bn254Fr::rand(rng); TEST_M];
		let set_private_inputs = AnchorSetup30_2::setup_set(&root, &roots_new).unwrap();

		let mc = Circuit_x5::new(
			arbitrary_input.clone(),
			leaf_private,
			leaf_public,
			set_private_inputs,
			roots_new,
			params4,
			path,
			root.clone(),
			nullifier_hash,
		);
		let public_inputs = AnchorSetup30_2::construct_public_inputs(
			chain_id,
			nullifier_hash,
			roots_new,
			root,
			recipient,
			relayer,
			fee,
			refund,
			commitment,
		);

		let (pk, vk) = setup_keys::<Bn254, _, _>(mc.clone(), rng).unwrap();
		let proof = prove::<Bn254, _, _>(mc, &pk, rng).unwrap();
		let res = verify::<Bn254>(&public_inputs, &vk, &proof).unwrap();
		assert!(!res);
	}

	#[test]
	fn should_fail_with_invalid_leaf() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;
		let params3 = setup_params_x5_3(curve);
		let params4 = setup_params_x5_4(curve);

		let chain_id = Bn254Fr::rand(rng);
		let relayer = Bn254Fr::rand(rng);
		let recipient = Bn254Fr::rand(rng);
		let fee = Bn254Fr::rand(rng);
		let refund = Bn254Fr::rand(rng);
		let commitment = Bn254Fr::rand(rng);

		let prover = AnchorSetup30_2::new(params3, params4.clone());
		let arbitrary_input =
			AnchorSetup30_2::setup_arbitrary_data(recipient, relayer, fee, refund, commitment);
		let (leaf_private, leaf_public, _, nullifier_hash) =
			prover.setup_leaf(chain_id, rng).unwrap();
		let leaf = Bn254Fr::rand(rng);
		let leaves = vec![leaf];
		let index = 0;
		let (tree, path) = prover.setup_tree_and_path(&leaves, index).unwrap();
		let root = tree.root().inner();
		// Invalid set
		let roots_new = [Bn254Fr::rand(rng); TEST_M];
		let set_private_inputs = AnchorSetup30_2::setup_set(&root, &roots_new).unwrap();

		let mc = Circuit_x5::new(
			arbitrary_input.clone(),
			leaf_private,
			leaf_public,
			set_private_inputs,
			roots_new,
			params4,
			path,
			root.clone(),
			nullifier_hash,
		);
		let public_inputs = AnchorSetup30_2::construct_public_inputs(
			chain_id,
			nullifier_hash,
			roots_new,
			root,
			recipient,
			relayer,
			fee,
			refund,
			commitment,
		);

		let (pk, vk) = setup_keys::<Bn254, _, _>(mc.clone(), rng).unwrap();
		let proof = prove::<Bn254, _, _>(mc, &pk, rng).unwrap();
		let res = verify::<Bn254>(&public_inputs, &vk, &proof).unwrap();
		assert!(!res);
	}

	#[test]
	fn should_fail_with_invalid_nullifier_hash() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;
		let params3 = setup_params_x5_3(curve);
		let params4 = setup_params_x5_4(curve);

		let chain_id = Bn254Fr::rand(rng);
		let relayer = Bn254Fr::rand(rng);
		let recipient = Bn254Fr::rand(rng);
		let fee = Bn254Fr::rand(rng);
		let refund = Bn254Fr::rand(rng);
		let commitment = Bn254Fr::rand(rng);

		let prover = AnchorSetup30_2::new(params3, params4.clone());
		let arbitrary_input =
			AnchorSetup30_2::setup_arbitrary_data(recipient, relayer, fee, refund, commitment);
		let (leaf_private, leaf_public, leaf, _) = prover.setup_leaf(chain_id, rng).unwrap();
		let nullifier_hash = Bn254Fr::rand(rng);
		let leaves = vec![leaf];
		let index = 0;
		let (tree, path) = prover.setup_tree_and_path(&leaves, index).unwrap();
		let root = tree.root().inner();
		// Invalid set
		let roots_new = [Bn254Fr::rand(rng); TEST_M];
		let set_private_inputs = AnchorSetup30_2::setup_set(&root, &roots_new).unwrap();

		let mc = Circuit_x5::new(
			arbitrary_input.clone(),
			leaf_private,
			leaf_public,
			set_private_inputs,
			roots_new,
			params4,
			path,
			root.clone(),
			nullifier_hash,
		);
		let public_inputs = AnchorSetup30_2::construct_public_inputs(
			chain_id,
			nullifier_hash,
			roots_new,
			root,
			recipient,
			relayer,
			fee,
			refund,
			commitment,
		);

		let (pk, vk) = setup_keys::<Bn254, _, _>(mc.clone(), rng).unwrap();
		let proof = prove::<Bn254, _, _>(mc, &pk, rng).unwrap();
		let res = verify::<Bn254>(&public_inputs, &vk, &proof).unwrap();
		assert!(!res);
	}
}
