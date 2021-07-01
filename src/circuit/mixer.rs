use crate::{
	arbitrary::{constraints::ArbitraryGadget, Arbitrary},
	leaf::{constraints::LeafCreationGadget, LeafCreation},
	merkle_tree::{
		constraints::{NodeVar, PathVar},
		Config as MerkleConfig, Path,
	},
};
use ark_crypto_primitives::{crh::CRHGadget, CRH};
use ark_ff::fields::PrimeField;
use ark_r1cs_std::{eq::EqGadget, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::marker::PhantomData;

pub struct MixerCircuit<
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
	L: LeafCreation<H>,
	LG: LeafCreationGadget<F, H, HG, L>,
> {
	arbitrary_input: A::Input,
	leaf_private_inputs: L::Private,
	leaf_public_inputs: L::Public,
	hasher_params: H::Parameters,
	path: Path<C>,
	root: <C::H as CRH>::Output,
	nullifier_hash: L::Nullifier,
	_field: PhantomData<F>,
	_arbitrary_gadget: PhantomData<AG>,
	_hasher: PhantomData<H>,
	_hasher_gadget: PhantomData<HG>,
	_leaf_hasher_gadget: PhantomData<LHGT>,
	_tree_hasher_gadget: PhantomData<HGT>,
	_leaf_creation: PhantomData<L>,
	_leaf_creation_gadget: PhantomData<LG>,
	_merkle_config: PhantomData<C>,
}

impl<F, A, AG, H, HG, C, LHGT, HGT, L, LG> MixerCircuit<F, A, AG, H, HG, C, LHGT, HGT, L, LG>
where
	F: PrimeField,
	A: Arbitrary,
	AG: ArbitraryGadget<F, A>,
	H: CRH,
	HG: CRHGadget<H, F>,
	C: MerkleConfig,
	LHGT: CRHGadget<C::LeafH, F>,
	HGT: CRHGadget<C::H, F>,
	L: LeafCreation<H>,
	LG: LeafCreationGadget<F, H, HG, L>,
{
	pub fn new(
		arbitrary_input: A::Input,
		leaf_private_inputs: L::Private,
		leaf_public_inputs: L::Public,
		hasher_params: H::Parameters,
		path: Path<C>,
		root: <C::H as CRH>::Output,
		nullifier_hash: L::Nullifier,
	) -> Self {
		Self {
			arbitrary_input,
			leaf_private_inputs,
			leaf_public_inputs,
			hasher_params,
			path,
			root,
			nullifier_hash,
			_field: PhantomData,
			_arbitrary_gadget: PhantomData,
			_hasher: PhantomData,
			_hasher_gadget: PhantomData,
			_leaf_hasher_gadget: PhantomData,
			_tree_hasher_gadget: PhantomData,
			_leaf_creation: PhantomData,
			_leaf_creation_gadget: PhantomData,
			_merkle_config: PhantomData,
		}
	}
}

impl<F, A, AG, H, HG, C, LHGT, HGT, L, LG> Clone
	for MixerCircuit<F, A, AG, H, HG, C, LHGT, HGT, L, LG>
where
	F: PrimeField,
	A: Arbitrary,
	AG: ArbitraryGadget<F, A>,
	H: CRH,
	HG: CRHGadget<H, F>,
	C: MerkleConfig,
	LHGT: CRHGadget<C::LeafH, F>,
	HGT: CRHGadget<C::H, F>,
	L: LeafCreation<H>,
	LG: LeafCreationGadget<F, H, HG, L>,
{
	fn clone(&self) -> Self {
		let arbitrary_input = self.arbitrary_input.clone();
		let leaf_private_inputs = self.leaf_private_inputs.clone();
		let leaf_public_inputs = self.leaf_public_inputs.clone();
		let hasher_params = self.hasher_params.clone();
		let path = self.path.clone();
		let root = self.root.clone();
		let nullifier_hash = self.nullifier_hash.clone();
		Self::new(
			arbitrary_input,
			leaf_private_inputs,
			leaf_public_inputs,
			hasher_params,
			path,
			root,
			nullifier_hash,
		)
	}
}

impl<F, A, AG, H, HG, C, LHGT, HGT, L, LG> ConstraintSynthesizer<F>
	for MixerCircuit<F, A, AG, H, HG, C, LHGT, HGT, L, LG>
where
	F: PrimeField,
	A: Arbitrary,
	AG: ArbitraryGadget<F, A>,
	H: CRH,
	HG: CRHGadget<H, F>,
	C: MerkleConfig,
	LHGT: CRHGadget<C::LeafH, F>,
	HGT: CRHGadget<C::H, F>,
	L: LeafCreation<H>,
	LG: LeafCreationGadget<F, H, HG, L>,
{
	fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
		let arbitrary_input = self.arbitrary_input;
		let leaf_private = self.leaf_private_inputs;
		let leaf_public = self.leaf_public_inputs;
		let hasher_params = self.hasher_params;
		let path = self.path;
		let root = self.root;
		let nullifier_hash = self.nullifier_hash;

		// Generating vars
		// Public inputs
		let leaf_public_var = LG::PublicVar::new_input(cs.clone(), || Ok(leaf_public))?;
		let nullifier_hash_var = LG::NullifierVar::new_input(cs.clone(), || Ok(nullifier_hash))?;
		let root_var = HGT::OutputVar::new_input(cs.clone(), || Ok(root))?;
		let arbitrary_input_var = AG::InputVar::new_input(cs.clone(), || Ok(arbitrary_input))?;

		// Constants
		let hasher_params_var = HG::ParametersVar::new_constant(cs.clone(), hasher_params)?;

		// Private inputs
		let leaf_private_var = LG::PrivateVar::new_witness(cs.clone(), || Ok(leaf_private))?;
		let path_var = PathVar::<F, C, HGT, LHGT>::new_witness(cs.clone(), || Ok(path))?;

		// Creating the leaf and checking the membership inside the tree
		let mixer_leaf = LG::create_leaf(&leaf_private_var, &leaf_public_var, &hasher_params_var)?;
		let mixer_nullifier = LG::create_nullifier(&leaf_private_var, &hasher_params_var)?;
		let is_member =
			path_var.check_membership(&NodeVar::Inner(root_var.clone()), &mixer_leaf)?;
		// Constraining arbitrary inputs
		AG::constrain(&arbitrary_input_var)?;

		// Enforcing constraints
		is_member.enforce_equal(&Boolean::TRUE)?;
		mixer_nullifier.enforce_equal(&nullifier_hash_var)?;

		Ok(())
	}
}

#[cfg(feature = "default_poseidon")]
#[cfg(test)]
mod test {
	use crate::setup::{common::*, mixer::*};
	use ark_bls12_381::{Bls12_381, Fr as BlsFr};
	use ark_crypto_primitives::SNARK;
	use ark_ff::UniformRand;
	use ark_groth16::Groth16;
	use ark_std::test_rng;

	#[test]
	fn setup_and_prove_mixer_groth16() {
		let rng = &mut test_rng();
		let (circuit, .., public_inputs) = setup_random_circuit::<_, BlsFr>(rng);

		let (pk, vk) = setup_groth16::<_, Bls12_381>(rng, circuit.clone());
		let proof = prove_groth16::<_, Bls12_381>(&pk, circuit, rng);

		let res = verify_groth16::<Bls12_381>(&vk, &public_inputs, &proof);
		assert!(res);
	}

	#[should_panic]
	#[test]
	fn should_fail_with_invalid_public_inputs() {
		let rng = &mut test_rng();
		let (circuit, .., public_inputs) = setup_random_circuit(rng);

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
		let params5 = setup_params_5();
		let relayer = BlsFr::rand(rng);
		let recipient = BlsFr::rand(rng);
		let (leaf_private, leaf, nullifier_hash) = setup_leaf(&params5, rng);

		let arbitrary_input = setup_arbitrary_data(recipient, relayer);
		let params3 = setup_params_3();
		let (_, path) = setup_tree_and_create_path(&[leaf], 0, &params3);
		let root = BlsFr::rand(rng);

		let circuit = Circuit::new(
			arbitrary_input.clone(),
			leaf_private,
			(),
			params5,
			path,
			root,
			nullifier_hash,
		);

		let mut public_inputs = Vec::new();
		public_inputs.push(nullifier_hash);
		public_inputs.push(root);
		public_inputs.push(arbitrary_input.recipient);
		public_inputs.push(arbitrary_input.relayer);
		let (pk, vk) = setup_groth16::<_, Bls12_381>(rng, circuit.clone());
		let proof = prove_groth16::<_, Bls12_381>(&pk, circuit, rng);
		let res = verify_groth16::<Bls12_381>(&vk, &public_inputs, &proof);
		assert!(res);
	}

	#[should_panic]
	#[test]
	fn should_fail_with_invalid_leaf() {
		let rng = &mut test_rng();
		let params5 = setup_params_5();
		let relayer = BlsFr::rand(rng);
		let recipient = BlsFr::rand(rng);
		let (leaf_private, _, nullifier_hash) = setup_leaf(&params5, rng);
		let leaf = BlsFr::rand(rng);
		let arbitrary_input = setup_arbitrary_data(recipient, relayer);
		let params3 = setup_params_3();
		let (_, path) = setup_tree_and_create_path(&[leaf], 0, &params3);
		let root = BlsFr::rand(rng);

		let circuit = Circuit::new(
			arbitrary_input.clone(),
			leaf_private,
			(),
			params5,
			path,
			root,
			nullifier_hash,
		);

		let mut public_inputs = Vec::new();
		public_inputs.push(nullifier_hash);
		public_inputs.push(root);
		public_inputs.push(arbitrary_input.recipient);
		public_inputs.push(arbitrary_input.relayer);
		let (pk, vk) = setup_groth16::<_, Bls12_381>(rng, circuit.clone());
		let proof = prove_groth16::<_, Bls12_381>(&pk, circuit, rng);
		let res = verify_groth16::<Bls12_381>(&vk, &public_inputs, &proof);
		assert!(res);
	}

	#[should_panic]
	#[test]
	fn should_fail_with_invalid_nullifier() {
		let rng = &mut test_rng();
		let params5 = setup_params_5();
		let relayer = BlsFr::rand(rng);
		let recipient = BlsFr::rand(rng);
		let (leaf_private, leaf, _) = setup_leaf(&params5, rng);
		let nullifier_hash = BlsFr::rand(rng);
		let arbitrary_input = setup_arbitrary_data(recipient, relayer);
		let params3 = setup_params_3();
		let (_, path) = setup_tree_and_create_path(&[leaf], 0, &params3);
		let root = BlsFr::rand(rng);

		let circuit = Circuit::new(
			arbitrary_input.clone(),
			leaf_private,
			(),
			params5,
			path,
			root,
			nullifier_hash,
		);

		let mut public_inputs = Vec::new();
		public_inputs.push(nullifier_hash);
		public_inputs.push(root);
		public_inputs.push(arbitrary_input.recipient);
		public_inputs.push(arbitrary_input.relayer);
		let (pk, vk) = setup_groth16::<_, Bls12_381>(rng, circuit.clone());
		let proof = prove_groth16::<_, Bls12_381>(&pk, circuit, rng);
		let res = verify_groth16::<Bls12_381>(&vk, &public_inputs, &proof);
		assert!(res);
	}
}
