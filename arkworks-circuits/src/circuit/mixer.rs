use ark_crypto_primitives::{crh::constraints::CRHGadget, CRH};
use ark_ff::fields::PrimeField;
use ark_r1cs_std::{eq::EqGadget, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::marker::PhantomData;
use arkworks_gadgets::{
	arbitrary::mixer_data::{constraints::InputVar as ArbitraryInputVar, Input as ArbitraryInput},
	leaf::mixer::{
		constraints::{MixerLeafGadget, PrivateVar as LeafPrivateVar},
		Private as LeafPrivate,
	},
	merkle_tree::{
		constraints::{NodeVar, PathVar},
		Config as MerkleConfig, Path,
	},
};

pub struct MixerCircuit<
	F: PrimeField,
	// Hasher for the leaf creation
	H: CRH,
	HG: CRHGadget<H, F>,
	// Merkle config and hasher gadget for the tree
	C: MerkleConfig,
	LHGT: CRHGadget<C::LeafH, F>,
	HGT: CRHGadget<C::H, F>,
	const N: usize,
> {
	arbitrary_input: ArbitraryInput<F>,
	leaf_private_inputs: LeafPrivate<F>,
	hasher_params: H::Parameters,
	path: Path<C, N>,
	root: <C::H as CRH>::Output,
	nullifier_hash: H::Output,
	_field: PhantomData<F>,
	_hasher: PhantomData<H>,
	_hasher_gadget: PhantomData<HG>,
	_leaf_hasher_gadget: PhantomData<LHGT>,
	_tree_hasher_gadget: PhantomData<HGT>,
	_merkle_config: PhantomData<C>,
}

impl<F, H, HG, C, LHGT, HGT, const N: usize> MixerCircuit<F, H, HG, C, LHGT, HGT, N>
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
		leaf_private_inputs: LeafPrivate<F>,
		hasher_params: H::Parameters,
		path: Path<C, N>,
		root: <C::H as CRH>::Output,
		nullifier_hash: H::Output,
	) -> Self {
		Self {
			arbitrary_input,
			leaf_private_inputs,
			hasher_params,
			path,
			root,
			nullifier_hash,
			_field: PhantomData,
			_hasher: PhantomData,
			_hasher_gadget: PhantomData,
			_leaf_hasher_gadget: PhantomData,
			_tree_hasher_gadget: PhantomData,
			_merkle_config: PhantomData,
		}
	}
}

impl<F, H, HG, C, LHGT, HGT, const N: usize> Clone for MixerCircuit<F, H, HG, C, LHGT, HGT, N>
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
		let hasher_params = self.hasher_params.clone();
		let path = self.path.clone();
		let root = self.root.clone();
		let nullifier_hash = self.nullifier_hash.clone();
		Self::new(
			arbitrary_input,
			leaf_private_inputs,
			hasher_params,
			path,
			root,
			nullifier_hash,
		)
	}
}

impl<F, H, HG, C, LHGT, HGT, const N: usize> ConstraintSynthesizer<F>
	for MixerCircuit<F, H, HG, C, LHGT, HGT, N>
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
		let hasher_params = self.hasher_params;
		let path = self.path;
		let root = self.root;
		let nullifier_hash = self.nullifier_hash;

		// Generating vars
		// Public inputs
		let nullifier_hash_var = HG::OutputVar::new_input(cs.clone(), || Ok(nullifier_hash))?;
		let root_var = HGT::OutputVar::new_input(cs.clone(), || Ok(root))?;
		let arbitrary_input_var = ArbitraryInputVar::new_input(cs.clone(), || Ok(arbitrary_input))?;

		// Constants
		let hasher_params_var = HG::ParametersVar::new_constant(cs.clone(), hasher_params)?;

		// Private inputs
		let leaf_private_var = LeafPrivateVar::new_witness(cs.clone(), || Ok(leaf_private))?;
		let path_var = PathVar::<F, C, HGT, LHGT, N>::new_witness(cs, || Ok(path))?;

		// Creating the leaf and checking the membership inside the tree
		let mixer_leaf_hash =
			MixerLeafGadget::<F, H, HG>::create_leaf(&leaf_private_var, &hasher_params_var)?;
		let mixer_nullifier_hash =
			MixerLeafGadget::<F, H, HG>::create_nullifier(&leaf_private_var, &hasher_params_var)?;
		let is_member = path_var.check_membership(&NodeVar::Inner(root_var), &mixer_leaf_hash)?;
		// Constraining arbitrary inputs
		arbitrary_input_var.constrain()?;

		// Enforcing constraints
		is_member.enforce_equal(&Boolean::TRUE)?;
		mixer_nullifier_hash.enforce_equal(&nullifier_hash_var)?;

		Ok(())
	}
}

#[cfg(feature = "default_poseidon")]
#[cfg(test)]
mod test {
	use crate::setup::{common::*, mixer::*};
	use ark_bls12_381::{Bls12_381, Fr as BlsFr};
	use ark_bn254::{Bn254, Fr as Bn254Fr};
	use ark_crypto_primitives::SNARK;
	use ark_ff::UniformRand;
	use ark_groth16::Groth16;
	use ark_std::{test_rng, One, Zero};
	use arkworks_utils::utils::common::{
		setup_params_x5_3, setup_params_x5_5, verify_groth16, Curve,
	};

	// merkle proof path legth
	// TreeConfig_x5, x7 HEIGHT is hardcoded to 30
	pub const LEN: usize = 30;

	#[test]
	fn setup_and_prove_mixer_groth16() {
		let rng = &mut test_rng();
		let curve = Curve::Bls381;
		let (circuit, .., public_inputs) = setup_random_circuit_x5::<_, BlsFr, LEN>(rng, curve);

		let (pk, vk) = setup_groth16_circuit_x5::<_, Bls12_381, LEN>(rng, circuit.clone());
		let proof = prove_groth16_circuit_x5::<_, Bls12_381, LEN>(&pk, circuit, rng);

		let res = verify_groth16::<Bls12_381>(&vk, &public_inputs, &proof);
		println!("{}", res);
		assert!(res);
	}

	#[test]
	fn setup_and_prove_random_circom_mixer_groth16() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;
		let (circuit, .., public_inputs) =
			setup_random_circuit_circomx5::<_, Bn254Fr, LEN>(rng, curve);

		let (pk, vk) = setup_groth16_circuit_circomx5::<_, Bn254, LEN>(rng, circuit.clone());
		let proof = prove_groth16_circuit_circomx5::<_, Bn254, LEN>(&pk, circuit, rng);

		let res = verify_groth16::<Bn254>(&vk, &public_inputs, &proof);
		println!("{}", res);
		assert!(res);
	}

	#[test]
	fn setup_and_prove_mixer_circom_groth16() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;

		let leaves = vec![];
		let index = 0;
		let recipient = Bn254Fr::one();
		let relayer = Bn254Fr::zero();
		let fee = Bn254Fr::zero();
		let refund = Bn254Fr::zero();

		let (circuit, .., public_inputs) = setup_circuit_circomx5::<_, Bn254Fr, LEN>(
			&leaves, index, recipient, relayer, fee, refund, rng, curve,
		);

		let (pk, vk) = setup_groth16_circuit_circomx5::<_, Bn254, LEN>(rng, circuit.clone());
		let proof = prove_groth16_circuit_circomx5(&pk, circuit, rng);

		let res = verify_groth16(&vk, &public_inputs, &proof);
		assert!(
			res,
			"Failed to verify Circom Proof, here is the inputs:
			recipient = {},
			relayer = {},
			fee = {},
			refund = {},
			public_inputs = {:?},
			proof = {:?},
			",
			recipient, relayer, fee, refund, public_inputs, proof
		);
	}

	#[should_panic]
	#[test]
	fn should_fail_with_invalid_public_inputs() {
		let rng = &mut test_rng();
		let curve = Curve::Bls381;
		let (circuit, .., public_inputs) = setup_random_circuit_x5::<_, BlsFr, LEN>(rng, curve);

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
		let relayer = BlsFr::rand(rng);
		let recipient = BlsFr::rand(rng);
		let fee = BlsFr::from(0);
		let refund = BlsFr::from(0);
		let (leaf_private, leaf, nullifier_hash) = setup_leaf_x5(&params5, rng);

		let arbitrary_input = setup_arbitrary_data(recipient, relayer, fee, refund);
		let params3 = setup_params_x5_3(curve);
		let (_, path) = setup_tree_and_create_path_tree_x5(&[leaf], 0, &params3);
		let root = BlsFr::rand(rng);

		let circuit = Circuit_x5::new(
			arbitrary_input.clone(),
			leaf_private,
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
		let (pk, vk) = setup_groth16_circuit_x5::<_, Bls12_381, LEN>(rng, circuit.clone());
		let proof = prove_groth16_circuit_x5::<_, Bls12_381, LEN>(&pk, circuit, rng);
		let res = verify_groth16::<Bls12_381>(&vk, &public_inputs, &proof);
		assert!(res);
	}

	#[should_panic]
	#[test]
	fn should_fail_with_invalid_leaf() {
		let rng = &mut test_rng();
		let curve = Curve::Bls381;
		let params5 = setup_params_x5_5(curve);
		let relayer = BlsFr::rand(rng);
		let recipient = BlsFr::rand(rng);
		let fee = BlsFr::from(0);
		let refund = BlsFr::from(0);
		let (leaf_private, _, nullifier_hash) = setup_leaf_x5(&params5, rng);
		let leaf = BlsFr::rand(rng);
		let arbitrary_input = setup_arbitrary_data(recipient, relayer, fee, refund);
		let params3 = setup_params_x5_3(curve);
		let (_, path) = setup_tree_and_create_path_tree_x5(&[leaf], 0, &params3);
		let root = BlsFr::rand(rng);

		let circuit = Circuit_x5::new(
			arbitrary_input.clone(),
			leaf_private,
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
		let (pk, vk) = setup_groth16_circuit_x5::<_, Bls12_381, LEN>(rng, circuit.clone());
		let proof = prove_groth16_circuit_x5::<_, Bls12_381, LEN>(&pk, circuit, rng);
		let res = verify_groth16::<Bls12_381>(&vk, &public_inputs, &proof);
		assert!(res);
	}

	#[should_panic]
	#[test]
	fn should_fail_with_invalid_nullifier() {
		let rng = &mut test_rng();
		let curve = Curve::Bls381;
		let params5 = setup_params_x5_5(curve);
		let relayer = BlsFr::rand(rng);
		let recipient = BlsFr::rand(rng);
		let fee = BlsFr::from(0);
		let refund = BlsFr::from(0);
		let (leaf_private, leaf, _) = setup_leaf_x5(&params5, rng);
		let nullifier_hash = BlsFr::rand(rng);
		let arbitrary_input = setup_arbitrary_data(recipient, relayer, fee, refund);
		let params3 = setup_params_x5_3(curve);
		let (_, path) = setup_tree_and_create_path_tree_x5(&[leaf], 0, &params3);
		let root = BlsFr::rand(rng);

		let circuit = Circuit_x5::new(
			arbitrary_input.clone(),
			leaf_private,
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
		let (pk, vk) = setup_groth16_circuit_x5::<_, Bls12_381, LEN>(rng, circuit.clone());
		let proof = prove_groth16_circuit_x5::<_, Bls12_381, LEN>(&pk, circuit, rng);
		let res = verify_groth16::<Bls12_381>(&vk, &public_inputs, &proof);
		assert!(res);
	}
}
