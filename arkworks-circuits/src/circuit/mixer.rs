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

#[cfg(test)]
mod test {
	use super::LeafPrivate;
	use crate::setup::mixer::*;
	use ark_bn254::{Bn254, Fr as Bn254Fr};
	use ark_ff::{BigInteger, PrimeField, UniformRand};
	use ark_groth16::{Groth16, Proof, VerifyingKey};
	use ark_serialize::CanonicalDeserialize;
	use ark_snark::SNARK;
	use ark_std::{test_rng, vec::Vec, One, Zero};
	use arkworks_utils::utils::common::{setup_params_x5_3, setup_params_x5_5, Curve};

	// merkle proof path legth
	// TreeConfig_x5, x7 HEIGHT is hardcoded to 30
	pub const LEN: usize = 30;
	type MixerProverSetupBn254_30 = MixerProverSetup<Bn254Fr, LEN>;

	#[test]
	fn setup_and_prove_mixer_groth16() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;
		let params3 = setup_params_x5_3::<Bn254Fr>(curve);
		let params5 = setup_params_x5_5::<Bn254Fr>(curve);
		let prover = MixerProverSetupBn254_30::new(params3, params5);
		let (circuit, .., public_inputs) = prover.setup_random_circuit(rng);

		let (pk, vk) = MixerProverSetupBn254_30::setup_keys::<Bn254, _>(circuit.clone(), rng);
		let proof = MixerProverSetupBn254_30::prove::<Bn254, _>(circuit, &pk, rng);
		let res = MixerProverSetupBn254_30::verify::<Bn254>(&public_inputs, &vk, &proof);
		println!("{}", res);
		assert!(res);
	}

	#[test]
	fn setup_and_prove_mixer_groth16_2() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;

		let leaves = vec![Bn254Fr::one()];
		let index = 0;
		let recipient = Bn254Fr::one();
		let relayer = Bn254Fr::zero();
		let fee = Bn254Fr::zero();
		let refund = Bn254Fr::zero();

		let params3 = setup_params_x5_3::<Bn254Fr>(curve);
		let params5 = setup_params_x5_5::<Bn254Fr>(curve);
		let prover = MixerProverSetupBn254_30::new(params3, params5);

		let (circuit, .., public_inputs) =
			prover.setup_circuit(&leaves, index, recipient, relayer, fee, refund, rng);

		let (pk, vk) = MixerProverSetupBn254_30::setup_keys::<Bn254, _>(circuit.clone(), rng);
		let proof = MixerProverSetupBn254_30::prove::<Bn254, _>(circuit, &pk, rng);
		let res = MixerProverSetupBn254_30::verify::<Bn254>(&public_inputs, &vk, &proof);
		assert!(
			res,
			"Failed to verify  Proof, here is the inputs:
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

	#[test]
	fn should_fail_with_invalid_public_inputs() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;

		let leaves = vec![Bn254Fr::one()];
		let index = 0;
		let recipient = Bn254Fr::one();
		let relayer = Bn254Fr::zero();
		let fee = Bn254Fr::zero();
		let refund = Bn254Fr::zero();

		let params3 = setup_params_x5_3::<Bn254Fr>(curve);
		let params5 = setup_params_x5_5::<Bn254Fr>(curve);
		let prover = MixerProverSetupBn254_30::new(params3, params5);

		let (circuit, .., public_inputs) =
			prover.setup_circuit(&leaves, index, recipient, relayer, fee, refund, rng);

		let (pk, vk) = MixerProverSetupBn254_30::setup_keys::<Bn254, _>(circuit.clone(), rng);
		let proof = MixerProverSetupBn254_30::prove::<Bn254, _>(circuit, &pk, rng);

		let vk = VerifyingKey::<Bn254>::deserialize(&vk[..]).unwrap();
		let proof = Proof::<Bn254>::deserialize(&proof[..]).unwrap();

		let pi = &public_inputs[1..];
		let res = Groth16::<Bn254>::verify(&vk, pi, &proof);
		assert!(res.is_err());
	}

	#[test]
	fn should_fail_with_invalid_root() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;

		let recipient = Bn254Fr::one();
		let relayer = Bn254Fr::zero();
		let fee = Bn254Fr::zero();
		let refund = Bn254Fr::zero();

		let params3 = setup_params_x5_3::<Bn254Fr>(curve);
		let params5 = setup_params_x5_5::<Bn254Fr>(curve);
		let prover = MixerProverSetupBn254_30::new(params3, params5);
		let (leaf_private, leaf, nullifier_hash) = prover.setup_leaf(rng);

		let arbitrary_input =
			MixerProverSetupBn254_30::setup_arbitrary_data(recipient, relayer, fee, refund);
		let (_, path) = prover.setup_tree_and_create_path(&[leaf], 0);
		let root = Bn254Fr::rand(rng);

		let circuit = prover.create_circuit(
			arbitrary_input.clone(),
			leaf_private,
			path,
			root,
			nullifier_hash,
		);

		let mut public_inputs = Vec::new();
		public_inputs.push(nullifier_hash);
		public_inputs.push(root);
		public_inputs.push(arbitrary_input.recipient);
		public_inputs.push(arbitrary_input.relayer);
		public_inputs.push(arbitrary_input.fee);
		public_inputs.push(arbitrary_input.refund);

		let (pk, vk) = MixerProverSetupBn254_30::setup_keys::<Bn254, _>(circuit.clone(), rng);
		let proof = MixerProverSetupBn254_30::prove::<Bn254, _>(circuit, &pk, rng);
		let res = MixerProverSetupBn254_30::verify::<Bn254>(&public_inputs, &vk, &proof);

		assert!(!res);
	}

	#[test]
	fn should_fail_with_invalid_leaf() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;

		let recipient = Bn254Fr::one();
		let relayer = Bn254Fr::zero();
		let fee = Bn254Fr::zero();
		let refund = Bn254Fr::zero();

		let params3 = setup_params_x5_3::<Bn254Fr>(curve);
		let params5 = setup_params_x5_5::<Bn254Fr>(curve);
		let prover = MixerProverSetupBn254_30::new(params3, params5);
		let (leaf_private, _, nullifier_hash) = prover.setup_leaf(rng);
		let leaf = Bn254Fr::rand(rng);

		let arbitrary_input =
			MixerProverSetupBn254_30::setup_arbitrary_data(recipient, relayer, fee, refund);
		let (tree, path) = prover.setup_tree_and_create_path(&[leaf], 0);
		let root = tree.root().inner();

		let circuit = prover.create_circuit(
			arbitrary_input.clone(),
			leaf_private,
			path,
			root,
			nullifier_hash,
		);

		let mut public_inputs = Vec::new();
		public_inputs.push(nullifier_hash);
		public_inputs.push(root);
		public_inputs.push(arbitrary_input.recipient);
		public_inputs.push(arbitrary_input.relayer);
		public_inputs.push(arbitrary_input.fee);
		public_inputs.push(arbitrary_input.refund);

		let (pk, vk) = MixerProverSetupBn254_30::setup_keys::<Bn254, _>(circuit.clone(), rng);
		let proof = MixerProverSetupBn254_30::prove::<Bn254, _>(circuit, &pk, rng);
		let res = MixerProverSetupBn254_30::verify::<Bn254>(&public_inputs, &vk, &proof);

		assert!(!res);
	}

	#[test]
	fn should_fail_with_invalid_nullifier() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;

		let recipient = Bn254Fr::one();
		let relayer = Bn254Fr::zero();
		let fee = Bn254Fr::zero();
		let refund = Bn254Fr::zero();

		let params3 = setup_params_x5_3::<Bn254Fr>(curve);
		let params5 = setup_params_x5_5::<Bn254Fr>(curve);
		let prover = MixerProverSetupBn254_30::new(params3, params5);
		let (leaf_private, leaf, nullifier_hash) = prover.setup_leaf(rng);

		// Invalid nullifier
		let leaf_private = LeafPrivate::new(leaf_private.secret(), Bn254Fr::rand(rng));

		let arbitrary_input =
			MixerProverSetupBn254_30::setup_arbitrary_data(recipient, relayer, fee, refund);
		let (tree, path) = prover.setup_tree_and_create_path(&[leaf], 0);
		let root = tree.root().inner();

		let circuit = prover.create_circuit(
			arbitrary_input.clone(),
			leaf_private,
			path,
			root,
			nullifier_hash,
		);

		let mut public_inputs = Vec::new();
		public_inputs.push(nullifier_hash);
		public_inputs.push(root);
		public_inputs.push(arbitrary_input.recipient);
		public_inputs.push(arbitrary_input.relayer);
		public_inputs.push(arbitrary_input.fee);
		public_inputs.push(arbitrary_input.refund);

		let (pk, vk) = MixerProverSetupBn254_30::setup_keys::<Bn254, _>(circuit.clone(), rng);
		let proof = MixerProverSetupBn254_30::prove::<Bn254, _>(circuit, &pk, rng);
		let res = MixerProverSetupBn254_30::verify::<Bn254>(&public_inputs, &vk, &proof);

		assert!(!res);
	}

	#[test]
	fn setup_and_prove_mixer_raw_inputs() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;

		let leaves = vec![Bn254Fr::one()];
		let index = 0;
		let recipient = Bn254Fr::one();
		let relayer = Bn254Fr::zero();
		let secret = Bn254Fr::rand(rng);
		let nullifier = Bn254Fr::rand(rng);

		let leaves_raw: Vec<Vec<u8>> = leaves.iter().map(|x| x.into_repr().to_bytes_le()).collect();
		let recipient_raw = recipient.into_repr().to_bytes_le();
		let relayer_raw = relayer.into_repr().to_bytes_le();
		let fee = 0;
		let refund = 0;
		let secret_raw = secret.into_repr().to_bytes_le();
		let nullifier_raw = nullifier.into_repr().to_bytes_le();

		let params3 = setup_params_x5_3::<Bn254Fr>(curve);
		let params5 = setup_params_x5_5::<Bn254Fr>(curve);
		let prover = MixerProverSetupBn254_30::new(params3, params5);

		let (circuit, .., public_inputs_raw) = prover.setup_circuit_with_privates_raw(
			secret_raw,
			nullifier_raw,
			&leaves_raw,
			index,
			recipient_raw,
			relayer_raw,
			fee,
			refund,
		);

		let public_inputs: Vec<Bn254Fr> = public_inputs_raw
			.iter()
			.map(|x| Bn254Fr::from_le_bytes_mod_order(x))
			.collect();

		let (pk, vk) = MixerProverSetupBn254_30::setup_keys::<Bn254, _>(circuit.clone(), rng);
		let proof = MixerProverSetupBn254_30::prove::<Bn254, _>(circuit, &pk, rng);
		let res = MixerProverSetupBn254_30::verify::<Bn254>(&public_inputs, &vk, &proof);
		assert!(
			res,
			"Failed to verify Proof, here is the inputs:
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
}
