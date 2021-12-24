use super::common::*;
use crate::circuit::mixer::MixerCircuit;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rc::Rc;
use arkworks_gadgets::{
	arbitrary::mixer_data::Input as MixerDataInput,
	leaf::mixer::{constraints::MixerLeafGadget, MixerLeaf, Private as LeafPrivate},
	merkle_tree::Path,
};
use arkworks_utils::{poseidon::PoseidonParameters, utils::common::verify_groth16};

use ark_crypto_primitives::SNARK;
use ark_ec::PairingEngine;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_std::{
	rand::{CryptoRng, Rng, RngCore},
	vec::Vec,
};

pub type MixerConstraintDataInput<F> = MixerDataInput<F>;

pub type Leaf_x5<F> = MixerLeaf<F, PoseidonCRH_x5_5<F>>;

pub type LeafGadget_x5<F> = MixerLeafGadget<F, PoseidonCRH_x5_5<F>, PoseidonCRH_x5_5Gadget<F>>;

pub type Circuit_x5<F, const N: usize> = MixerCircuit<
	F,
	PoseidonCRH_x5_5<F>,
	PoseidonCRH_x5_5Gadget<F>,
	TreeConfig_x5<F>,
	LeafCRHGadget<F>,
	PoseidonCRH_x5_3Gadget<F>,
	N,
>;

pub type Leaf_x17<F> = MixerLeaf<F, PoseidonCRH_x17_5<F>>;
pub type LeafGadget_x17<F> = MixerLeafGadget<F, PoseidonCRH_x17_5<F>, PoseidonCRH_x17_5Gadget<F>>;

pub type Circuit_x17<F, const N: usize> = MixerCircuit<
	F,
	PoseidonCRH_x17_5<F>,
	PoseidonCRH_x17_5Gadget<F>,
	TreeConfig_x17<F>,
	LeafCRHGadget<F>,
	PoseidonCRH_x17_3Gadget<F>,
	N,
>;

pub type Leaf_MiMC220<F> = MixerLeaf<F, MiMCCRH_220<F>>;
pub type LeafGadget_MiMC220<F> = MixerLeafGadget<F, MiMCCRH_220<F>, MiMCCRH_220Gadget<F>>;

pub type Circuit_MiMC220<F, const N: usize> = MixerCircuit<
	F,
	MiMCCRH_220<F>,
	MiMCCRH_220Gadget<F>,
	TreeConfig_MiMC220<F>,
	LeafCRHGadget<F>,
	MiMCCRH_220Gadget<F>,
	N,
>;

pub fn setup_leaf_with_privates_raw<F: PrimeField, R: RngCore>(
	params5: &PoseidonParameters<F>,
	rng: &mut R,
) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
	// Secret inputs for the leaf
	let leaf_private = LeafPrivate::generate(rng);

	let leaf_hash = Leaf_x5::create_leaf(&leaf_private, &params5).unwrap();
	let nullifier_hash = Leaf_x5::create_nullifier(&leaf_private, &params5).unwrap();

	let secret_bytes = leaf_private.secret().into_repr().to_bytes_le();
	let nullifier_bytes = leaf_private.nullifier().into_repr().to_bytes_le();

	let leaf_bytes = leaf_hash.into_repr().to_bytes_le();
	let nullifier_hash_bytes = nullifier_hash.into_repr().to_bytes_le();
	(
		secret_bytes,
		nullifier_bytes,
		leaf_bytes,
		nullifier_hash_bytes,
	)
}

pub struct MixerProverSetup<F: PrimeField, const N: usize> {
	params3: PoseidonParameters<F>,
	params5: PoseidonParameters<F>,
}

impl<F: PrimeField, const N: usize> MixerProverSetup<F, N> {
	pub fn new(params3: PoseidonParameters<F>, params5: PoseidonParameters<F>) -> Self {
		Self { params3, params5 }
	}

	pub fn setup_arbitrary_data(
		recipient: F,
		relayer: F,
		fee: F,
		refund: F,
	) -> MixerConstraintDataInput<F> {
		MixerConstraintDataInput::new(recipient, relayer, fee, refund)
	}

	pub fn construct_public_inputs(
		nullifier_hash: F,
		root: F,
		recipient: F,
		relayer: F,
		fee: F,
		refund: F,
	) -> Vec<F> {
		vec![nullifier_hash, root, recipient, relayer, fee, refund]
	}

	pub fn deconstruct_public_inputs(
		public_inputs: &[F],
	) -> (
		F, // nullifier hash
		F, // root
		F, // recipient
		F, // relayer
		F, // fee
		F, // refund
	) {
		(
			public_inputs[0],
			public_inputs[1],
			public_inputs[2],
			public_inputs[3],
			public_inputs[4],
			public_inputs[6],
		)
	}

	pub fn setup_leaf<R: Rng>(&self, rng: &mut R) -> (LeafPrivate<F>, F, F) {
		// Secret inputs for the leaf
		let leaf_private = LeafPrivate::generate(rng);

		// Creating the leaf
		let leaf_hash = Leaf_x5::create_leaf(&leaf_private, &self.params5).unwrap();
		let nullifier_hash = Leaf_x5::create_nullifier(&leaf_private, &self.params5).unwrap();
		(leaf_private, leaf_hash, nullifier_hash)
	}

	pub fn setup_leaf_with_privates(&self, secret: F, nullfier: F) -> (LeafPrivate<F>, F, F) {
		// Secret inputs for the leaf
		let leaf_private = LeafPrivate::new(secret, nullfier);

		// Creating the leaf
		let leaf_hash = Leaf_x5::create_leaf(&leaf_private, &self.params5).unwrap();
		let nullifier_hash = Leaf_x5::create_nullifier(&leaf_private, &self.params5).unwrap();
		(leaf_private, leaf_hash, nullifier_hash)
	}

	pub fn setup_leaf_with_privates_raw(
		&self,
		secret: Vec<u8>,
		nullfier: Vec<u8>,
	) -> (LeafPrivate<F>, F, F) {
		// Secret inputs for the leaf
		let secret_f = F::from_le_bytes_mod_order(&secret);
		let nullifier_f = F::from_le_bytes_mod_order(&nullfier);

		self.setup_leaf_with_privates(secret_f, nullifier_f)
	}

	#[allow(clippy::too_many_arguments)]
	pub fn setup_circuit<R: Rng>(
		self,
		leaves: &[F],
		index: u64,
		recipient: F,
		relayer: F,
		fee: F,
		refund: F,
		rng: &mut R,
	) -> (Circuit_x5<F, N>, F, F, F, Vec<F>) {
		let arbitrary_input = Self::setup_arbitrary_data(recipient, relayer, fee, refund);
		let (leaf_private, leaf, nullifier_hash) = self.setup_leaf(rng);
		let mut leaves_new = leaves.to_vec();
		leaves_new.push(leaf);
		let (tree, path) = self.setup_tree_and_create_path(&leaves_new, index);
		let root = tree.root().inner();

		let mc = Circuit_x5::new(
			arbitrary_input,
			leaf_private,
			self.params5,
			path,
			root,
			nullifier_hash,
		);
		let public_inputs =
			Self::construct_public_inputs(nullifier_hash, root, recipient, relayer, fee, refund);
		(mc, leaf, nullifier_hash, root, public_inputs)
	}

	#[allow(clippy::too_many_arguments)]
	pub fn setup_circuit_with_privates(
		self,
		secret: F,
		nullifier: F,
		leaves: &[F],
		index: u64,
		recipient: F,
		relayer: F,
		fee: F,
		refund: F,
	) -> (Circuit_x5<F, N>, F, F, F, Vec<F>) {
		let arbitrary_input = Self::setup_arbitrary_data(recipient, relayer, fee, refund);
		let (leaf_private, leaf, nullifier_hash) = self.setup_leaf_with_privates(secret, nullifier);
		let mut leaves_new = leaves.to_vec();
		leaves_new.push(leaf);
		let (tree, path) = self.setup_tree_and_create_path(&leaves_new, index);
		let root = tree.root().inner();

		let mc = Circuit_x5::new(
			arbitrary_input,
			leaf_private,
			self.params5,
			path,
			root,
			nullifier_hash,
		);
		let public_inputs =
			Self::construct_public_inputs(nullifier_hash, root, recipient, relayer, fee, refund);
		(mc, leaf, nullifier_hash, root, public_inputs)
	}

	#[allow(clippy::too_many_arguments)]
	pub fn setup_circuit_with_privates_raw(
		self,
		secret: Vec<u8>,
		nullifier: Vec<u8>,
		leaves: &[Vec<u8>],
		index: u64,
		recipient: Vec<u8>,
		relayer: Vec<u8>,
		fee: u128,
		refund: u128,
	) -> (Circuit_x5<F, N>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<Vec<u8>>) {
		let secret_f = F::from_le_bytes_mod_order(&secret);
		let nullifier_f = F::from_le_bytes_mod_order(&nullifier);
		let leaves_f: Vec<F> = leaves
			.iter()
			.map(|x| F::from_le_bytes_mod_order(x))
			.collect();
		let recipient_f = F::from_le_bytes_mod_order(&recipient);
		let relayer_f = F::from_le_bytes_mod_order(&relayer);
		let fee_f = F::from(fee);
		let refund_f = F::from(refund);

		let (mc, leaf, nullifier_hash, root, public_inputs) = self.setup_circuit_with_privates(
			secret_f,
			nullifier_f,
			&leaves_f,
			index,
			recipient_f,
			relayer_f,
			fee_f,
			refund_f,
		);

		let leaf_raw = leaf.into_repr().to_bytes_le();
		let nullifier_hash_raw = nullifier_hash.into_repr().to_bytes_le();
		let root_raw = root.into_repr().to_bytes_le();
		let public_inputs_raw: Vec<Vec<u8>> = public_inputs
			.iter()
			.map(|x| x.into_repr().to_bytes_le())
			.collect();

		(
			mc,
			leaf_raw,
			nullifier_hash_raw,
			root_raw,
			public_inputs_raw,
		)
	}

	pub fn setup_random_circuit<R: Rng>(self, rng: &mut R) -> (Circuit_x5<F, N>, F, F, F, Vec<F>) {
		let leaves = Vec::new();
		let index = 0;
		let recipient = F::rand(rng);
		let relayer = F::rand(rng);
		let fee = F::rand(rng);
		let refund = F::rand(rng);
		self.setup_circuit(&leaves, index, recipient, relayer, fee, refund, rng)
	}

	pub fn create_circuit(
		self,
		arbitrary_input: MixerConstraintDataInput<F>,
		leaf_private: LeafPrivate<F>,
		path: Path<TreeConfig_x5<F>, N>,
		root: F,
		nullifier_hash: F,
	) -> Circuit_x5<F, N> {
		let mc = Circuit_x5::new(
			arbitrary_input,
			leaf_private,
			self.params5,
			path,
			root,
			nullifier_hash,
		);
		mc
	}

	pub fn setup_tree(&self, leaves: &[F]) -> Tree_x5<F> {
		let inner_params = Rc::new(self.params3.clone());
		let mt = Tree_x5::new_sequential(inner_params, Rc::new(()), leaves).unwrap();
		mt
	}

	pub fn setup_tree_and_create_path(
		&self,
		leaves: &[F],
		index: u64,
	) -> (Tree_x5<F>, Path<TreeConfig_x5<F>, N>) {
		// Making the merkle tree
		let mt = self.setup_tree(leaves);
		// Getting the proof path
		let path = mt.generate_membership_proof(index);
		(mt, path)
	}

	pub fn setup_keys<E: PairingEngine, R: RngCore + CryptoRng>(
		circuit: Circuit_x5<E::Fr, N>,
		rng: &mut R,
	) -> (Vec<u8>, Vec<u8>) {
		let (pk, vk) = Groth16::<E>::circuit_specific_setup(circuit, rng).unwrap();

		let mut pk_bytes = Vec::new();
		let mut vk_bytes = Vec::new();
		pk.serialize(&mut pk_bytes).unwrap();
		vk.serialize(&mut vk_bytes).unwrap();
		(pk_bytes, vk_bytes)
	}

	pub fn prove<E: PairingEngine, R: RngCore + CryptoRng>(
		circuit: Circuit_x5<E::Fr, N>,
		pk_bytes: &[u8],
		rng: &mut R,
	) -> Vec<u8> {
		let pk = ProvingKey::<E>::deserialize(pk_bytes).unwrap();

		let proof = Groth16::prove(&pk, circuit, rng).unwrap();
		let mut proof_bytes = Vec::new();
		proof.serialize(&mut proof_bytes).unwrap();
		proof_bytes
	}

	pub fn verify<E: PairingEngine>(public_inputs: &[E::Fr], vk: &[u8], proof: &[u8]) -> bool {
		let vk = VerifyingKey::<E>::deserialize(vk).unwrap();
		let proof = Proof::<E>::deserialize(proof).unwrap();
		let ver_res = verify_groth16(&vk, &public_inputs, &proof);
		ver_res
	}
}
