use std::ptr::null;

use crate::common::{MixerLeaf, MixerProof};
use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_crypto_primitives::Error;
use ark_ec::PairingEngine;
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::CanonicalSerializeHashExt;
use ark_std::{
	collections::BTreeMap,
	marker::PhantomData,
	rand::{CryptoRng, Rng, RngCore},
	vec::Vec,
	UniformRand,
};
use arkworks_circuits::circuit::mixer::MixerCircuit;
use arkworks_gadgets::poseidon::{
	constraints::CRHGadget,
	field_hasher::{FieldHasher, Poseidon},
	field_hasher_constraints::{FieldHasherGadget, PoseidonGadget},
	CRH,
};
use arkworks_utils::utils::common::{setup_params_x5_3, setup_params_x5_5, Curve};

use arkworks_gadgets::{
	arbitrary::mixer_data::Input as MixerDataInput,
	identity::{constraints::CRHGadget as IdentityCRHGadget, CRH as IdentityCRH},
	leaf::mixer::Private,
	merkle_tree::simple_merkle::{Path, SparseMerkleTree},
};

use crate::common::prove_unchecked;

#[cfg(test)]
mod tests;

use crate::MixerProver;

use super::{SMT, create_merkle_tree};

pub fn create_leaf<F: PrimeField, H: FieldHasher<F>>(
	hasher: &H,
	private: &Private<F>,
) -> Result<F, Error> {
	let leaf = hasher.hash_two(&private.secret(), &private.nullifier())?;
	Ok(leaf)
}

pub fn create_nullifier<F: PrimeField, H: FieldHasher<F>>(
	hasher: &H,
	private: &Private<F>,
) -> Result<F, Error> {
	let nullifier_hash = hasher.hash_two(&private.nullifier(), &private.nullifier())?;
	Ok(nullifier_hash)
}

pub type MixerConstraintDataInput<F> = MixerDataInput<F>;

pub fn setup_arbitrary_data<F: PrimeField>(
	recipient: F,
	relayer: F,
	fee: F,
	refund: F,
) -> MixerConstraintDataInput<F> {
	MixerConstraintDataInput::new(recipient, relayer, fee, refund)
}

pub fn construct_public_inputs<F: PrimeField>(
	nullifier_hash: F,
	root: F,
	recipient: F,
	relayer: F,
	fee: F,
	refund: F,
) -> Vec<F> {
	vec![nullifier_hash, root, recipient, relayer, fee, refund]
}

pub fn deconstruct_public_inputs<F: PrimeField>(
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

pub type PoseidonMixerCircuit<F, const N: usize> = MixerCircuit<F, PoseidonGadget<F>, N>;

struct MixerR1CSProver<E: PairingEngine, HG: FieldHasherGadget<E::Fr>, const HEIGHT: usize> {
	engine: PhantomData<E>,
	hasher: HG::Native,
	default_leaf: [u8; 32],
}

impl<E: PairingEngine, HG: FieldHasherGadget<E::Fr>, const HEIGHT: usize>
	MixerR1CSProver<E, HG, HEIGHT>
{
	pub fn setup_tree_and_create_path(
		&self,
		leaves: &[E::Fr],
		index: u64,
	) -> Result<
		(
			SMT<E::Fr, HG::Native, HEIGHT>,
			Path<E::Fr, HG::Native, HEIGHT>,
		),
		Error,
	> {
		// Making the merkle tree
		let smt = create_merkle_tree::<E::Fr, HG::Native, HEIGHT>(
			self.hasher.clone(),
			leaves,
			&self.default_leaf,
		);
		// Getting the proof path
		let path = smt.generate_membership_proof(index);
		Ok((smt, path))
	}

	pub fn setup_random_circuit<R: CryptoRng + RngCore>(
		self,
		rng: &mut R,
	) -> Result<
		(
			MixerCircuit<E::Fr, HG, HEIGHT>,
			E::Fr,
			E::Fr,
			E::Fr,
			Vec<E::Fr>,
		),
		Error,
	> {
		let recipient = E::Fr::rand(rng);
		let relayer = E::Fr::rand(rng);
		let fee = E::Fr::rand(rng);
		let refund = E::Fr::rand(rng);
		// Create the arbitrary input data
		let arbitrary_input = setup_arbitrary_data::<E::Fr>(recipient, relayer, fee, refund);
		// Generate the leaf
		let leaf = self.create_leaf_with_privates(None, None, rng)?;
		let leaf_value = E::Fr::from_le_bytes_mod_order(&leaf.leaf_bytes);
		let leaf_private = Private::new(
			E::Fr::from_le_bytes_mod_order(&leaf.secret_bytes),
			E::Fr::from_le_bytes_mod_order(&leaf.nullifier_bytes),
		);
		let nullifier_hash = E::Fr::from_le_bytes_mod_order(&leaf.nullifier_hash_bytes);
		let leaves = vec![E::Fr::from_le_bytes_mod_order(&leaf.leaf_bytes)];
		let (tree, path) = self.setup_tree_and_create_path(&leaves, 0)?;
		let root = tree.root();

		let mc = MixerCircuit::new(
			arbitrary_input,
			leaf_private,
			path,
			root,
			nullifier_hash,
			self.hasher,
		);
		let public_inputs =
			construct_public_inputs(nullifier_hash, root, recipient, relayer, fee, refund);

		Ok((mc, leaf_value, nullifier_hash, root, public_inputs))
	}

	pub fn setup_circuit_with_privates(
		self,
		secret: E::Fr,
		nullifier: E::Fr,
		leaves: &[E::Fr],
		index: u64,
		recipient: E::Fr,
		relayer: E::Fr,
		fee: E::Fr,
		refund: E::Fr,
	) -> Result<(MixerCircuit<E::Fr, HG, HEIGHT>, E::Fr, E::Fr, E::Fr, Vec<E::Fr>), Error> {
		let arbitrary_input = setup_arbitrary_data(recipient, relayer, fee, refund);
		let leaf_private: Private<E::Fr> = Private::new(secret, nullifier);
		let leaf = create_leaf(&self.hasher, &leaf_private)?;
		let nullifier_hash = create_nullifier(&self.hasher, &leaf_private)?;
		let (tree, path) = self.setup_tree_and_create_path(&leaves, index)?;
		let root = tree.root();

		let mc = MixerCircuit::new(
			arbitrary_input,
			leaf_private,
			path,
			root,
			nullifier_hash,
			self.hasher,
		);
		let public_inputs = construct_public_inputs(nullifier_hash, root, recipient, relayer, fee, refund);
		Ok((mc, leaf, nullifier_hash, root, public_inputs))
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
	) -> Result<(MixerCircuit<E::Fr, HG, HEIGHT>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<Vec<u8>>), Error> {
		let secret_f = E::Fr::from_le_bytes_mod_order(&secret);
		let nullifier_f = E::Fr::from_le_bytes_mod_order(&nullifier);
		let leaves_f: Vec<E::Fr> = leaves
			.iter()
			.map(|x| E::Fr::from_le_bytes_mod_order(x))
			.collect();
		let recipient_f = E::Fr::from_le_bytes_mod_order(&recipient);
		let relayer_f = E::Fr::from_le_bytes_mod_order(&relayer);
		let fee_f = E::Fr::from(fee);
		let refund_f = E::Fr::from(refund);

		let (mc, leaf, nullifier_hash, root, public_inputs) = self.setup_circuit_with_privates(
			secret_f,
			nullifier_f,
			&leaves_f,
			index,
			recipient_f,
			relayer_f,
			fee_f,
			refund_f,
		)?;

		let leaf_raw = leaf.into_repr().to_bytes_le();
		let nullifier_hash_raw = nullifier_hash.into_repr().to_bytes_le();
		let root_raw = root.into_repr().to_bytes_le();
		let public_inputs_raw: Vec<Vec<u8>> = public_inputs
			.iter()
			.map(|x| x.into_repr().to_bytes_le())
			.collect();

		Ok((
			mc,
			leaf_raw,
			nullifier_hash_raw,
			root_raw,
			public_inputs_raw,
		))
	}

	pub fn create_circuit(
		self,
		arbitrary_input: MixerConstraintDataInput<E::Fr>,
		leaf_private: Private<E::Fr>,
		path: Path<E::Fr, HG::Native, HEIGHT>,
		root: E::Fr,
		nullifier_hash: E::Fr,
	) -> MixerCircuit<E::Fr, HG, HEIGHT> {
		let mc = MixerCircuit::new(
			arbitrary_input,
			leaf_private,
			path,
			root,
			nullifier_hash,
			self.hasher,
		);
		mc
	}
}

impl<E: PairingEngine, HG: FieldHasherGadget<E::Fr>, const HEIGHT: usize> MixerProver<E, HG, HEIGHT>
	for MixerR1CSProver<E, HG, HEIGHT>
{
	fn create_leaf_with_privates<R: RngCore + CryptoRng>(
		&self,
		secret: Option<Vec<u8>>,
		nullifier: Option<Vec<u8>>,
		rng: &mut R,
	) -> Result<MixerLeaf, Error> {
		let secret_field_elt: E::Fr = match secret {
			Some(secret) => E::Fr::from_le_bytes_mod_order(&secret),
			None => E::Fr::rand(rng),
		};
		let nullifier_field_elt: E::Fr = match nullifier {
			Some(nullifier) => E::Fr::from_le_bytes_mod_order(&nullifier),
			None => E::Fr::rand(rng),
		};

		let private: Private<E::Fr> = Private::new(secret_field_elt, nullifier_field_elt);
		let leaf_field_element = create_leaf(&self.hasher, &private)?;
		let nullifier_hash_field_element = create_nullifier(&self.hasher, &private)?;
		Ok(MixerLeaf {
			secret_bytes: secret_field_elt.into_repr().to_bytes_le(),
			nullifier_bytes: nullifier_field_elt.into_repr().to_bytes_le(),
			leaf_bytes: leaf_field_element.into_repr().to_bytes_le(),
			nullifier_hash_bytes: nullifier_hash_field_element.into_repr().to_bytes_le(),
		})
	}

	fn create_proof<R: RngCore + CryptoRng>(
		&self,
		secret: Vec<u8>,
		nullifier: Vec<u8>,
		leaves: Vec<Vec<u8>>,
		index: u64,
		recipient: Vec<u8>,
		relayer: Vec<u8>,
		fee: u128,
		refund: u128,
		pk: Vec<u8>,
		rng: &mut R,
	) -> Result<MixerProof, Error> {
		// Get field element version of all the data
		let secret_f = E::Fr::from_le_bytes_mod_order(&secret);
		let nullifier_f = E::Fr::from_le_bytes_mod_order(&nullifier);
		let leaves_f: Vec<E::Fr> = leaves
			.iter()
			.map(|x| E::Fr::from_le_bytes_mod_order(x))
			.collect();
		let recipient_f = E::Fr::from_le_bytes_mod_order(&recipient);
		let relayer_f = E::Fr::from_le_bytes_mod_order(&relayer);
		let fee_f = E::Fr::from(fee);
		let refund_f = E::Fr::from(refund);
		// Create the arbitrary input data
		let arbitrary_input =
			setup_arbitrary_data::<E::Fr>(recipient_f, relayer_f, fee_f, refund_f);
		// Generate the leaf
		let MixerLeaf {
			leaf_bytes,
			nullifier_hash_bytes,
			..
		} = self.create_leaf_with_privates(Some(secret), Some(nullifier), rng)?;
		// Setup the tree and generate the path
		let (tree, path) = self.setup_tree_and_create_path(&leaves_f, index)?;
		let root = tree.root();

		let leaf_private = Private::new(secret_f, nullifier_f);
		let mc = MixerCircuit::<E::Fr, HG, HEIGHT>::new(
			arbitrary_input,
			leaf_private,
			path,
			root,
			nullifier_f,
			self.hasher.clone(),
		);
		let public_inputs =
			construct_public_inputs(nullifier_f, root, recipient_f, relayer_f, fee_f, refund_f);

		let leaf_raw = leaf_bytes;
		let nullifier_hash_raw = nullifier_hash_bytes;
		let root_raw = root.into_repr().to_bytes_le();
		let public_inputs_raw: Vec<Vec<u8>> = public_inputs
			.iter()
			.map(|x| x.into_repr().to_bytes_le())
			.collect();

		let proof = prove_unchecked::<E, _, _>(mc, &pk, rng)?;

		Ok(MixerProof {
			leaf_raw,
			nullifier_hash_raw,
			root_raw,
			public_inputs_raw,
			proof,
		})
	}
}
