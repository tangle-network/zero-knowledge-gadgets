use crate::common::{MixerLeaf, MixerProof};
use ark_crypto_primitives::Error;
use ark_ec::PairingEngine;
use ark_ff::{BigInteger, PrimeField};
use ark_std::{
	marker::PhantomData,
	rand::{CryptoRng, RngCore},
	vec::Vec,
	UniformRand,
};
use arkworks_circuits::mixer::MixerCircuit;
use arkworks_gadgets::poseidon::{
	field_hasher::{FieldHasher, Poseidon},
	field_hasher_constraints::PoseidonGadget,
};
use arkworks_utils::utils::common::{setup_params_x5_3, Curve};

use arkworks_gadgets::merkle_tree::simple_merkle::Path;

use crate::common::*;

#[cfg(test)]
mod tests;

use crate::MixerProver;

use super::setup_tree_and_create_path;

pub fn construct_public_inputs<F: PrimeField>(
	nullifier_hash: F,
	root: F,
	arbitrary_input: F,
) -> Vec<F> {
	vec![nullifier_hash, root, arbitrary_input]
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

struct MixerR1CSProver<E: PairingEngine, const HEIGHT: usize> {
	engine: PhantomData<E>,
}

impl<E: PairingEngine, const HEIGHT: usize> MixerR1CSProver<E, HEIGHT> {
	#[allow(dead_code)]
	pub fn setup_random_circuit<R: CryptoRng + RngCore>(
		curve: Curve,
		default_leaf: [u8; 32],
		rng: &mut R,
	) -> Result<
		(
			MixerCircuit<E::Fr, PoseidonGadget<E::Fr>, HEIGHT>,
			E::Fr,
			E::Fr,
			E::Fr,
			Vec<E::Fr>,
		),
		Error,
	> {
		let params3 = setup_params_x5_3(curve);
		let poseidon = Poseidon::<E::Fr>::new(params3.clone());

		let arbitrary_input = E::Fr::rand(rng);
		// Generate the leaf
		let leaf = Self::create_leaf_with_privates(curve, None, None, rng)?;
		let leaf_value = E::Fr::from_le_bytes_mod_order(&leaf.leaf_bytes);

		let secret = E::Fr::from_le_bytes_mod_order(&leaf.secret_bytes);
		let nullifier = E::Fr::from_le_bytes_mod_order(&leaf.nullifier_bytes);

		let nullifier_hash = E::Fr::from_le_bytes_mod_order(&leaf.nullifier_hash_bytes);
		let leaves = vec![E::Fr::from_le_bytes_mod_order(&leaf.leaf_bytes)];
		let (tree, path) = setup_tree_and_create_path::<E::Fr, PoseidonGadget<E::Fr>, HEIGHT>(
			poseidon.clone(),
			&leaves,
			0,
			&default_leaf,
		)?;
		let root = tree.root();

		let mc = MixerCircuit::<E::Fr, PoseidonGadget<E::Fr>, HEIGHT>::new(
			arbitrary_input,
			secret,
			nullifier,
			path,
			root,
			nullifier_hash,
			poseidon,
		);
		let public_inputs = construct_public_inputs(nullifier_hash, root, arbitrary_input);

		Ok((mc, leaf_value, nullifier_hash, root, public_inputs))
	}

	#[allow(dead_code)]
	pub fn setup_circuit_with_privates(
		curve: Curve,
		secret: E::Fr,
		nullifier: E::Fr,
		leaves: &[E::Fr],
		index: u64,
		arbitrary_input: E::Fr,
		default_leaf: [u8; 32],
	) -> Result<
		(
			MixerCircuit<E::Fr, PoseidonGadget<E::Fr>, HEIGHT>,
			E::Fr,
			E::Fr,
			E::Fr,
			Vec<E::Fr>,
		),
		Error,
	> {
		// Initialize hasher
		let params3 = setup_params_x5_3(curve);
		let poseidon = Poseidon::<E::Fr>::new(params3.clone());
		// Setup inputs
		let leaf = poseidon.hash_two(&secret, &nullifier)?;
		let nullifier_hash = poseidon.hash_two(&nullifier, &nullifier)?;
		let (tree, path) = setup_tree_and_create_path::<E::Fr, PoseidonGadget<E::Fr>, HEIGHT>(
			poseidon.clone(),
			&leaves,
			index,
			&default_leaf,
		)?;
		let root = tree.root();

		let mc = MixerCircuit::<E::Fr, PoseidonGadget<E::Fr>, HEIGHT>::new(
			arbitrary_input,
			secret,
			nullifier,
			path,
			root,
			nullifier_hash,
			poseidon,
		);
		let public_inputs = construct_public_inputs(nullifier_hash, root, arbitrary_input);
		Ok((mc, leaf, nullifier_hash, root, public_inputs))
	}

	#[allow(clippy::too_many_arguments)]
	#[allow(dead_code)]
	pub fn setup_circuit_with_privates_raw(
		curve: Curve,
		secret: Vec<u8>,
		nullifier: Vec<u8>,
		leaves: &[Vec<u8>],
		index: u64,
		recipient: Vec<u8>,
		relayer: Vec<u8>,
		fee: u128,
		refund: u128,
		default_leaf: [u8; 32],
	) -> Result<
		(
			MixerCircuit<E::Fr, PoseidonGadget<E::Fr>, HEIGHT>,
			Vec<u8>,
			Vec<u8>,
			Vec<u8>,
			Vec<Vec<u8>>,
		),
		Error,
	> {
		let secret_f = E::Fr::from_le_bytes_mod_order(&secret);
		let nullifier_f = E::Fr::from_le_bytes_mod_order(&nullifier);
		let leaves_f: Vec<E::Fr> = leaves
			.iter()
			.map(|x| E::Fr::from_le_bytes_mod_order(x))
			.collect();

		let mut arbitrary_data_bytes = Vec::new();
		arbitrary_data_bytes.extend(&recipient);
		arbitrary_data_bytes.extend(&relayer);
		arbitrary_data_bytes.extend(fee.to_le_bytes());
		arbitrary_data_bytes.extend(refund.to_le_bytes());
		let arbitrary_data = keccak_256(&arbitrary_data_bytes);
		let arbitrary_input = E::Fr::from_le_bytes_mod_order(&arbitrary_data);

		let (mc, leaf, nullifier_hash, root, public_inputs) = Self::setup_circuit_with_privates(
			curve,
			secret_f,
			nullifier_f,
			&leaves_f,
			index,
			arbitrary_input,
			default_leaf,
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

	#[allow(dead_code)]
	pub fn create_circuit(
		curve: Curve,
		arbitrary_input: E::Fr,
		secret: E::Fr,
		nullifier: E::Fr,
		path: Path<E::Fr, Poseidon<E::Fr>, HEIGHT>,
		root: E::Fr,
		nullifier_hash: E::Fr,
	) -> MixerCircuit<E::Fr, PoseidonGadget<E::Fr>, HEIGHT> {
		// Initialize hasher
		let params3 = setup_params_x5_3(curve);
		let poseidon = Poseidon::<E::Fr>::new(params3.clone());
		// Setup circuit
		let mc = MixerCircuit::new(
			arbitrary_input,
			secret,
			nullifier,
			path,
			root,
			nullifier_hash,
			poseidon,
		);
		mc
	}
}

impl<E: PairingEngine, const HEIGHT: usize> MixerProver<E, HEIGHT> for MixerR1CSProver<E, HEIGHT> {
	fn create_leaf_with_privates<R: RngCore + CryptoRng>(
		curve: Curve,
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

		let params3 = setup_params_x5_3(curve);
		let poseidon = Poseidon::<E::Fr>::new(params3.clone());
		let leaf_field_element = poseidon.hash_two(&secret_field_elt, &nullifier_field_elt)?;
		let nullifier_hash_field_element =
			poseidon.hash_two(&nullifier_field_elt, &nullifier_field_elt)?;
		Ok(MixerLeaf {
			secret_bytes: secret_field_elt.into_repr().to_bytes_le(),
			nullifier_bytes: nullifier_field_elt.into_repr().to_bytes_le(),
			leaf_bytes: leaf_field_element.into_repr().to_bytes_le(),
			nullifier_hash_bytes: nullifier_hash_field_element.into_repr().to_bytes_le(),
		})
	}

	fn create_proof<R: RngCore + CryptoRng>(
		curve: Curve,
		secret: Vec<u8>,
		nullifier: Vec<u8>,
		leaves: Vec<Vec<u8>>,
		index: u64,
		recipient: Vec<u8>,
		relayer: Vec<u8>,
		fee: u128,
		refund: u128,
		pk: Vec<u8>,
		default_leaf: [u8; 32],
		rng: &mut R,
	) -> Result<MixerProof, Error> {
		let params3 = setup_params_x5_3(curve);
		let poseidon = Poseidon::<E::Fr>::new(params3.clone());
		// Get field element version of all the data
		let secret_f = E::Fr::from_le_bytes_mod_order(&secret);
		let nullifier_f = E::Fr::from_le_bytes_mod_order(&nullifier);
		let leaves_f: Vec<E::Fr> = leaves
			.iter()
			.map(|x| E::Fr::from_le_bytes_mod_order(x))
			.collect();

		let mut arbitrary_data_bytes = Vec::new();
		arbitrary_data_bytes.extend(&recipient);
		arbitrary_data_bytes.extend(&relayer);
		arbitrary_data_bytes.extend(fee.to_le_bytes());
		arbitrary_data_bytes.extend(refund.to_le_bytes());
		let arbitrary_data = keccak_256(&arbitrary_data_bytes);
		let arbitrary_input = E::Fr::from_le_bytes_mod_order(&arbitrary_data);
		// Generate the leaf
		let MixerLeaf {
			leaf_bytes,
			nullifier_hash_bytes,
			..
		} = Self::create_leaf_with_privates(curve, Some(secret), Some(nullifier), rng)?;
		// Setup the tree and generate the path
		let (tree, path) = setup_tree_and_create_path::<E::Fr, PoseidonGadget<E::Fr>, HEIGHT>(
			poseidon.clone(),
			&leaves_f,
			index,
			&default_leaf,
		)?;
		let root = tree.root();

		let mc = MixerCircuit::<E::Fr, PoseidonGadget<E::Fr>, HEIGHT>::new(
			arbitrary_input,
			secret_f,
			nullifier_f,
			path,
			root,
			nullifier_f,
			poseidon,
		);
		let public_inputs = construct_public_inputs(nullifier_f, root, arbitrary_input);

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