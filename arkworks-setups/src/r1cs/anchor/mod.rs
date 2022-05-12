use crate::{common::*, AnchorProver};
use ark_crypto_primitives::Error;
use ark_ec::PairingEngine;
use ark_ff::{BigInteger, PrimeField};
use ark_std::{
	marker::PhantomData,
	rand::{CryptoRng, RngCore},
	vec::Vec,
	UniformRand, Zero,
};
use arkworks_native_gadgets::{
	merkle_tree::Path,
	poseidon::{FieldHasher, Poseidon},
};
use arkworks_r1cs_circuits::anchor::AnchorCircuit;
use arkworks_r1cs_gadgets::poseidon::PoseidonGadget;
use arkworks_utils::Curve;
use codec::Encode;
use ark_std::vec;

#[cfg(test)]
mod tests;

pub type PoseidonAnchorCircuit<F, const N: usize, const M: usize> =
	AnchorCircuit<F, PoseidonGadget<F>, N, M>;

pub struct AnchorR1CSProver<E: PairingEngine, const HEIGHT: usize, const ANCHOR_CT: usize> {
	engine: PhantomData<E>,
}

impl<E: PairingEngine, const HEIGHT: usize, const ANCHOR_CT: usize>
	AnchorR1CSProver<E, HEIGHT, ANCHOR_CT>
{
	#[allow(clippy::too_many_arguments)]
	pub fn construct_public_inputs(
		chain_id: E::Fr,
		nullifier_hash: E::Fr,
		roots: [E::Fr; ANCHOR_CT],
		arbitrary_input: E::Fr,
	) -> Vec<E::Fr> {
		let mut pub_ins = vec![nullifier_hash, arbitrary_input, chain_id];
		pub_ins.extend(roots.to_vec());
		pub_ins
	}

	#[allow(dead_code)]
	pub fn setup_random_circuit<R: CryptoRng + RngCore>(
		curve: Curve,
		default_leaf: [u8; 32],
		rng: &mut R,
	) -> Result<
		(
			AnchorCircuit<E::Fr, PoseidonGadget<E::Fr>, HEIGHT, ANCHOR_CT>,
			E::Fr,
			E::Fr,
			Vec<E::Fr>,
			Vec<E::Fr>,
		),
		Error,
	> {
		let arbitrary_input = E::Fr::rand(rng);
		// Initialize hashers
		let params3 = setup_params::<E::Fr>(curve, 5, 3);
		let params4 = setup_params::<E::Fr>(curve, 5, 4);
		let tree_hasher = Poseidon::<E::Fr> { params: params3 };
		let leaf_hasher = Poseidon::<E::Fr> { params: params4 };
		// Create random chain_id public input
		let chain_id = 1u64;
		let chain_id_f = E::Fr::from(chain_id);
		// Generate the leaf
		let leaf = Self::create_random_leaf(curve, chain_id, rng)?;
		let leaf_value = E::Fr::from_le_bytes_mod_order(&leaf.leaf_bytes);

		let secret = E::Fr::from_le_bytes_mod_order(&leaf.secret_bytes);
		let nullifier = E::Fr::from_le_bytes_mod_order(&leaf.nullifier_bytes);

		let nullifier_hash = E::Fr::from_le_bytes_mod_order(&leaf.nullifier_hash_bytes);
		let leaves = vec![E::Fr::from_le_bytes_mod_order(&leaf.leaf_bytes)];
		let (tree, path) = setup_tree_and_create_path::<E::Fr, Poseidon<E::Fr>, HEIGHT>(
			&tree_hasher,
			&leaves,
			0,
			&default_leaf,
		)?;
		let mut root_set = [E::Fr::rand(rng); ANCHOR_CT];
		root_set[0] = tree.root();

		let mc = AnchorCircuit::new(
			arbitrary_input,
			secret,
			nullifier,
			chain_id_f,
			root_set,
			path,
			nullifier_hash,
			tree_hasher,
			leaf_hasher,
		);
		let public_inputs =
			Self::construct_public_inputs(chain_id_f, nullifier_hash, root_set, arbitrary_input);

		Ok((
			mc,
			leaf_value,
			nullifier_hash,
			root_set.to_vec(),
			public_inputs,
		))
	}

	#[allow(dead_code)]
	pub fn setup_circuit_with_privates(
		curve: Curve,
		chain_id: E::Fr,
		secret: E::Fr,
		nullifier: E::Fr,
		leaves: &[E::Fr],
		index: u64,
		roots: [E::Fr; ANCHOR_CT],
		arbitrary_input: E::Fr,
		default_leaf: [u8; 32],
	) -> Result<
		(
			AnchorCircuit<E::Fr, PoseidonGadget<E::Fr>, HEIGHT, ANCHOR_CT>,
			E::Fr,
			E::Fr,
			Vec<E::Fr>,
			Vec<E::Fr>,
		),
		Error,
	> {
		// Initialize hashers
		let params3 = setup_params::<E::Fr>(curve, 5, 3);
		let params4 = setup_params::<E::Fr>(curve, 5, 4);
		let tree_hasher = Poseidon::<E::Fr> { params: params3 };
		let leaf_hasher = Poseidon::<E::Fr> { params: params4 };
		// Setup inputs
		let leaf = leaf_hasher.hash(&[chain_id, secret, nullifier])?;
		let nullifier_hash = tree_hasher.hash_two(&nullifier, &nullifier)?;
		let (_, path) = setup_tree_and_create_path::<E::Fr, Poseidon<E::Fr>, HEIGHT>(
			&tree_hasher,
			&leaves,
			index,
			&default_leaf,
		)?;

		let mc = AnchorCircuit::new(
			arbitrary_input,
			secret,
			nullifier,
			chain_id,
			roots,
			path,
			nullifier_hash,
			tree_hasher,
			leaf_hasher,
		);
		let public_inputs =
			Self::construct_public_inputs(chain_id, nullifier_hash, roots, arbitrary_input);
		Ok((mc, leaf, nullifier_hash, roots.to_vec(), public_inputs))
	}

	#[allow(dead_code)]
	#[allow(clippy::too_many_arguments)]
	pub fn setup_circuit_with_privates_raw(
		curve: Curve,
		chain_id: u64,
		secret: Vec<u8>,
		nullifier: Vec<u8>,
		leaves: &[Vec<u8>],
		index: u64,
		roots: [Vec<u8>; ANCHOR_CT],
		recipient: Vec<u8>,
		relayer: Vec<u8>,
		fee: u128,
		refund: u128,
		commitment: Vec<u8>,
		default_leaf: [u8; 32],
	) -> Result<
		(
			AnchorCircuit<E::Fr, PoseidonGadget<E::Fr>, HEIGHT, ANCHOR_CT>,
			Vec<u8>,
			Vec<u8>,
			Vec<Vec<u8>>,
			Vec<Vec<u8>>,
		),
		Error,
	> {
		let chain_id_f = E::Fr::from(chain_id);
		let secret_f = E::Fr::from_le_bytes_mod_order(&secret);
		let nullifier_f = E::Fr::from_le_bytes_mod_order(&nullifier);
		let leaves_f: Vec<E::Fr> = leaves
			.iter()
			.map(|x| E::Fr::from_le_bytes_mod_order(x))
			.collect();

		let mut arbitrary_data_bytes = Vec::new();
		arbitrary_data_bytes.extend(&recipient);
		arbitrary_data_bytes.extend(&relayer);
		arbitrary_data_bytes.extend(fee.encode());
		arbitrary_data_bytes.extend(refund.encode());
		arbitrary_data_bytes.extend(&commitment);
		let arbitrary_data = keccak_256(&arbitrary_data_bytes);
		let arbitrary_input = E::Fr::from_le_bytes_mod_order(&arbitrary_data);
		let roots_set: [E::Fr; ANCHOR_CT] = roots
			.iter()
			.map(|x| E::Fr::from_le_bytes_mod_order(x))
			.collect::<Vec<E::Fr>>()
			.try_into()
			.unwrap_or([E::Fr::zero(); ANCHOR_CT]);

		let (mc, leaf, nullifier_hash, roots, public_inputs) = Self::setup_circuit_with_privates(
			curve,
			chain_id_f,
			secret_f,
			nullifier_f,
			&leaves_f,
			index,
			roots_set,
			arbitrary_input,
			default_leaf,
		)?;

		let leaf_raw = leaf.into_repr().to_bytes_le();
		let nullifier_hash_raw = nullifier_hash.into_repr().to_bytes_le();
		let roots_raw = roots.iter().map(|v| v.into_repr().to_bytes_le()).collect();
		let public_inputs_raw: Vec<Vec<u8>> = public_inputs
			.iter()
			.map(|x| x.into_repr().to_bytes_le())
			.collect();

		Ok((
			mc,
			leaf_raw,
			nullifier_hash_raw,
			roots_raw,
			public_inputs_raw,
		))
	}

	#[allow(dead_code)]
	pub fn create_circuit(
		curve: Curve,
		arbitrary_input: E::Fr,
		secret: E::Fr,
		nullifier: E::Fr,
		chain_id: E::Fr,
		path: Path<E::Fr, Poseidon<E::Fr>, HEIGHT>,
		root_set: [E::Fr; ANCHOR_CT],
		nullifier_hash: E::Fr,
	) -> AnchorCircuit<E::Fr, PoseidonGadget<E::Fr>, HEIGHT, ANCHOR_CT> {
		// Initialize hashers
		let params3 = setup_params::<E::Fr>(curve, 5, 3);
		let params4 = setup_params::<E::Fr>(curve, 5, 4);
		let tree_hasher = Poseidon::<E::Fr> { params: params3 };
		let leaf_hasher = Poseidon::<E::Fr> { params: params4 };

		let mc = AnchorCircuit::new(
			arbitrary_input,
			secret,
			nullifier,
			chain_id,
			root_set,
			path,
			nullifier_hash,
			tree_hasher,
			leaf_hasher,
		);
		mc
	}
}

impl<E: PairingEngine, const HEIGHT: usize, const ANCHOR_CT: usize>
	AnchorProver<E, HEIGHT, ANCHOR_CT> for AnchorR1CSProver<E, HEIGHT, ANCHOR_CT>
{
	fn create_leaf_with_privates(
		curve: Curve,
		chain_id: u64,
		secret: Vec<u8>,
		nullifier: Vec<u8>,
	) -> Result<Leaf, Error> {
		// Initialize hashers
		let params3 = setup_params::<E::Fr>(curve, 5, 3);
		let params4 = setup_params::<E::Fr>(curve, 5, 4);
		let tree_hasher = Poseidon::<E::Fr> { params: params3 };
		let leaf_hasher = Poseidon::<E::Fr> { params: params4 };

		let secret_field_elt: E::Fr = E::Fr::from_le_bytes_mod_order(&secret);
		let nullifier_field_elt: E::Fr = E::Fr::from_le_bytes_mod_order(&nullifier);
		let chain_id_elt = E::Fr::from(chain_id);
		let leaf_field_element =
			leaf_hasher.hash(&[chain_id_elt, nullifier_field_elt, secret_field_elt])?;
		let nullifier_hash_field_element =
			tree_hasher.hash_two(&nullifier_field_elt, &nullifier_field_elt)?;
		Ok(Leaf {
			chain_id_bytes: Some(chain_id.to_be_bytes().to_vec()),
			secret_bytes: secret_field_elt.into_repr().to_bytes_le(),
			nullifier_bytes: nullifier_field_elt.into_repr().to_bytes_le(),
			leaf_bytes: leaf_field_element.into_repr().to_bytes_le(),
			nullifier_hash_bytes: nullifier_hash_field_element.into_repr().to_bytes_le(),
		})
	}

	fn create_proof<R: RngCore + CryptoRng>(
		curve: Curve,
		chain_id: u64,
		secret: Vec<u8>,
		nullifier: Vec<u8>,
		leaves: Vec<Vec<u8>>,
		index: u64,
		root_set: [Vec<u8>; ANCHOR_CT],
		recipient: Vec<u8>,
		relayer: Vec<u8>,
		fee: u128,
		refund: u128,
		commitment: Vec<u8>,
		pk: Vec<u8>,
		default_leaf: [u8; 32],
		rng: &mut R,
	) -> Result<AnchorProof, Error> {
		// Initialize hashers
		let params3 = setup_params::<E::Fr>(curve, 5, 3);
		let params4 = setup_params::<E::Fr>(curve, 5, 4);
		let tree_hasher = Poseidon::<E::Fr> { params: params3 };
		let leaf_hasher = Poseidon::<E::Fr> { params: params4 };
		// Get field element version of all the data
		let secret_f = E::Fr::from_le_bytes_mod_order(&secret);
		let nullifier_f = E::Fr::from_le_bytes_mod_order(&nullifier);
		let leaves_f: Vec<E::Fr> = leaves
			.iter()
			.map(|x| E::Fr::from_le_bytes_mod_order(x))
			.collect();
		let root_set_f: [E::Fr; ANCHOR_CT] = root_set.map(|x| E::Fr::from_le_bytes_mod_order(&x));
		// Create the arbitrary input data
		let mut arbitrary_data_bytes = Vec::new();
		arbitrary_data_bytes.extend(&recipient);
		arbitrary_data_bytes.extend(&relayer);
		// Using encode to be compatible with on chain types
		arbitrary_data_bytes.extend(fee.encode());
		arbitrary_data_bytes.extend(refund.encode());
		arbitrary_data_bytes.extend(&commitment);
		let arbitrary_data = keccak_256(&arbitrary_data_bytes);
		let arbitrary_input = E::Fr::from_le_bytes_mod_order(&arbitrary_data);
		// Generate the leaf
		let Leaf {
			leaf_bytes,
			nullifier_hash_bytes,
			..
		} = Self::create_leaf_with_privates(curve, chain_id, secret, nullifier)?;
		// Setup the tree and generate the path
		let (_, path) = setup_tree_and_create_path::<E::Fr, Poseidon<E::Fr>, HEIGHT>(
			&tree_hasher,
			&leaves_f,
			index,
			&default_leaf,
		)?;

		let chain_id_f = E::Fr::from(chain_id);
		let nullifier_hash_f = E::Fr::from_le_bytes_mod_order(&nullifier_hash_bytes);
		let mc = AnchorCircuit::<E::Fr, PoseidonGadget<E::Fr>, HEIGHT, ANCHOR_CT>::new(
			arbitrary_input,
			secret_f,
			nullifier_f,
			chain_id_f,
			root_set_f,
			path,
			nullifier_hash_f,
			tree_hasher,
			leaf_hasher,
		);
		let public_inputs = Self::construct_public_inputs(
			chain_id_f,
			nullifier_hash_f,
			root_set_f,
			arbitrary_input,
		);

		let leaf_raw = leaf_bytes;
		let nullifier_hash_raw = nullifier_hash_bytes;
		let roots_raw = root_set_f
			.iter()
			.map(|v| v.into_repr().to_bytes_le())
			.collect();
		let public_inputs_raw: Vec<Vec<u8>> = public_inputs
			.iter()
			.map(|x| x.into_repr().to_bytes_le())
			.collect();

		let proof = prove_unchecked::<E, _, _>(mc, &pk, rng)?;

		Ok(AnchorProof {
			leaf_raw,
			nullifier_hash_raw,
			roots_raw,
			public_inputs_raw,
			proof,
		})
	}

	fn create_random_leaf<R: RngCore + CryptoRng>(
		curve: Curve,
		chain_id: u64,
		rng: &mut R,
	) -> Result<Leaf, Error> {
		let secret = E::Fr::rand(rng);
		let nullifier = E::Fr::rand(rng);
		Self::create_leaf_with_privates(
			curve,
			chain_id,
			secret.into_repr().to_bytes_le(),
			nullifier.into_repr().to_bytes_le(),
		)
	}
}
