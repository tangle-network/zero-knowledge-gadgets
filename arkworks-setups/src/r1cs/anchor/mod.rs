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
use arkworks_circuits::anchor::AnchorCircuit;
use arkworks_gadgets::{
	leaf::anchor::{Private, Public},
	merkle_tree::simple_merkle::Path,
	poseidon::{field_hasher::Poseidon, field_hasher_constraints::PoseidonGadget},
};
use arkworks_utils::utils::common::{setup_params_x5_3, setup_params_x5_4, Curve};

use super::setup_tree_and_create_path;

#[cfg(test)]
mod tests;

pub type PoseidonAnchorCircuit<F, const N: usize, const M: usize> =
	AnchorCircuit<F, PoseidonGadget<F>, PoseidonGadget<F>, N, M>;

struct AnchorR1CSProver<E: PairingEngine, const HEIGHT: usize, const ANCHOR_CT: usize> {
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
		let mut pub_ins = vec![chain_id, nullifier_hash];
		pub_ins.extend(roots.to_vec());
		pub_ins.push(arbitrary_input);
		pub_ins
	}

	#[allow(dead_code)]
	pub fn setup_random_circuit<R: CryptoRng + RngCore>(
		curve: Curve,
		default_leaf: [u8; 32],
		rng: &mut R,
	) -> Result<
		(
			AnchorCircuit<E::Fr, PoseidonGadget<E::Fr>, PoseidonGadget<E::Fr>, HEIGHT, ANCHOR_CT>,
			E::Fr,
			E::Fr,
			Vec<E::Fr>,
			Vec<E::Fr>,
		),
		Error,
	> {
		let arbitrary_input = E::Fr::rand(rng);
		// Initialize hashers
		let params3 = setup_params_x5_3::<E::Fr>(curve);
		let params4 = setup_params_x5_4::<E::Fr>(curve);
		let tree_hasher = Poseidon::<E::Fr> { params: params3 };
		let leaf_hasher = Poseidon::<E::Fr> { params: params4 };
		// Create random chain_id public input
		let chain_id = 1u64;
		let chain_id_f = E::Fr::from(chain_id);
		// Generate the leaf
		let leaf = Self::create_leaf_with_privates(curve, chain_id, None, None, rng)?;
		let leaf_value = E::Fr::from_le_bytes_mod_order(&leaf.leaf_bytes);
		let leaf_public = Public::new(chain_id_f);
		let leaf_private = Private::new(
			E::Fr::from_le_bytes_mod_order(&leaf.secret_bytes),
			E::Fr::from_le_bytes_mod_order(&leaf.nullifier_bytes),
		);
		let nullifier_hash = E::Fr::from_le_bytes_mod_order(&leaf.nullifier_hash_bytes);
		let leaves = vec![E::Fr::from_le_bytes_mod_order(&leaf.leaf_bytes)];
		let (tree, path) = setup_tree_and_create_path::<E::Fr, PoseidonGadget<E::Fr>, HEIGHT>(
			tree_hasher.clone(),
			&leaves,
			0,
			&default_leaf,
		)?;
		let mut root_set = [E::Fr::rand(rng); ANCHOR_CT];
		root_set[0] = tree.root();

		let mc = AnchorCircuit::new(
			arbitrary_input,
			leaf_private,
			leaf_public,
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
			AnchorCircuit<E::Fr, PoseidonGadget<E::Fr>, PoseidonGadget<E::Fr>, HEIGHT, ANCHOR_CT>,
			E::Fr,
			E::Fr,
			Vec<E::Fr>,
			Vec<E::Fr>,
		),
		Error,
	> {
		use arkworks_gadgets::leaf::anchor;
		// Initialize hashers
		let params3 = setup_params_x5_3::<E::Fr>(curve);
		let params4 = setup_params_x5_4::<E::Fr>(curve);
		let tree_hasher = Poseidon::<E::Fr> { params: params3 };
		let leaf_hasher = Poseidon::<E::Fr> { params: params4 };
		// Setup inputs
		let leaf_public = Public::new(chain_id);
		let leaf_private: Private<E::Fr> = Private::new(secret, nullifier);
		let leaf = anchor::AnchorLeaf::<E::Fr, Poseidon<E::Fr>>::create_leaf(
			&leaf_private,
			&leaf_public,
			&leaf_hasher,
		)?;
		let nullifier_hash = anchor::AnchorLeaf::<E::Fr, Poseidon<E::Fr>>::create_nullifier(
			&leaf_private,
			&tree_hasher.clone(),
		)?;
		let (_, path) = setup_tree_and_create_path::<E::Fr, PoseidonGadget<E::Fr>, HEIGHT>(
			tree_hasher.clone(),
			&leaves,
			index,
			&default_leaf,
		)?;

		let mc = AnchorCircuit::new(
			arbitrary_input,
			leaf_private,
			leaf_public,
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
			AnchorCircuit<E::Fr, PoseidonGadget<E::Fr>, PoseidonGadget<E::Fr>, HEIGHT, ANCHOR_CT>,
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
		arbitrary_data_bytes.extend(fee.to_le_bytes());
		arbitrary_data_bytes.extend(refund.to_le_bytes());
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
		leaf_private: Private<E::Fr>,
		leaf_public: Public<E::Fr>,
		path: Path<E::Fr, Poseidon<E::Fr>, HEIGHT>,
		root_set: [E::Fr; ANCHOR_CT],
		nullifier_hash: E::Fr,
	) -> AnchorCircuit<E::Fr, PoseidonGadget<E::Fr>, PoseidonGadget<E::Fr>, HEIGHT, ANCHOR_CT> {
		// Initialize hashers
		let params3 = setup_params_x5_3::<E::Fr>(curve);
		let params4 = setup_params_x5_4::<E::Fr>(curve);
		let tree_hasher = Poseidon::<E::Fr> { params: params3 };
		let leaf_hasher = Poseidon::<E::Fr> { params: params4 };

		let mc = AnchorCircuit::new(
			arbitrary_input,
			leaf_private,
			leaf_public,
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
	fn create_leaf_with_privates<R: RngCore + CryptoRng>(
		curve: Curve,
		chain_id: u64,
		secret: Option<Vec<u8>>,
		nullifier: Option<Vec<u8>>,
		rng: &mut R,
	) -> Result<AnchorLeaf, Error> {
		use arkworks_gadgets::leaf::anchor;
		// Initialize hashers
		let params3 = setup_params_x5_3::<E::Fr>(curve);
		let params4 = setup_params_x5_4::<E::Fr>(curve);
		let tree_hasher = Poseidon::<E::Fr> { params: params3 };
		let leaf_hasher = Poseidon::<E::Fr> { params: params4 };

		let secret_field_elt: E::Fr = match secret {
			Some(secret) => E::Fr::from_le_bytes_mod_order(&secret),
			None => E::Fr::rand(rng),
		};
		let nullifier_field_elt: E::Fr = match nullifier {
			Some(nullifier) => E::Fr::from_le_bytes_mod_order(&nullifier),
			None => E::Fr::rand(rng),
		};
		let chain_id_elt = E::Fr::from(chain_id);
		let public = Public::new(chain_id_elt);
		let private: Private<E::Fr> = Private::new(secret_field_elt, nullifier_field_elt);
		let leaf_field_element = anchor::AnchorLeaf::create_leaf(&private, &public, &leaf_hasher)?;
		let nullifier_hash_field_element =
			anchor::AnchorLeaf::create_nullifier(&private, &tree_hasher)?;
		Ok(AnchorLeaf {
			chain_id_bytes: chain_id.to_be_bytes().to_vec(),
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
		let params3 = setup_params_x5_3::<E::Fr>(curve);
		let params4 = setup_params_x5_4::<E::Fr>(curve);
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
		arbitrary_data_bytes.extend(fee.to_le_bytes());
		arbitrary_data_bytes.extend(refund.to_le_bytes());
		arbitrary_data_bytes.extend(&commitment);
		let arbitrary_data = keccak_256(&arbitrary_data_bytes);
		let arbitrary_input = E::Fr::from_le_bytes_mod_order(&arbitrary_data);
		// Generate the leaf
		let AnchorLeaf {
			leaf_bytes,
			nullifier_hash_bytes,
			..
		} = Self::create_leaf_with_privates(curve, chain_id, Some(secret), Some(nullifier), rng)?;
		// Setup the tree and generate the path
		let (_, path) = setup_tree_and_create_path::<E::Fr, PoseidonGadget<E::Fr>, HEIGHT>(
			tree_hasher.clone(),
			&leaves_f,
			index,
			&default_leaf,
		)?;

		let chain_id_f = E::Fr::from(chain_id);
		let leaf_public = Public::new(chain_id_f);
		let leaf_private = Private::new(secret_f, nullifier_f);
		let mc = AnchorCircuit::<
			E::Fr,
			PoseidonGadget<E::Fr>,
			PoseidonGadget<E::Fr>,
			HEIGHT,
			ANCHOR_CT,
		>::new(
			arbitrary_input,
			leaf_private,
			leaf_public,
			root_set_f,
			path,
			nullifier_f,
			tree_hasher,
			leaf_hasher,
		);
		let public_inputs =
			Self::construct_public_inputs(chain_id_f, nullifier_f, root_set_f, arbitrary_input);

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
}
