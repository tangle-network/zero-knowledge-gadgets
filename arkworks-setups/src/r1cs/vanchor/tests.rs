use ark_std::vec;

use crate::{common::*, VAnchorProver};
use ark_serialize::CanonicalDeserialize;
use ark_std::{collections::BTreeMap, One, Zero};
use arkworks_native_gadgets::poseidon::Poseidon;
use arkworks_utils::Curve;

use ark_bn254::{Bn254, Fr as BnFr};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_groth16::{Groth16, Proof, VerifyingKey};

use ark_snark::SNARK;
use ark_std::{str::FromStr, test_rng};

use super::{setup_params, VAnchorR1CSProver};

const HEIGHT: usize = 30;
const ANCHOR_CT: usize = 2;
const INS: usize = 2;
const OUTS: usize = 2;

#[allow(non_camel_case_types)]
type VAnchorR1CSProver_Bn254_Poseidon_30 = VAnchorR1CSProver<Bn254, HEIGHT, ANCHOR_CT, INS, OUTS>;
#[allow(non_camel_case_types)]
type VAnchorR1CSProver_Bn254_Poseidon_30_16_in =
	VAnchorR1CSProver<Bn254, HEIGHT, ANCHOR_CT, 16, OUTS>;
const DEFAULT_LEAF: [u8; 32] = [0u8; 32];

#[test]
fn should_create_proof_for_random_circuit() {
	let rng = &mut test_rng();
	let curve = Curve::Bn254;
	let params3 = setup_params::<BnFr>(curve, 5, 3);
	let tree_hasher = Poseidon::<BnFr> { params: params3 };

	// Set up a random circuit and make pk/vk pair
	let random_circuit =
		VAnchorR1CSProver_Bn254_Poseidon_30::setup_random_circuit(curve, DEFAULT_LEAF, rng)
			.unwrap();
	let (proving_key, verifying_key) =
		setup_keys_unchecked::<Bn254, _, _>(random_circuit, rng).unwrap();

	// Make a proof now
	let public_amount = 10;
	let ext_data_hash = BnFr::rand(rng);

	// Input Utxos
	let in_chain_id = 0u64;
	let in_amount = 5;
	let index = 0u64;
	let in_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30::create_random_utxo(
		curve,
		in_chain_id,
		in_amount,
		Some(0),
		rng,
	)
	.unwrap();
	let in_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30::create_random_utxo(
		curve,
		in_chain_id,
		in_amount,
		Some(1),
		rng,
	)
	.unwrap();
	let in_utxos = [in_utxo1.clone(), in_utxo2.clone()];

	// Output Utxos
	let out_chain_id = 0u64;
	let out_amount = 10;
	let out_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxos = [out_utxo1.clone(), out_utxo2.clone()];

	let leaf0 = in_utxo1.commitment;
	let leaf1 = in_utxo2.commitment;

	let (smt, _) = setup_tree_and_create_path::<BnFr, Poseidon<BnFr>, HEIGHT>(
		&tree_hasher,
		&vec![leaf0, leaf1],
		0,
		&DEFAULT_LEAF,
	)
	.unwrap();

	let mut in_leaves = BTreeMap::new();
	in_leaves.insert(in_chain_id, vec![
		leaf0.into_repr().to_bytes_le(),
		leaf1.into_repr().to_bytes_le(),
	]);
	let in_indices = [0, 1];
	let in_root_set = [
		smt.root().into_repr().to_bytes_le(),
		smt.root().into_repr().to_bytes_le(),
	];

	let proof = VAnchorR1CSProver_Bn254_Poseidon_30::create_proof(
		curve,
		in_chain_id,
		public_amount,
		ext_data_hash.into_repr().to_bytes_le(),
		in_root_set,
		in_indices,
		in_leaves,
		in_utxos,
		out_utxos,
		proving_key,
		DEFAULT_LEAF,
		rng,
	)
	.unwrap();

	let pub_ins = proof
		.public_inputs_raw
		.iter()
		.map(|inp| BnFr::from_le_bytes_mod_order(inp.as_slice()))
		.collect::<Vec<_>>();
	let res = verify_unchecked::<Bn254>(&pub_ins, &verifying_key, &proof.proof).unwrap();

	assert!(res);
}

#[test]
fn should_create_circuit_and_prove_groth16_2_input_2_output() {
	let rng = &mut test_rng();
	let curve = Curve::Bn254;
	let params3 = setup_params::<BnFr>(curve, 5, 3);
	let params4 = setup_params::<BnFr>(curve, 5, 4);
	let tree_hasher = Poseidon::<BnFr> { params: params3 };
	let nullifier_hasher = Poseidon::<BnFr> { params: params4 };

	// Set up a random circuit and make pk/vk pair
	let random_circuit =
		VAnchorR1CSProver_Bn254_Poseidon_30::setup_random_circuit(curve, DEFAULT_LEAF, rng)
			.unwrap();
	let (proving_key, verifying_key) =
		setup_keys_unchecked::<Bn254, _, _>(random_circuit, rng).unwrap();

	let public_amount = 10;
	let ext_data_hash = BnFr::rand(rng);

	// Input Utxos
	let in_chain_id = 0u64;
	let in_amount = 5;
	let mut in_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30::create_random_utxo(
		curve,
		in_chain_id,
		in_amount,
		None,
		rng,
	)
	.unwrap();
	// Setting the index after the fact to test the function
	in_utxo1.set_index(0, &nullifier_hasher).unwrap();

	let mut in_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30::create_random_utxo(
		curve,
		in_chain_id,
		in_amount,
		None,
		rng,
	)
	.unwrap();
	// Setting the index after the fact to test the function
	in_utxo2.set_index(1, &nullifier_hasher).unwrap();

	let in_utxos = [in_utxo1.clone(), in_utxo2.clone()];

	// Output Utxos
	let out_chain_id = 0u64;
	let out_amount = 10;
	let out_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxos = [out_utxo1.clone(), out_utxo2.clone()];

	let leaf0 = in_utxo1.commitment;
	let leaf1 = in_utxo2.commitment;

	let (smt, _) = setup_tree_and_create_path::<BnFr, Poseidon<BnFr>, HEIGHT>(
		&tree_hasher,
		&vec![leaf0, leaf1],
		0,
		&DEFAULT_LEAF,
	)
	.unwrap();

	let mut in_leaves = BTreeMap::new();
	in_leaves.insert(in_chain_id, vec![
		leaf0.into_repr().to_bytes_le(),
		leaf1.into_repr().to_bytes_le(),
	]);
	let in_indices = [0, 1];
	let in_root_set = [
		smt.root().into_repr().to_bytes_le(),
		smt.root().into_repr().to_bytes_le(),
	];

	let proof = VAnchorR1CSProver_Bn254_Poseidon_30::create_proof(
		curve,
		in_chain_id,
		public_amount,
		ext_data_hash.into_repr().to_bytes_le(),
		in_root_set,
		in_indices,
		in_leaves,
		in_utxos,
		out_utxos,
		proving_key,
		DEFAULT_LEAF,
		rng,
	)
	.unwrap();

	let pub_ins = proof
		.public_inputs_raw
		.iter()
		.map(|inp| BnFr::from_le_bytes_mod_order(inp.as_slice()))
		.collect::<Vec<_>>();

	let res = verify_unchecked::<Bn254>(&pub_ins, &verifying_key, &proof.proof).unwrap();

	assert!(res);
}

#[test]
fn should_fail_with_invalid_root() {
	let rng = &mut test_rng();
	let curve = Curve::Bn254;
	let params3 = setup_params::<BnFr>(curve, 5, 3);
	let tree_hasher = Poseidon::<BnFr> { params: params3 };

	// Set up a random circuit and make pk/vk pair
	let random_circuit =
		VAnchorR1CSProver_Bn254_Poseidon_30::setup_random_circuit(curve, DEFAULT_LEAF, rng)
			.unwrap();
	let (proving_key, verifying_key) =
		setup_keys_unchecked::<Bn254, _, _>(random_circuit, rng).unwrap();

	let public_amount = 10;
	let ext_data_hash = BnFr::rand(rng);

	// Input Utxos
	let in_chain_id = 0u64;
	let in_amount = 5;
	let index = 0u64;
	let in_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30::create_random_utxo(
		curve,
		in_chain_id,
		in_amount,
		Some(index),
		rng,
	)
	.unwrap();
	let in_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30::create_random_utxo(
		curve,
		in_chain_id,
		in_amount,
		Some(index),
		rng,
	)
	.unwrap();
	let in_utxos = [in_utxo1.clone(), in_utxo2.clone()];

	// Output Utxos
	let out_chain_id = 0u64;
	let out_amount = 10;
	let out_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxos = [out_utxo1.clone(), out_utxo2.clone()];

	let leaf0 = in_utxo1.commitment;
	let leaf1 = in_utxo2.commitment;

	let (smt, _) = setup_tree_and_create_path::<BnFr, Poseidon<BnFr>, HEIGHT>(
		&tree_hasher,
		&vec![leaf0, leaf1],
		0,
		&DEFAULT_LEAF,
	)
	.unwrap();

	let mut in_leaves = BTreeMap::new();
	in_leaves.insert(in_chain_id, vec![
		leaf0.into_repr().to_bytes_le(),
		leaf1.into_repr().to_bytes_le(),
	]);
	let in_indices = [0, 1];
	let in_root_set = [
		smt.root().into_repr().to_bytes_le(),
		smt.root().into_repr().to_bytes_le(),
	];

	let proof = VAnchorR1CSProver_Bn254_Poseidon_30::create_proof(
		curve,
		in_chain_id,
		public_amount,
		ext_data_hash.into_repr().to_bytes_le(),
		in_root_set,
		in_indices,
		in_leaves,
		in_utxos,
		out_utxos,
		proving_key,
		DEFAULT_LEAF,
		rng,
	)
	.unwrap();

	let pub_ins = proof
		.public_inputs_raw
		.iter()
		.map(|inp| BnFr::from_le_bytes_mod_order(inp.as_slice()))
		.collect::<Vec<_>>();

	let res = verify_unchecked::<Bn254>(&pub_ins, &verifying_key, &proof.proof).unwrap();

	assert!(!res);
}

#[test]
fn should_fail_with_invalid_nullifier() {
	let rng = &mut test_rng();
	let curve = Curve::Bn254;
	let params3 = setup_params::<BnFr>(curve, 5, 3);
	let tree_hasher = Poseidon::<BnFr> { params: params3 };

	// Set up a random circuit and make pk/vk pair
	let random_circuit =
		VAnchorR1CSProver_Bn254_Poseidon_30::setup_random_circuit(curve, DEFAULT_LEAF, rng)
			.unwrap();
	let (proving_key, verifying_key) =
		setup_keys_unchecked::<Bn254, _, _>(random_circuit, rng).unwrap();

	let public_amount = 10;
	let ext_data_hash = BnFr::rand(rng);

	// Input Utxos
	let in_chain_id = 0u64;
	let in_amount = 5;
	let index = 0u64;
	let mut in_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30::create_random_utxo(
		curve,
		in_chain_id,
		in_amount,
		Some(index),
		rng,
	)
	.unwrap();
	let in_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30::create_random_utxo(
		curve,
		in_chain_id,
		in_amount,
		Some(index),
		rng,
	)
	.unwrap();

	// Adding invalid nullifier
	in_utxo1.nullifier = Some(BnFr::rand(rng));

	let in_utxos = [in_utxo1.clone(), in_utxo2.clone()];

	// Output Utxos
	let out_chain_id = 0u64;
	let out_amount = 10;
	let out_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxos = [out_utxo1.clone(), out_utxo2.clone()];

	let leaf0 = in_utxo1.commitment;
	let leaf1 = in_utxo2.commitment;

	let (smt, _) = setup_tree_and_create_path::<BnFr, Poseidon<BnFr>, HEIGHT>(
		&tree_hasher,
		&vec![leaf0, leaf1],
		0,
		&DEFAULT_LEAF,
	)
	.unwrap();

	let mut in_leaves = BTreeMap::new();
	in_leaves.insert(in_chain_id, vec![
		leaf0.into_repr().to_bytes_le(),
		leaf1.into_repr().to_bytes_le(),
	]);
	let in_indices = [0, 1];
	let in_root_set = [
		smt.root().into_repr().to_bytes_le(),
		smt.root().into_repr().to_bytes_le(),
	];

	let proof = VAnchorR1CSProver_Bn254_Poseidon_30::create_proof(
		curve,
		in_chain_id,
		public_amount,
		ext_data_hash.into_repr().to_bytes_le(),
		in_root_set,
		in_indices,
		in_leaves,
		in_utxos,
		out_utxos,
		proving_key,
		DEFAULT_LEAF,
		rng,
	)
	.unwrap();

	let pub_ins = proof
		.public_inputs_raw
		.iter()
		.map(|inp| BnFr::from_le_bytes_mod_order(inp.as_slice()))
		.collect::<Vec<_>>();
	let res = verify_unchecked::<Bn254>(&pub_ins, &verifying_key, &proof.proof).unwrap();

	assert!(!res);
}

#[test]
#[ignore]
fn should_fail_with_same_nullifier() {
	let rng = &mut test_rng();
	let curve = Curve::Bn254;
	let params3 = setup_params::<BnFr>(curve, 5, 3);
	let tree_hasher = Poseidon::<BnFr> { params: params3 };

	// Set up a random circuit and make pk/vk pair
	let random_circuit =
		VAnchorR1CSProver_Bn254_Poseidon_30::setup_random_circuit(curve, DEFAULT_LEAF, rng)
			.unwrap();
	let (proving_key, verifying_key) =
		setup_keys_unchecked::<Bn254, _, _>(random_circuit, rng).unwrap();

	let public_amount = 0;
	let ext_data_hash = BnFr::rand(rng);

	// Input Utxos
	let in_chain_id = 0u64;
	let in_amount = 5;
	let index = 0u64;
	let in_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30::create_random_utxo(
		curve,
		in_chain_id,
		in_amount,
		Some(index),
		rng,
	)
	.unwrap();

	// Both inputs are the same -- attempt of double spending
	let in_utxos = [in_utxo1.clone(), in_utxo1.clone()];

	// Output Utxos
	let out_chain_id = 0u64;
	let out_amount = 10;
	let out_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxos = [out_utxo1.clone(), out_utxo2.clone()];

	let leaf0 = in_utxo1.commitment;

	let (smt, _) = setup_tree_and_create_path::<BnFr, Poseidon<BnFr>, HEIGHT>(
		&tree_hasher,
		&vec![leaf0],
		0,
		&DEFAULT_LEAF,
	)
	.unwrap();

	let mut in_leaves = BTreeMap::new();
	in_leaves.insert(in_chain_id, vec![
		leaf0.into_repr().to_bytes_le(),
		leaf0.into_repr().to_bytes_le(),
	]);
	let in_indices = [0, 0];
	let in_root_set = [
		smt.root().into_repr().to_bytes_le(),
		smt.root().into_repr().to_bytes_le(),
	];

	let proof = VAnchorR1CSProver_Bn254_Poseidon_30::create_proof(
		curve,
		in_chain_id,
		public_amount,
		ext_data_hash.into_repr().to_bytes_le(),
		in_root_set,
		in_indices,
		in_leaves,
		in_utxos,
		out_utxos,
		proving_key,
		DEFAULT_LEAF,
		rng,
	)
	.unwrap();

	let pub_ins = proof
		.public_inputs_raw
		.iter()
		.map(|inp| BnFr::from_le_bytes_mod_order(inp.as_slice()))
		.collect::<Vec<_>>();
	let res = verify_unchecked::<Bn254>(&pub_ins, &verifying_key, &proof.proof).unwrap();

	assert!(!res);
}

#[test]
fn should_fail_with_inconsistent_input_output_values() {
	let rng = &mut test_rng();
	let curve = Curve::Bn254;
	let params3 = setup_params::<BnFr>(curve, 5, 3);
	let tree_hasher = Poseidon::<BnFr> { params: params3 };

	// Set up a random circuit and make pk/vk pair
	let random_circuit =
		VAnchorR1CSProver_Bn254_Poseidon_30::setup_random_circuit(curve, DEFAULT_LEAF, rng)
			.unwrap();
	let (proving_key, verifying_key) =
		setup_keys_unchecked::<Bn254, _, _>(random_circuit, rng).unwrap();

	let public_amount = 10;
	let ext_data_hash = BnFr::rand(rng);

	// Input Utxos
	let in_chain_id = 0u64;
	// Input amount too high
	let in_amount = 10;
	let index = 0u64;
	let in_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30::create_random_utxo(
		curve,
		in_chain_id,
		in_amount,
		Some(index),
		rng,
	)
	.unwrap();
	let in_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30::create_random_utxo(
		curve,
		in_chain_id,
		in_amount,
		Some(index),
		rng,
	)
	.unwrap();
	let in_utxos = [in_utxo1.clone(), in_utxo2.clone()];

	// Output Utxos
	let out_chain_id = 0u64;
	let out_amount = 10;
	let out_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxos = [out_utxo1.clone(), out_utxo2.clone()];

	let leaf0 = in_utxo1.commitment;
	let leaf1 = in_utxo2.commitment;

	let (smt, _) = setup_tree_and_create_path::<BnFr, Poseidon<BnFr>, HEIGHT>(
		&tree_hasher,
		&vec![leaf0, leaf1],
		0,
		&DEFAULT_LEAF,
	)
	.unwrap();

	let mut in_leaves = BTreeMap::new();
	in_leaves.insert(in_chain_id, vec![
		leaf0.into_repr().to_bytes_le(),
		leaf1.into_repr().to_bytes_le(),
	]);
	let in_indices = [0, 1];
	let in_root_set = [
		smt.root().into_repr().to_bytes_le(),
		smt.root().into_repr().to_bytes_le(),
	];

	let proof = VAnchorR1CSProver_Bn254_Poseidon_30::create_proof(
		curve,
		in_chain_id,
		public_amount,
		ext_data_hash.into_repr().to_bytes_le(),
		in_root_set,
		in_indices,
		in_leaves,
		in_utxos,
		out_utxos,
		proving_key,
		DEFAULT_LEAF,
		rng,
	)
	.unwrap();

	let pub_ins = proof
		.public_inputs_raw
		.iter()
		.map(|inp| BnFr::from_le_bytes_mod_order(inp.as_slice()))
		.collect::<Vec<_>>();
	let res = verify_unchecked::<Bn254>(&pub_ins, &verifying_key, &proof.proof).unwrap();

	assert!(!res);
}

#[test]
fn should_fail_with_big_amount() {
	let rng = &mut test_rng();
	let curve = Curve::Bn254;
	let params3 = setup_params::<BnFr>(curve, 5, 3);
	let tree_hasher = Poseidon::<BnFr> { params: params3 };

	// Set up a random circuit and make pk/vk pair
	let random_circuit =
		VAnchorR1CSProver_Bn254_Poseidon_30::setup_random_circuit(curve, DEFAULT_LEAF, rng)
			.unwrap();
	let (proving_key, verifying_key) =
		setup_keys_unchecked::<Bn254, _, _>(random_circuit, rng).unwrap();

	// 2^248
	let limit = BnFr::from_str(
		"452312848583266388373324160190187140051835877600158453279131187530910662656",
	)
	.unwrap();

	let public_amount = 0;
	let ext_data_hash = BnFr::rand(rng);

	// Input Utxos
	let in_chain_id = 0u64;
	let in_amount = BnFr::from(limit + BnFr::one());
	let index = 0u64;
	let in_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30::new_utxo(
		curve,
		in_chain_id,
		in_amount,
		Some(index),
		None,
		None,
		rng,
	)
	.unwrap();
	let in_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30::new_utxo(
		curve,
		in_chain_id,
		in_amount,
		Some(index),
		None,
		None,
		rng,
	)
	.unwrap();
	let in_utxos = [in_utxo1.clone(), in_utxo2.clone()];

	// Output Utxos
	let out_chain_id = 0u64;
	let out_amount = 10;
	let out_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxos = [out_utxo1.clone(), out_utxo2.clone()];

	let leaf0 = in_utxo1.commitment;
	let leaf1 = in_utxo2.commitment;

	let (smt, _) = setup_tree_and_create_path::<BnFr, Poseidon<BnFr>, HEIGHT>(
		&tree_hasher,
		&vec![leaf0, leaf1],
		0,
		&DEFAULT_LEAF,
	)
	.unwrap();

	let mut in_leaves = BTreeMap::new();
	in_leaves.insert(in_chain_id, vec![
		leaf0.into_repr().to_bytes_le(),
		leaf1.into_repr().to_bytes_le(),
	]);
	let in_indices = [0, 1];
	let in_root_set = [
		smt.root().into_repr().to_bytes_le(),
		smt.root().into_repr().to_bytes_le(),
	];

	let proof = VAnchorR1CSProver_Bn254_Poseidon_30::create_proof(
		curve,
		in_chain_id,
		public_amount,
		ext_data_hash.into_repr().to_bytes_le(),
		in_root_set,
		in_indices,
		in_leaves,
		in_utxos,
		out_utxos,
		proving_key,
		DEFAULT_LEAF,
		rng,
	)
	.unwrap();

	let pub_ins = proof
		.public_inputs_raw
		.iter()
		.map(|inp| BnFr::from_le_bytes_mod_order(inp.as_slice()))
		.collect::<Vec<_>>();
	let res = verify_unchecked::<Bn254>(&pub_ins, &verifying_key, &proof.proof).unwrap();

	assert!(!res);
}

#[test]
fn should_fail_with_invalid_public_input() {
	let rng = &mut test_rng();
	let curve = Curve::Bn254;
	let params3 = setup_params::<BnFr>(curve, 5, 3);
	let params4 = setup_params::<BnFr>(curve, 5, 4);
	let tree_hasher = Poseidon::<BnFr> { params: params3 };
	let nullifier_hasher = Poseidon::<BnFr> { params: params4 };

	// Set up a random circuit and make pk/vk pair
	let random_circuit =
		VAnchorR1CSProver_Bn254_Poseidon_30::setup_random_circuit(curve, DEFAULT_LEAF, rng)
			.unwrap();
	let (proving_key, verifying_key) =
		setup_keys_unchecked::<Bn254, _, _>(random_circuit, rng).unwrap();

	let public_amount = 0;
	let ext_data_hash = BnFr::rand(rng);

	// Input Utxos
	let in_chain_id = 0u64;
	let in_amount = 5;
	let index = 0u64;
	let mut in_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30::create_random_utxo(
		curve,
		in_chain_id,
		in_amount,
		None,
		rng,
	)
	.unwrap();
	// Setting the index after the fact to test the function
	in_utxo1.set_index(index, &nullifier_hasher).unwrap();

	let mut in_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30::create_random_utxo(
		curve,
		in_chain_id,
		in_amount,
		Some(index),
		rng,
	)
	.unwrap();
	// Setting the index after the fact to test the function
	in_utxo2.set_index(index, &nullifier_hasher).unwrap();

	let in_utxos = [in_utxo1.clone(), in_utxo2.clone()];

	// Output Utxos
	let out_chain_id = 0u64;
	let out_amount = 10;
	let out_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxos = [out_utxo1.clone(), out_utxo2.clone()];

	let leaf0 = in_utxo1.commitment;
	let leaf1 = in_utxo2.commitment;

	let (smt, _) = setup_tree_and_create_path::<BnFr, Poseidon<BnFr>, HEIGHT>(
		&tree_hasher,
		&vec![leaf0, leaf1],
		0,
		&DEFAULT_LEAF,
	)
	.unwrap();

	let mut in_leaves = BTreeMap::new();
	in_leaves.insert(in_chain_id, vec![
		leaf0.into_repr().to_bytes_le(),
		leaf1.into_repr().to_bytes_le(),
	]);
	let in_indices = [0, 1];
	let in_root_set = [
		smt.root().into_repr().to_bytes_le(),
		smt.root().into_repr().to_bytes_le(),
	];

	let proof = VAnchorR1CSProver_Bn254_Poseidon_30::create_proof(
		curve,
		in_chain_id,
		public_amount,
		ext_data_hash.into_repr().to_bytes_le(),
		in_root_set,
		in_indices,
		in_leaves,
		in_utxos,
		out_utxos,
		proving_key,
		DEFAULT_LEAF,
		rng,
	)
	.unwrap();

	let pub_ins = proof
		.public_inputs_raw
		.iter()
		.map(|inp| BnFr::from_le_bytes_mod_order(inp.as_slice()))
		.collect::<Vec<_>>();

	let truncated_public_inputs = &pub_ins[2..];
	let vk = VerifyingKey::<Bn254>::deserialize_unchecked(&verifying_key[..]).unwrap();
	let proof = Proof::<Bn254>::deserialize(&proof.proof[..]).unwrap();
	let res = Groth16::<Bn254>::verify(&vk, truncated_public_inputs, &proof);

	assert!(res.is_err());
}

#[test]
fn should_create_circuit_and_prove_with_default_utxos() {
	let rng = &mut test_rng();
	let curve = Curve::Bn254;
	let params3 = setup_params::<BnFr>(curve, 5, 3);
	let tree_hasher = Poseidon::<BnFr> { params: params3 };

	// Set up a random circuit and make pk/vk pair
	let random_circuit =
		VAnchorR1CSProver_Bn254_Poseidon_30::setup_random_circuit(curve, DEFAULT_LEAF, rng)
			.unwrap();
	let (proving_key, verifying_key) =
		setup_keys_unchecked::<Bn254, _, _>(random_circuit, rng).unwrap();

	let public_amount = 10;
	let ext_data_hash = BnFr::rand(rng);

	// Default input utxos
	let amount = 0;
	let in_chain_id = 0u64;
	let in_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30::create_random_utxo(
		curve,
		in_chain_id,
		amount,
		Some(0u64),
		rng,
	)
	.unwrap();

	let in_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30::create_random_utxo(
		curve,
		in_chain_id,
		amount,
		Some(0u64),
		rng,
	)
	.unwrap();

	let in_utxos = [in_utxo1.clone(), in_utxo2.clone()];

	// Output Utxos
	let out_chain_id = 0u64;
	let out_amount = 5;
	let out_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxos = [out_utxo1.clone(), out_utxo2.clone()];

	let leaf = BnFr::rand(rng);
	let (smt, _) = setup_tree_and_create_path::<BnFr, Poseidon<BnFr>, HEIGHT>(
		&tree_hasher,
		&vec![leaf],
		0,
		&DEFAULT_LEAF,
	)
	.unwrap();

	let in_leaves = BTreeMap::new();
	let in_indices = [0, 0];
	let in_root_set = [
		smt.root().into_repr().to_bytes_le(),
		smt.root().into_repr().to_bytes_le(),
	];

	let proof = VAnchorR1CSProver_Bn254_Poseidon_30::create_proof(
		curve,
		in_chain_id,
		public_amount,
		ext_data_hash.into_repr().to_bytes_le(),
		in_root_set,
		in_indices,
		in_leaves,
		in_utxos,
		out_utxos,
		proving_key,
		DEFAULT_LEAF,
		rng,
	)
	.unwrap();

	let pub_ins = proof
		.public_inputs_raw
		.iter()
		.map(|inp| BnFr::from_le_bytes_mod_order(inp.as_slice()))
		.collect::<Vec<_>>();
	let res = verify_unchecked::<Bn254>(&pub_ins, &verifying_key, &proof.proof).unwrap();

	assert!(res);
}

#[test]
fn should_create_circuit_and_prove_with_16_utxos() {
	let rng = &mut test_rng();
	let curve = Curve::Bn254;
	let params3 = setup_params::<BnFr>(curve, 5, 3);
	let tree_hasher = Poseidon::<BnFr> { params: params3 };

	// Set up a random circuit and make pk/vk pair
	let random_circuit =
		VAnchorR1CSProver_Bn254_Poseidon_30_16_in::setup_random_circuit(curve, DEFAULT_LEAF, rng)
			.unwrap();
	let (proving_key, verifying_key) =
		setup_keys_unchecked::<Bn254, _, _>(random_circuit, rng).unwrap();

	let public_amount = 10;
	let ext_data_hash = BnFr::rand(rng);

	// Default input utxos
	let amount = 0;
	let in_chain_id = 0u64;
	let mut in_utxos_list: Vec<_> = vec![];
	let mut utxo_index = 0;
	loop {
		if in_utxos_list.len() == 16 {
			break;
		}
		let utxo = VAnchorR1CSProver_Bn254_Poseidon_30_16_in::create_random_utxo(
			curve,
			in_chain_id,
			amount,
			Some(utxo_index),
			rng,
		)
		.unwrap();
		utxo_index += 1;
		in_utxos_list.push(utxo)
	}

	let in_utxos: [_; 16] = in_utxos_list
		.clone()
		.try_into()
		.map_err(|_| "".to_string())
		.unwrap();

	// Output Utxos
	let out_chain_id = 0u64;
	let out_amount = 5;
	let out_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30_16_in::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30_16_in::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxos = [out_utxo1.clone(), out_utxo2.clone()];

	let leaves = in_utxos_list
		.iter()
		.map(|utxo| utxo.commitment)
		.collect::<Vec<_>>();
	let (smt, _) = setup_tree_and_create_path::<BnFr, Poseidon<BnFr>, HEIGHT>(
		&tree_hasher,
		&leaves,
		0,
		&DEFAULT_LEAF,
	)
	.unwrap();

	let in_leaves = BTreeMap::new();
	let in_indices = in_utxos_list
		.iter()
		.enumerate()
		.map(|(index, _)| index as u64)
		.collect::<Vec<u64>>();
	let in_root_set = [
		smt.root().into_repr().to_bytes_le(),
		smt.root().into_repr().to_bytes_le(),
	];
	let in_indices = in_indices.try_into().unwrap();
	let proof = VAnchorR1CSProver_Bn254_Poseidon_30_16_in::create_proof(
		curve,
		in_chain_id,
		public_amount,
		ext_data_hash.into_repr().to_bytes_le(),
		in_root_set,
		in_indices,
		in_leaves,
		in_utxos,
		out_utxos,
		proving_key,
		DEFAULT_LEAF,
		rng,
	)
	.unwrap();

	let pub_ins = proof
		.public_inputs_raw
		.iter()
		.map(|inp| BnFr::from_le_bytes_mod_order(inp.as_slice()))
		.collect::<Vec<_>>();
	let res = verify_unchecked::<Bn254>(&pub_ins, &verifying_key, &proof.proof).unwrap();

	assert!(res);
}
