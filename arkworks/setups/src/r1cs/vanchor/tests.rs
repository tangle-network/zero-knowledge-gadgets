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
const INS_2: usize = 2;
const INS_16: usize = 16;
const OUTS: usize = 2;

#[allow(non_camel_case_types)]
type VAnchorR1CSProver_Bn254_Poseidon_30_2_2 =
	VAnchorR1CSProver<Bn254, HEIGHT, ANCHOR_CT, INS_2, OUTS>;
#[allow(non_camel_case_types)]
type VAnchorR1CSProver_Bn254_Poseidon_30_16_2 =
	VAnchorR1CSProver<Bn254, HEIGHT, ANCHOR_CT, INS_16, OUTS>;
const DEFAULT_LEAF: [u8; 32] = [0u8; 32];

#[test]
fn should_create_proof_for_random_circuit() {
	let rng = &mut test_rng();
	let curve = Curve::Bn254;
	let params3 = setup_params::<BnFr>(curve, 5, 3);
	let tree_hasher = Poseidon::<BnFr> { params: params3 };

	// Set up a random circuit and make pk/vk pair
	let random_circuit =
		VAnchorR1CSProver_Bn254_Poseidon_30_2_2::setup_random_circuit(curve, DEFAULT_LEAF, rng)
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
	let in_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30_2_2::create_random_utxo(
		curve,
		in_chain_id,
		in_amount,
		Some(index),
		rng,
	)
	.unwrap();
	let in_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30_2_2::create_random_utxo(
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
	let out_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30_2_2::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30_2_2::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxos = [out_utxo1, out_utxo2];

	let leaf0 = in_utxo1.commitment;
	let leaf1 = in_utxo2.commitment;

	let (smt, _) = setup_tree_and_create_path::<BnFr, Poseidon<BnFr>, HEIGHT>(
		&tree_hasher,
		&[leaf0, leaf1],
		0,
		&DEFAULT_LEAF,
	)
	.unwrap();

	let mut in_leaves = BTreeMap::new();
	in_leaves.insert(in_chain_id, vec![
		leaf0.into_repr().to_bytes_be(),
		leaf1.into_repr().to_bytes_be(),
	]);
	let in_indices = [0, 1];
	let in_root_set = [
		smt.root().into_repr().to_bytes_be(),
		smt.root().into_repr().to_bytes_be(),
	];

	let proof = VAnchorR1CSProver_Bn254_Poseidon_30_2_2::create_proof(
		curve,
		in_chain_id,
		public_amount,
		ext_data_hash.into_repr().to_bytes_be(),
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
		.map(|inp| BnFr::from_be_bytes_mod_order(inp.as_slice()))
		.collect::<Vec<_>>();
	let res = verify_unchecked::<Bn254>(&pub_ins, &verifying_key, &proof.proof).unwrap();

	assert!(res);
}

#[test]
fn should_create_circuit_and_prove_groth16_2_input_2_output() {
	let rng = &mut test_rng();
	let curve = Curve::Bn254;
	let params3 = setup_params::<BnFr>(curve, 5, 3);
	let tree_hasher = Poseidon::<BnFr> { params: params3 };

	// Set up a random circuit and make pk/vk pair
	let random_circuit =
		VAnchorR1CSProver_Bn254_Poseidon_30_2_2::setup_random_circuit(curve, DEFAULT_LEAF, rng)
			.unwrap();
	let (proving_key, verifying_key) =
		setup_keys_unchecked::<Bn254, _, _>(random_circuit, rng).unwrap();

	let public_amount = 10;
	let ext_data_hash = BnFr::rand(rng);

	// Input Utxos
	let in_chain_id = 0u64;
	let in_amount = 5;
	let mut in_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30_2_2::create_random_utxo(
		curve,
		in_chain_id,
		in_amount,
		None,
		rng,
	)
	.unwrap();
	// Setting the index after the fact to test the function
	in_utxo1.set_index(0);

	let mut in_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30_2_2::create_random_utxo(
		curve,
		in_chain_id,
		in_amount,
		None,
		rng,
	)
	.unwrap();
	// Setting the index after the fact to test the function
	in_utxo2.set_index(1);

	let in_utxos = [in_utxo1.clone(), in_utxo2.clone()];

	// Output Utxos
	let out_chain_id = 0u64;
	let out_amount = 10;
	let out_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30_2_2::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30_2_2::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxos = [out_utxo1, out_utxo2];

	let leaf0 = in_utxo1.commitment;
	let leaf1 = in_utxo2.commitment;

	let (smt, _) = setup_tree_and_create_path::<BnFr, Poseidon<BnFr>, HEIGHT>(
		&tree_hasher,
		&[leaf0, leaf1],
		0,
		&DEFAULT_LEAF,
	)
	.unwrap();

	let mut in_leaves = BTreeMap::new();
	in_leaves.insert(in_chain_id, vec![
		leaf0.into_repr().to_bytes_be(),
		leaf1.into_repr().to_bytes_be(),
	]);
	let in_indices = [0, 1];
	let in_root_set = [
		smt.root().into_repr().to_bytes_be(),
		smt.root().into_repr().to_bytes_be(),
	];

	let proof = VAnchorR1CSProver_Bn254_Poseidon_30_2_2::create_proof(
		curve,
		in_chain_id,
		public_amount,
		ext_data_hash.into_repr().to_bytes_be(),
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
		.map(|inp| BnFr::from_be_bytes_mod_order(inp.as_slice()))
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
		VAnchorR1CSProver_Bn254_Poseidon_30_2_2::setup_random_circuit(curve, DEFAULT_LEAF, rng)
			.unwrap();
	let (proving_key, verifying_key) =
		setup_keys_unchecked::<Bn254, _, _>(random_circuit, rng).unwrap();

	let public_amount = 10;
	let ext_data_hash = BnFr::rand(rng);

	// Input Utxos
	let in_chain_id = 0u64;
	let in_amount = 5;
	let index = 0u64;
	let in_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30_2_2::create_random_utxo(
		curve,
		in_chain_id,
		in_amount,
		Some(index),
		rng,
	)
	.unwrap();
	let in_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30_2_2::create_random_utxo(
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
	let out_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30_2_2::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30_2_2::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxos = [out_utxo1, out_utxo2];

	let leaf0 = in_utxo1.commitment;
	let leaf1 = in_utxo2.commitment;

	let (smt, _) = setup_tree_and_create_path::<BnFr, Poseidon<BnFr>, HEIGHT>(
		&tree_hasher,
		&[leaf0, leaf1],
		0,
		&DEFAULT_LEAF,
	)
	.unwrap();

	let mut in_leaves = BTreeMap::new();
	in_leaves.insert(in_chain_id, vec![
		leaf0.into_repr().to_bytes_be(),
		leaf1.into_repr().to_bytes_be(),
	]);
	let in_indices = [0, 1];
	let in_root_set = [
		smt.root().into_repr().to_bytes_be(),
		smt.root().into_repr().to_bytes_be(),
	];

	let proof = VAnchorR1CSProver_Bn254_Poseidon_30_2_2::create_proof(
		curve,
		in_chain_id,
		public_amount,
		ext_data_hash.into_repr().to_bytes_be(),
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
		.map(|inp| BnFr::from_be_bytes_mod_order(inp.as_slice()))
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
		VAnchorR1CSProver_Bn254_Poseidon_30_2_2::setup_random_circuit(curve, DEFAULT_LEAF, rng)
			.unwrap();
	let (proving_key, verifying_key) =
		setup_keys_unchecked::<Bn254, _, _>(random_circuit, rng).unwrap();

	let public_amount = 0;
	let ext_data_hash = BnFr::rand(rng);

	// Input Utxos
	let in_chain_id = 0u64;
	let in_amount = 5;
	let index = 0u64;
	let in_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30_2_2::create_random_utxo(
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
	let out_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30_2_2::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30_2_2::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxos = [out_utxo1, out_utxo2];

	let leaf0 = in_utxo1.commitment;

	let (smt, _) = setup_tree_and_create_path::<BnFr, Poseidon<BnFr>, HEIGHT>(
		&tree_hasher,
		&[leaf0],
		0,
		&DEFAULT_LEAF,
	)
	.unwrap();

	let mut in_leaves = BTreeMap::new();
	in_leaves.insert(in_chain_id, vec![
		leaf0.into_repr().to_bytes_be(),
		leaf0.into_repr().to_bytes_be(),
	]);
	let in_indices = [0, 0];
	let in_root_set = [
		smt.root().into_repr().to_bytes_be(),
		smt.root().into_repr().to_bytes_be(),
	];

	let proof = VAnchorR1CSProver_Bn254_Poseidon_30_2_2::create_proof(
		curve,
		in_chain_id,
		public_amount,
		ext_data_hash.into_repr().to_bytes_be(),
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
		.map(|inp| BnFr::from_be_bytes_mod_order(inp.as_slice()))
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
		VAnchorR1CSProver_Bn254_Poseidon_30_2_2::setup_random_circuit(curve, DEFAULT_LEAF, rng)
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
	let in_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30_2_2::create_random_utxo(
		curve,
		in_chain_id,
		in_amount,
		Some(index),
		rng,
	)
	.unwrap();
	let in_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30_2_2::create_random_utxo(
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
	let out_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30_2_2::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30_2_2::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxos = [out_utxo1, out_utxo2];

	let leaf0 = in_utxo1.commitment;
	let leaf1 = in_utxo2.commitment;

	let (smt, _) = setup_tree_and_create_path::<BnFr, Poseidon<BnFr>, HEIGHT>(
		&tree_hasher,
		&[leaf0, leaf1],
		0,
		&DEFAULT_LEAF,
	)
	.unwrap();

	let mut in_leaves = BTreeMap::new();
	in_leaves.insert(in_chain_id, vec![
		leaf0.into_repr().to_bytes_be(),
		leaf1.into_repr().to_bytes_be(),
	]);
	let in_indices = [0, 1];
	let in_root_set = [
		smt.root().into_repr().to_bytes_be(),
		smt.root().into_repr().to_bytes_be(),
	];

	let proof = VAnchorR1CSProver_Bn254_Poseidon_30_2_2::create_proof(
		curve,
		in_chain_id,
		public_amount,
		ext_data_hash.into_repr().to_bytes_be(),
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
		.map(|inp| BnFr::from_be_bytes_mod_order(inp.as_slice()))
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
		VAnchorR1CSProver_Bn254_Poseidon_30_2_2::setup_random_circuit(curve, DEFAULT_LEAF, rng)
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
	let in_amount = limit + BnFr::one();
	let index = 0u64;
	let in_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30_2_2::new_utxo(
		curve,
		in_chain_id,
		in_amount,
		Some(index),
		None,
		None,
		rng,
	)
	.unwrap();
	let in_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30_2_2::new_utxo(
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
	let out_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30_2_2::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30_2_2::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxos = [out_utxo1, out_utxo2];

	let leaf0 = in_utxo1.commitment;
	let leaf1 = in_utxo2.commitment;

	let (smt, _) = setup_tree_and_create_path::<BnFr, Poseidon<BnFr>, HEIGHT>(
		&tree_hasher,
		&[leaf0, leaf1],
		0,
		&DEFAULT_LEAF,
	)
	.unwrap();

	let mut in_leaves = BTreeMap::new();
	in_leaves.insert(in_chain_id, vec![
		leaf0.into_repr().to_bytes_be(),
		leaf1.into_repr().to_bytes_be(),
	]);
	let in_indices = [0, 1];
	let in_root_set = [
		smt.root().into_repr().to_bytes_be(),
		smt.root().into_repr().to_bytes_be(),
	];

	let proof = VAnchorR1CSProver_Bn254_Poseidon_30_2_2::create_proof(
		curve,
		in_chain_id,
		public_amount,
		ext_data_hash.into_repr().to_bytes_be(),
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
		.map(|inp| BnFr::from_be_bytes_mod_order(inp.as_slice()))
		.collect::<Vec<_>>();
	let res = verify_unchecked::<Bn254>(&pub_ins, &verifying_key, &proof.proof).unwrap();

	assert!(!res);
}

#[test]
fn should_fail_with_invalid_public_input() {
	let rng = &mut test_rng();
	let curve = Curve::Bn254;
	let params3 = setup_params::<BnFr>(curve, 5, 3);
	let tree_hasher = Poseidon::<BnFr> { params: params3 };
	// Set up a random circuit and make pk/vk pair
	let random_circuit =
		VAnchorR1CSProver_Bn254_Poseidon_30_2_2::setup_random_circuit(curve, DEFAULT_LEAF, rng)
			.unwrap();
	let (proving_key, verifying_key) =
		setup_keys_unchecked::<Bn254, _, _>(random_circuit, rng).unwrap();

	let public_amount = 0;
	let ext_data_hash = BnFr::rand(rng);

	// Input Utxos
	let in_chain_id = 0u64;
	let in_amount = 5;
	let index = 0u64;
	let mut in_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30_2_2::create_random_utxo(
		curve,
		in_chain_id,
		in_amount,
		None,
		rng,
	)
	.unwrap();
	// Setting the index after the fact to test the function
	in_utxo1.set_index(index);

	let mut in_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30_2_2::create_random_utxo(
		curve,
		in_chain_id,
		in_amount,
		Some(index),
		rng,
	)
	.unwrap();
	// Setting the index after the fact to test the function
	in_utxo2.set_index(index);

	let in_utxos = [in_utxo1.clone(), in_utxo2.clone()];

	// Output Utxos
	let out_chain_id = 0u64;
	let out_amount = 10;
	let out_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30_2_2::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30_2_2::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxos = [out_utxo1, out_utxo2];

	let leaf0 = in_utxo1.commitment;
	let leaf1 = in_utxo2.commitment;

	let (smt, _) = setup_tree_and_create_path::<BnFr, Poseidon<BnFr>, HEIGHT>(
		&tree_hasher,
		&[leaf0, leaf1],
		0,
		&DEFAULT_LEAF,
	)
	.unwrap();

	let mut in_leaves = BTreeMap::new();
	in_leaves.insert(in_chain_id, vec![
		leaf0.into_repr().to_bytes_be(),
		leaf1.into_repr().to_bytes_be(),
	]);
	let in_indices = [0, 1];
	let in_root_set = [
		smt.root().into_repr().to_bytes_be(),
		smt.root().into_repr().to_bytes_be(),
	];

	let proof = VAnchorR1CSProver_Bn254_Poseidon_30_2_2::create_proof(
		curve,
		in_chain_id,
		public_amount,
		ext_data_hash.into_repr().to_bytes_be(),
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
		.map(|inp| BnFr::from_be_bytes_mod_order(inp.as_slice()))
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
		VAnchorR1CSProver_Bn254_Poseidon_30_2_2::setup_random_circuit(curve, DEFAULT_LEAF, rng)
			.unwrap();
	let (proving_key, verifying_key) =
		setup_keys_unchecked::<Bn254, _, _>(random_circuit, rng).unwrap();

	let public_amount = 10;
	let ext_data_hash = BnFr::rand(rng);

	// Default input utxos
	let amount = 0;
	let in_chain_id = 0u64;
	let in_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30_2_2::create_random_utxo(
		curve,
		in_chain_id,
		amount,
		Some(0u64),
		rng,
	)
	.unwrap();

	let in_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30_2_2::create_random_utxo(
		curve,
		in_chain_id,
		amount,
		Some(0u64),
		rng,
	)
	.unwrap();

	let in_utxos = [in_utxo1, in_utxo2];

	// Output Utxos
	let out_chain_id = 0u64;
	let out_amount = 5;
	let out_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30_2_2::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30_2_2::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxos = [out_utxo1, out_utxo2];

	let leaf = BnFr::rand(rng);
	let (smt, _) = setup_tree_and_create_path::<BnFr, Poseidon<BnFr>, HEIGHT>(
		&tree_hasher,
		&[leaf],
		0,
		&DEFAULT_LEAF,
	)
	.unwrap();

	let in_leaves = BTreeMap::new();
	let in_indices = [0, 0];
	let in_root_set = [
		smt.root().into_repr().to_bytes_be(),
		smt.root().into_repr().to_bytes_be(),
	];

	let proof = VAnchorR1CSProver_Bn254_Poseidon_30_2_2::create_proof(
		curve,
		in_chain_id,
		public_amount,
		ext_data_hash.into_repr().to_bytes_be(),
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
		.map(|inp| BnFr::from_be_bytes_mod_order(inp.as_slice()))
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
		VAnchorR1CSProver_Bn254_Poseidon_30_16_2::setup_random_circuit(curve, DEFAULT_LEAF, rng)
			.unwrap();
	let (proving_key, verifying_key) =
		setup_keys_unchecked::<Bn254, _, _>(random_circuit, rng).unwrap();

	let public_amount = 10;
	let ext_data_hash = BnFr::rand(rng);

	// Default input utxos
	let amount = 10;
	let in_chain_id = 0u64;
	let mut in_utxos_list: Vec<_> = vec![];
	let mut utxo_index = 0;
	loop {
		if in_utxos_list.len() == 16 {
			break;
		}
		let utxo = VAnchorR1CSProver_Bn254_Poseidon_30_16_2::create_random_utxo(
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
	let out_amount = 85;
	let out_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30_16_2::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30_16_2::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxos = [out_utxo1, out_utxo2];

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

	let mut in_leaves = BTreeMap::new();
	let leaves_bytes = leaves
		.iter()
		.map(|f| f.into_repr().to_bytes_be())
		.collect::<Vec<_>>();
	in_leaves.insert(in_chain_id, leaves_bytes);
	let in_indices = in_utxos_list
		.iter()
		.enumerate()
		.map(|(index, _)| index as u64)
		.collect::<Vec<u64>>();
	let in_root_set = [
		smt.root().into_repr().to_bytes_be(),
		smt.root().into_repr().to_bytes_be(),
	];
	let in_indices = in_indices.try_into().unwrap();
	let proof = VAnchorR1CSProver_Bn254_Poseidon_30_16_2::create_proof(
		curve,
		in_chain_id,
		public_amount,
		ext_data_hash.into_repr().to_bytes_be(),
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
		.map(|inp| BnFr::from_be_bytes_mod_order(inp.as_slice()))
		.collect::<Vec<_>>();
	let res = verify_unchecked::<Bn254>(&pub_ins, &verifying_key, &proof.proof).unwrap();

	assert!(res);
}

#[test]
fn should_create_circuit_and_prove_with_16_default_utxos() {
	let rng = &mut test_rng();
	let curve = Curve::Bn254;
	let params3 = setup_params::<BnFr>(curve, 5, 3);
	let tree_hasher = Poseidon::<BnFr> { params: params3 };

	// Set up a random circuit and make pk/vk pair
	let random_circuit =
		VAnchorR1CSProver_Bn254_Poseidon_30_16_2::setup_random_circuit(curve, DEFAULT_LEAF, rng)
			.unwrap();
	let (proving_key, verifying_key) =
		setup_keys_unchecked::<Bn254, _, _>(random_circuit, rng).unwrap();

	let public_amount = 10;
	let ext_data_hash = BnFr::rand(rng);

	// Default input utxos
	let amount = 0;
	let in_chain_id = 0u64;
	let mut in_utxos_list: Vec<_> = vec![];
	loop {
		if in_utxos_list.len() == 16 {
			break;
		}
		let utxo = VAnchorR1CSProver_Bn254_Poseidon_30_16_2::create_random_utxo(
			curve,
			in_chain_id,
			amount,
			Some(0u64),
			rng,
		)
		.unwrap();
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
	let out_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30_16_2::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30_16_2::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxos = [out_utxo1, out_utxo2];

	let leaf = BnFr::rand(rng);
	let (smt, _) = setup_tree_and_create_path::<BnFr, Poseidon<BnFr>, HEIGHT>(
		&tree_hasher,
		&[leaf],
		0,
		&DEFAULT_LEAF,
	)
	.unwrap();

	let in_leaves = BTreeMap::new();
	let in_indices = [0; 16];
	let in_root_set = [
		smt.root().into_repr().to_bytes_be(),
		smt.root().into_repr().to_bytes_be(),
	];

	let proof = VAnchorR1CSProver_Bn254_Poseidon_30_16_2::create_proof(
		curve,
		in_chain_id,
		public_amount,
		ext_data_hash.into_repr().to_bytes_be(),
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
		.map(|inp| BnFr::from_be_bytes_mod_order(inp.as_slice()))
		.collect::<Vec<_>>();
	let res = verify_unchecked::<Bn254>(&pub_ins, &verifying_key, &proof.proof).unwrap();

	assert!(res);
}

#[test]
fn should_create_circuit_and_prove_with_16_mixed_utxos() {
	// Input 8 non-default utxo with amount 20 each
	// Input 8 different default utxos
	// public amount 10 => 8 * 20 + 10 = 170
	// Output 2 utxos with amount 85
	let rng = &mut test_rng();
	let curve = Curve::Bn254;
	let params3 = setup_params::<BnFr>(curve, 5, 3);
	let tree_hasher = Poseidon::<BnFr> { params: params3 };

	// Set up a random circuit and make pk/vk pair
	let random_circuit =
		VAnchorR1CSProver_Bn254_Poseidon_30_16_2::setup_random_circuit(curve, DEFAULT_LEAF, rng)
			.unwrap();
	let (proving_key, verifying_key) =
		setup_keys_unchecked::<Bn254, _, _>(random_circuit, rng).unwrap();

	let public_amount = 10;
	let ext_data_hash = BnFr::rand(rng);

	// Default input utxos
	let amount = 20;
	let in_chain_id = 0u64;
	let mut in_utxos_list: Vec<_> = vec![];
	let mut utxo_index = 0;

	loop {
		if in_utxos_list.len() == 16 {
			break;
		}
		let non_default_utxo = VAnchorR1CSProver_Bn254_Poseidon_30_16_2::create_random_utxo(
			curve,
			in_chain_id,
			amount,
			Some(utxo_index),
			rng,
		)
		.unwrap();
		// should create a different default utxo each time to avoid Error
		// `AssignmentMissing`
		let default_utxo = VAnchorR1CSProver_Bn254_Poseidon_30_16_2::create_random_utxo(
			curve,
			in_chain_id,
			0,
			Some(0u64),
			rng,
		)
		.unwrap();
		utxo_index += 1;
		in_utxos_list.push(non_default_utxo);
		in_utxos_list.push(default_utxo.clone());
	}

	let in_utxos: [_; 16] = in_utxos_list
		.clone()
		.try_into()
		.map_err(|_| "".to_string())
		.unwrap();

	// Output Utxos
	let out_chain_id = 0u64;
	let out_amount = 85;
	let out_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30_16_2::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30_16_2::create_random_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		rng,
	)
	.unwrap();
	let out_utxos = [out_utxo1, out_utxo2];

	let leaves = in_utxos_list
		.iter()
		.filter(|u| u.amount != BnFr::zero())
		.map(|utxo| utxo.commitment)
		.collect::<Vec<_>>();
	let (smt, _) = setup_tree_and_create_path::<BnFr, Poseidon<BnFr>, HEIGHT>(
		&tree_hasher,
		&leaves,
		0,
		&DEFAULT_LEAF,
	)
	.unwrap();
	let leaves_bytes = leaves
		.iter()
		.map(|f| f.into_repr().to_bytes_be())
		.collect::<Vec<_>>();
	let mut in_leaves = BTreeMap::new();
	in_leaves.insert(in_chain_id, leaves_bytes);

	let in_indices = in_utxos_list
		.iter()
		.map(|u| u.index.unwrap_or(0))
		.collect::<Vec<_>>()
		.try_into()
		.unwrap();
	let in_root_set = [
		smt.root().into_repr().to_bytes_be(),
		smt.root().into_repr().to_bytes_be(),
	];

	let proof = VAnchorR1CSProver_Bn254_Poseidon_30_16_2::create_proof(
		curve,
		in_chain_id,
		public_amount,
		ext_data_hash.into_repr().to_bytes_be(),
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
		.map(|inp| BnFr::from_be_bytes_mod_order(inp.as_slice()))
		.collect::<Vec<_>>();
	let res = verify_unchecked::<Bn254>(&pub_ins, &verifying_key, &proof.proof).unwrap();

	assert!(res);
}

#[test]
fn should_calculate_and_set_nullifier() {
	let rng = &mut test_rng();
	let params4 = setup_params::<BnFr>(Curve::Bn254, 5, 4);
	let nullifier_hasher = Poseidon::<BnFr> { params: params4 };

	let mut out_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30_16_2::create_random_utxo(
		Curve::Bn254,
		1,
		10,
		None,
		rng,
	)
	.unwrap();
	let index_before = out_utxo1.index;
	let nullifier_before = out_utxo1.calculate_nullifier(&nullifier_hasher);

	assert_eq!(index_before.is_none(), true);
	assert_eq!(nullifier_before.is_err(), true);

	out_utxo1.set_index(2);
	let nullifier_after = out_utxo1.calculate_nullifier(&nullifier_hasher).unwrap();

	out_utxo1.set_index(6);
	let nullifier_recalculated = out_utxo1.calculate_nullifier(&nullifier_hasher).unwrap();

	assert_ne!(nullifier_after, nullifier_recalculated);
}
