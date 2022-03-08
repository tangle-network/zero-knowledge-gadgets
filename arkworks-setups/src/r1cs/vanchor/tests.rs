use ark_std::vec;

use crate::common::*;
use ark_serialize::CanonicalDeserialize;
use ark_std::{One, Zero};
use arkworks_native_gadgets::poseidon::Poseidon;
use arkworks_r1cs_gadgets::poseidon::PoseidonGadget;
use arkworks_utils::Curve;

use ark_bn254::{Bn254, Fr as BnFr};
use ark_ff::UniformRand;
use ark_groth16::{Groth16, Proof, VerifyingKey};

use ark_snark::SNARK;
use ark_std::{str::FromStr, test_rng};

use super::{setup_params, VAnchorR1CSProver};

const HEIGHT: usize = 30;
const ANCHOR_CT: usize = 2;
const INS: usize = 2;
const OUTS: usize = 2;

#[allow(non_camel_case_types)]
type VAnchorR1CSProver_Bn254_Poseidon_30 = VAnchorR1CSProver<Bn254, HEIGHT, INS, OUTS, ANCHOR_CT>;
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
	let (proving_key, verifying_key) = setup_keys::<Bn254, _, _>(random_circuit, rng).unwrap();

	// Make a proof now
	let public_amount = BnFr::from(10u32);
	let ext_data_hash = BnFr::rand(rng);

	// Input Utxos
	let in_chain_id = 0u64;
	let in_amount = BnFr::from(5u32);
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
	let out_amount = BnFr::from(10u32);
	let out_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30::new_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		None,
		None,
		rng,
	)
	.unwrap();
	let out_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30::new_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		None,
		None,
		rng,
	)
	.unwrap();
	let out_utxos = [out_utxo1.clone(), out_utxo2.clone()];

	let leaf0 = in_utxo1.commitment;
	let (_, in_path0) = setup_tree_and_create_path::<BnFr, PoseidonGadget<BnFr>, HEIGHT>(
		tree_hasher.clone(),
		&vec![leaf0],
		0,
		&DEFAULT_LEAF,
	)
	.unwrap();
	let root0 = in_path0.calculate_root(&leaf0, &tree_hasher).unwrap();
	let leaf1 = in_utxo2.commitment;
	let (_, in_path1) = setup_tree_and_create_path::<BnFr, PoseidonGadget<BnFr>, HEIGHT>(
		tree_hasher.clone(),
		&vec![leaf1],
		0,
		&DEFAULT_LEAF,
	)
	.unwrap();
	let root1 = in_path1.calculate_root(&leaf1, &tree_hasher).unwrap();

	let in_leaves = [vec![leaf0], vec![leaf1]];
	let in_indices = [0; 2];
	let in_root_set = [root0, root1];

	let (circuit, .., pub_ins) = VAnchorR1CSProver_Bn254_Poseidon_30::setup_circuit_with_utxos(
		curve,
		BnFr::from(in_chain_id),
		public_amount,
		ext_data_hash,
		in_root_set,
		in_indices,
		in_leaves,
		in_utxos,
		out_utxos,
		DEFAULT_LEAF,
	)
	.unwrap();

	let proof = prove::<Bn254, _, _>(circuit, &proving_key, rng).unwrap();
	let res = verify::<Bn254>(&pub_ins, &verifying_key, &proof).unwrap();

	assert!(res);
}

#[test]
fn should_create_circuit_and_prove_groth16_2_input_2_output() {
	let rng = &mut test_rng();
	let curve = Curve::Bn254;
	let params3 = setup_params::<BnFr>(curve, 5, 3);
	let tree_hasher = Poseidon::<BnFr> { params: params3 };

	let public_amount = BnFr::from(10u32);
	let ext_data_hash = BnFr::rand(rng);

	// Input Utxos
	let in_chain_id = 0u64;
	let in_amount = BnFr::from(5u32);
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
	let out_amount = BnFr::from(10u32);
	let out_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30::new_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		None,
		None,
		rng,
	)
	.unwrap();
	let out_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30::new_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		None,
		None,
		rng,
	)
	.unwrap();
	let out_utxos = [out_utxo1.clone(), out_utxo2.clone()];

	let leaf0 = in_utxo1.commitment;
	let (_, in_path0) = setup_tree_and_create_path::<BnFr, PoseidonGadget<BnFr>, HEIGHT>(
		tree_hasher.clone(),
		&vec![leaf0],
		0,
		&DEFAULT_LEAF,
	)
	.unwrap();
	let root0 = in_path0.calculate_root(&leaf0, &tree_hasher).unwrap();
	let leaf1 = in_utxo2.commitment;
	let (_, in_path1) = setup_tree_and_create_path::<BnFr, PoseidonGadget<BnFr>, HEIGHT>(
		tree_hasher.clone(),
		&vec![leaf1],
		0,
		&DEFAULT_LEAF,
	)
	.unwrap();
	let root1 = in_path1.calculate_root(&leaf1, &tree_hasher).unwrap();

	let in_leaves = [vec![leaf0], vec![leaf1]];
	let in_indices = [0; 2];
	let in_root_set = [root0, root1];

	let (circuit, .., pub_ins) = VAnchorR1CSProver_Bn254_Poseidon_30::setup_circuit_with_utxos(
		curve,
		BnFr::from(in_chain_id),
		public_amount,
		ext_data_hash,
		in_root_set,
		in_indices,
		in_leaves,
		in_utxos,
		out_utxos,
		DEFAULT_LEAF,
	)
	.unwrap();

	let (proving_key, verifying_key) = setup_keys::<Bn254, _, _>(circuit.clone(), rng).unwrap();
	let proof = prove::<Bn254, _, _>(circuit, &proving_key, rng).unwrap();
	let res = verify::<Bn254>(&pub_ins, &verifying_key, &proof).unwrap();

	assert!(res);
}

#[test]
fn should_fail_with_invalid_root() {
	let rng = &mut test_rng();
	let curve = Curve::Bn254;

	let public_amount = BnFr::from(10u32);
	let ext_data_hash = BnFr::rand(rng);

	// Input Utxos
	let in_chain_id = 0u64;
	let in_amount = BnFr::from(5u32);
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
	let out_amount = BnFr::from(10u32);
	let out_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30::new_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		None,
		None,
		rng,
	)
	.unwrap();
	let out_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30::new_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		None,
		None,
		rng,
	)
	.unwrap();
	let out_utxos = [out_utxo1.clone(), out_utxo2.clone()];

	let leaf0 = in_utxos[0].commitment;
	let leaf1 = in_utxos[1].commitment;

	let in_leaves = [vec![leaf0], vec![leaf1]];
	let in_indices = [0; 2];

	// Invalid root set
	let in_root_set = [BnFr::rand(rng); 2];

	let (circuit, .., pub_ins) = VAnchorR1CSProver_Bn254_Poseidon_30::setup_circuit_with_utxos(
		curve,
		BnFr::from(in_chain_id),
		public_amount,
		ext_data_hash,
		in_root_set,
		in_indices,
		in_leaves,
		in_utxos,
		out_utxos,
		DEFAULT_LEAF,
	)
	.unwrap();

	let (proving_key, verifying_key) = setup_keys::<Bn254, _, _>(circuit.clone(), rng).unwrap();
	let proof = prove::<Bn254, _, _>(circuit, &proving_key, rng).unwrap();
	let res = verify::<Bn254>(&pub_ins, &verifying_key, &proof).unwrap();

	assert!(!res);
}

#[test]
fn should_fail_with_invalid_nullifier() {
	let rng = &mut test_rng();
	let curve = Curve::Bn254;
	let params3 = setup_params::<BnFr>(curve, 5, 3);
	let tree_hasher = Poseidon::<BnFr> { params: params3 };

	let public_amount = BnFr::from(10u32);
	let ext_data_hash = BnFr::rand(rng);

	// Input Utxos
	let in_chain_id = 0u64;
	let in_amount = BnFr::from(5u32);
	let index = 0u64;
	let mut in_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30::new_utxo(
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

	// Adding invalid nullifier
	in_utxo1.nullifier = Some(BnFr::rand(rng));

	let in_utxos = [in_utxo1.clone(), in_utxo2.clone()];

	// Output Utxos
	let out_chain_id = 0u64;
	let out_amount = BnFr::from(10u32);
	let out_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30::new_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		None,
		None,
		rng,
	)
	.unwrap();
	let out_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30::new_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		None,
		None,
		rng,
	)
	.unwrap();
	let out_utxos = [out_utxo1.clone(), out_utxo2.clone()];

	let leaf0 = in_utxos[0].commitment;
	let (_, in_path0) = setup_tree_and_create_path::<BnFr, PoseidonGadget<BnFr>, HEIGHT>(
		tree_hasher.clone(),
		&vec![leaf0],
		0,
		&DEFAULT_LEAF,
	)
	.unwrap();
	let root0 = in_path0.calculate_root(&leaf0, &tree_hasher).unwrap();
	let leaf1 = in_utxos[1].commitment;
	let (_, in_path1) = setup_tree_and_create_path::<BnFr, PoseidonGadget<BnFr>, HEIGHT>(
		tree_hasher.clone(),
		&vec![leaf1],
		0,
		&DEFAULT_LEAF,
	)
	.unwrap();
	let root1 = in_path1.calculate_root(&leaf1, &tree_hasher).unwrap();

	let in_leaves = [vec![leaf0], vec![leaf1]];
	let in_indices = [0; 2];
	let in_root_set = [root0, root1];

	let (circuit, .., pub_ins) = VAnchorR1CSProver_Bn254_Poseidon_30::setup_circuit_with_utxos(
		curve,
		BnFr::from(in_chain_id),
		public_amount,
		ext_data_hash,
		in_root_set,
		in_indices,
		in_leaves,
		in_utxos,
		out_utxos,
		DEFAULT_LEAF,
	)
	.unwrap();

	let (proving_key, verifying_key) = setup_keys::<Bn254, _, _>(circuit.clone(), rng).unwrap();
	let proof = prove::<Bn254, _, _>(circuit, &proving_key, rng).unwrap();
	let res = verify::<Bn254>(&pub_ins, &verifying_key, &proof).unwrap();

	assert!(!res);
}

#[test]
#[ignore]
fn should_fail_with_same_nullifier() {
	let rng = &mut test_rng();
	let curve = Curve::Bn254;
	let params3 = setup_params::<BnFr>(curve, 5, 3);
	let tree_hasher = Poseidon::<BnFr> { params: params3 };

	let public_amount = BnFr::from(0u32);
	let ext_data_hash = BnFr::rand(rng);

	// Input Utxos
	let in_chain_id = 0u64;
	let in_amount = BnFr::from(5u32);
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

	// Both inputs are the same -- attempt of double spending
	let in_utxos = [in_utxo1.clone(), in_utxo1.clone()];

	// Output Utxos
	let out_chain_id = 0u64;
	let out_amount = BnFr::from(10u32);
	let out_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30::new_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		None,
		None,
		rng,
	)
	.unwrap();
	let out_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30::new_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		None,
		None,
		rng,
	)
	.unwrap();
	let out_utxos = [out_utxo1.clone(), out_utxo2.clone()];

	let leaf0 = in_utxos[0].commitment;
	let (_, in_path0) = setup_tree_and_create_path::<BnFr, PoseidonGadget<BnFr>, HEIGHT>(
		tree_hasher.clone(),
		&vec![leaf0],
		0,
		&DEFAULT_LEAF,
	)
	.unwrap();
	let root0 = in_path0.calculate_root(&leaf0, &tree_hasher).unwrap();
	let leaf1 = in_utxos[1].commitment;
	let (_, in_path1) = setup_tree_and_create_path::<BnFr, PoseidonGadget<BnFr>, HEIGHT>(
		tree_hasher.clone(),
		&vec![leaf1],
		0,
		&DEFAULT_LEAF,
	)
	.unwrap();
	let root1 = in_path1.calculate_root(&leaf1, &tree_hasher).unwrap();

	let in_leaves = [vec![leaf0], vec![leaf1]];
	let in_indices = [0; 2];
	let in_root_set = [root0, root1];

	let (circuit, .., pub_ins) = VAnchorR1CSProver_Bn254_Poseidon_30::setup_circuit_with_utxos(
		curve,
		BnFr::from(in_chain_id),
		public_amount,
		ext_data_hash,
		in_root_set,
		in_indices,
		in_leaves,
		in_utxos,
		out_utxos,
		DEFAULT_LEAF,
	)
	.unwrap();

	let (proving_key, verifying_key) = setup_keys::<Bn254, _, _>(circuit.clone(), rng).unwrap();
	let proof = prove::<Bn254, _, _>(circuit, &proving_key, rng).unwrap();
	let res = verify::<Bn254>(&pub_ins, &verifying_key, &proof).unwrap();

	assert!(!res);
}

#[test]
fn should_fail_with_inconsistent_input_output_values() {
	let rng = &mut test_rng();
	let curve = Curve::Bn254;
	let params3 = setup_params::<BnFr>(curve, 5, 3);
	let tree_hasher = Poseidon::<BnFr> { params: params3 };

	let public_amount = BnFr::from(10u32);
	let ext_data_hash = BnFr::rand(rng);

	// Input Utxos
	let in_chain_id = 0u64;
	// Input amount too high
	let in_amount = BnFr::from(10u32);
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
	let out_amount = BnFr::from(10u32);
	let out_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30::new_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		None,
		None,
		rng,
	)
	.unwrap();
	let out_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30::new_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		None,
		None,
		rng,
	)
	.unwrap();
	let out_utxos = [out_utxo1.clone(), out_utxo2.clone()];

	let leaf0 = in_utxos[0].commitment;
	let (_, in_path0) = setup_tree_and_create_path::<BnFr, PoseidonGadget<BnFr>, HEIGHT>(
		tree_hasher.clone(),
		&vec![leaf0],
		0,
		&DEFAULT_LEAF,
	)
	.unwrap();
	let root0 = in_path0.calculate_root(&leaf0, &tree_hasher).unwrap();
	let leaf1 = in_utxos[1].commitment;
	let (_, in_path1) = setup_tree_and_create_path::<BnFr, PoseidonGadget<BnFr>, HEIGHT>(
		tree_hasher.clone(),
		&vec![leaf1],
		0,
		&DEFAULT_LEAF,
	)
	.unwrap();
	let root1 = in_path1.calculate_root(&leaf1, &tree_hasher).unwrap();

	let in_leaves = [vec![leaf0], vec![leaf1]];
	let in_indices = [0; 2];
	let in_root_set = [root0, root1];

	let (circuit, .., pub_ins) = VAnchorR1CSProver_Bn254_Poseidon_30::setup_circuit_with_utxos(
		curve,
		BnFr::from(in_chain_id),
		public_amount,
		ext_data_hash,
		in_root_set,
		in_indices,
		in_leaves,
		in_utxos,
		out_utxos,
		DEFAULT_LEAF,
	)
	.unwrap();

	let (proving_key, verifying_key) = setup_keys::<Bn254, _, _>(circuit.clone(), rng).unwrap();
	let proof = prove::<Bn254, _, _>(circuit, &proving_key, rng).unwrap();
	let res = verify::<Bn254>(&pub_ins, &verifying_key, &proof).unwrap();

	assert!(!res);
}

#[test]
fn should_fail_with_big_amount() {
	let rng = &mut test_rng();
	let curve = Curve::Bn254;
	let params3 = setup_params::<BnFr>(curve, 5, 3);
	let tree_hasher = Poseidon::<BnFr> { params: params3 };

	// 2^248
	let limit = BnFr::from_str(
		"452312848583266388373324160190187140051835877600158453279131187530910662656",
	)
	.unwrap();

	let public_amount = BnFr::zero();
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
	let out_amount = BnFr::from(10u32);
	let out_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30::new_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		None,
		None,
		rng,
	)
	.unwrap();
	let out_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30::new_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		None,
		None,
		rng,
	)
	.unwrap();
	let out_utxos = [out_utxo1.clone(), out_utxo2.clone()];

	let leaf0 = in_utxos[0].commitment;
	let (_, in_path0) = setup_tree_and_create_path::<BnFr, PoseidonGadget<BnFr>, HEIGHT>(
		tree_hasher.clone(),
		&vec![leaf0],
		0,
		&DEFAULT_LEAF,
	)
	.unwrap();
	let root0 = in_path0.calculate_root(&leaf0, &tree_hasher).unwrap();
	let leaf1 = in_utxos[1].commitment;
	let (_, in_path1) = setup_tree_and_create_path::<BnFr, PoseidonGadget<BnFr>, HEIGHT>(
		tree_hasher.clone(),
		&vec![leaf1],
		0,
		&DEFAULT_LEAF,
	)
	.unwrap();
	let root1 = in_path1.calculate_root(&leaf1, &tree_hasher).unwrap();

	let in_leaves = [vec![leaf0], vec![leaf1]];
	let in_indices = [0; 2];
	let in_root_set = [root0, root1];

	let (circuit, .., pub_ins) = VAnchorR1CSProver_Bn254_Poseidon_30::setup_circuit_with_utxos(
		curve,
		BnFr::from(in_chain_id),
		public_amount,
		ext_data_hash,
		in_root_set,
		in_indices,
		in_leaves,
		in_utxos,
		out_utxos,
		DEFAULT_LEAF,
	)
	.unwrap();

	let (proving_key, verifying_key) = setup_keys::<Bn254, _, _>(circuit.clone(), rng).unwrap();
	let proof = prove::<Bn254, _, _>(circuit, &proving_key, rng).unwrap();
	let res = verify::<Bn254>(&pub_ins, &verifying_key, &proof).unwrap();

	assert!(!res);
}

#[test]
fn should_fail_with_invalid_public_input() {
	let rng = &mut test_rng();
	let curve = Curve::Bn254;
	let params3 = setup_params::<BnFr>(curve, 5, 3);
	let tree_hasher = Poseidon::<BnFr> { params: params3 };

	let public_amount = BnFr::from(0u32);
	let ext_data_hash = BnFr::rand(rng);

	// Input Utxos
	let in_chain_id = 0u64;
	let in_amount = BnFr::from(5u32);
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
	let out_amount = BnFr::from(10u32);
	let out_utxo1 = VAnchorR1CSProver_Bn254_Poseidon_30::new_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		None,
		None,
		rng,
	)
	.unwrap();
	let out_utxo2 = VAnchorR1CSProver_Bn254_Poseidon_30::new_utxo(
		curve,
		out_chain_id,
		out_amount,
		None,
		None,
		None,
		rng,
	)
	.unwrap();
	let out_utxos = [out_utxo1.clone(), out_utxo2.clone()];

	let leaf0 = in_utxos[0].commitment;
	let (_, in_path0) = setup_tree_and_create_path::<BnFr, PoseidonGadget<BnFr>, HEIGHT>(
		tree_hasher.clone(),
		&vec![leaf0],
		0,
		&DEFAULT_LEAF,
	)
	.unwrap();
	let root0 = in_path0.calculate_root(&leaf0, &tree_hasher).unwrap();
	let leaf1 = in_utxos[1].commitment;
	let (_, in_path1) = setup_tree_and_create_path::<BnFr, PoseidonGadget<BnFr>, HEIGHT>(
		tree_hasher.clone(),
		&vec![leaf1],
		0,
		&DEFAULT_LEAF,
	)
	.unwrap();
	let root1 = in_path1.calculate_root(&leaf1, &tree_hasher).unwrap();

	let in_leaves = [vec![leaf0], vec![leaf1]];
	let in_indices = [0; 2];
	let in_root_set = [root0, root1];

	let (circuit, .., pub_ins) = VAnchorR1CSProver_Bn254_Poseidon_30::setup_circuit_with_utxos(
		curve,
		BnFr::from(in_chain_id),
		public_amount,
		ext_data_hash,
		in_root_set,
		in_indices,
		in_leaves,
		in_utxos,
		out_utxos,
		DEFAULT_LEAF,
	)
	.unwrap();

	let truncated_public_inputs = &pub_ins[2..];
	let (proving_key, verifying_key) = setup_keys::<Bn254, _, _>(circuit.clone(), rng).unwrap();
	let proof = prove::<Bn254, _, _>(circuit, &proving_key, rng).unwrap();

	let vk = VerifyingKey::<Bn254>::deserialize(&verifying_key[..]).unwrap();
	let proof = Proof::<Bn254>::deserialize(&proof[..]).unwrap();
	let res = Groth16::<Bn254>::verify(&vk, truncated_public_inputs, &proof);

	assert!(res.is_err());
}
