use crate::{common::*, AnchorProver};
use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_ff::{PrimeField, UniformRand};
use ark_groth16::Groth16;
use ark_snark::SNARK;
use ark_std::test_rng;
use arkworks_native_gadgets::poseidon::{FieldHasher, Poseidon};
use arkworks_r1cs_circuits::anchor::AnchorCircuit;
use arkworks_r1cs_gadgets::poseidon::PoseidonGadget;
use arkworks_utils::Curve;
use codec::Encode;

use super::{setup_params, AnchorR1CSProver};

pub const HEIGHT: usize = 30;
pub const ANCHOR_CT: usize = 2;

#[allow(non_camel_case_types)]
type AnchorR1CSProver_Bn254_Poseidon_30 = AnchorR1CSProver<Bn254, HEIGHT, ANCHOR_CT>;
pub const DEFAULT_LEAF: [u8; 32] = [0u8; 32];

#[test]
fn setup_random_anchor() {
	let rng = &mut test_rng();
	let curve = Curve::Bn254;

	let (circuit, .., public_inputs) =
		AnchorR1CSProver_Bn254_Poseidon_30::setup_random_circuit(curve, DEFAULT_LEAF, rng).unwrap();
	let (pk, vk) = setup_keys::<Bn254, _, _>(circuit.clone(), rng).unwrap();
	let proof = prove::<Bn254, _, _>(circuit, &pk, rng).unwrap();
	let res = verify::<Bn254>(&public_inputs, &vk, &proof).unwrap();
	assert!(res);
}

#[test]
fn setup_and_prove_anchor_groth16() {
	let rng = &mut test_rng();
	let curve = Curve::Bn254;

	let params3 = setup_params::<Bn254Fr>(curve, 5, 3);
	// the essence of tree hasher? for creating a tree?
	let tree_hasher = Poseidon::<Bn254Fr> { params: params3 };

	let chain_id_u64 = 1u64;
	//what's this Bn254Fr crate?
	let chain_id = Bn254Fr::from(chain_id_u64);
	// must the arbitrary input be random? why random
	let arbitrary_input = Bn254Fr::rand(rng);

	let leaf =
		AnchorR1CSProver_Bn254_Poseidon_30::create_random_leaf(curve, chain_id_u64, rng).unwrap();
	let secret = Bn254Fr::from_le_bytes_mod_order(&leaf.secret_bytes);
	let nullifier = Bn254Fr::from_le_bytes_mod_order(&leaf.nullifier_bytes);
	let leaves = vec![Bn254Fr::from_le_bytes_mod_order(&leaf.leaf_bytes)];
	let index = 0;

	// sets up a merkle tree and generates path for it
	// are the elements inserted into the tree, the leaves?
	let (tree, _) = setup_tree_and_create_path::<Bn254Fr, Poseidon<Bn254Fr>, HEIGHT>(
		&tree_hasher,
		&leaves,
		index,
		&DEFAULT_LEAF,
	)
	.unwrap();
	let mut roots = [Bn254Fr::from(0u64); ANCHOR_CT];
	roots[0] = tree.root();

	let (circuit, .., public_inputs) =
		AnchorR1CSProver_Bn254_Poseidon_30::setup_circuit_with_privates(
			curve,
			chain_id,
			secret,
			nullifier,
			&leaves,
			index,
			roots,
			arbitrary_input,
			DEFAULT_LEAF,
		)
		.unwrap();

	let (pk, vk) = setup_keys::<Bn254, _, _>(circuit.clone(), rng).unwrap();
	let proof = prove::<Bn254, _, _>(circuit, &pk, rng).unwrap();
	let res = verify::<Bn254>(&public_inputs, &vk, &proof).unwrap();
	assert!(
		res,
		"Failed to verify  Proof, here is the inputs:
        arbitrary_input = {:?},
        public_inputs = {:?},
        proof = {:?},
        ",
		arbitrary_input, public_inputs, proof
	);
}

#[test]
fn should_fail_with_invalid_public_inputs() {
	let rng = &mut test_rng();
	let curve = Curve::Bn254;

	let params3 = setup_params::<Bn254Fr>(curve, 5, 3);
	let tree_hasher = Poseidon::<Bn254Fr> { params: params3 };

	let chain_id_u64 = 1u64;
	let chain_id = Bn254Fr::from(chain_id_u64);
	let arbitrary_input = Bn254Fr::rand(rng);

	let leaf =
		AnchorR1CSProver_Bn254_Poseidon_30::create_random_leaf(curve, chain_id_u64, rng).unwrap();
	let secret = Bn254Fr::from_le_bytes_mod_order(&leaf.secret_bytes);
	let nullifier = Bn254Fr::from_le_bytes_mod_order(&leaf.nullifier_bytes);
	let leaves = vec![Bn254Fr::from_le_bytes_mod_order(&leaf.leaf_bytes)];
	let index = 0;

	let (tree, _) = setup_tree_and_create_path::<Bn254Fr, Poseidon<Bn254Fr>, HEIGHT>(
		&tree_hasher,
		&leaves,
		index,
		&DEFAULT_LEAF,
	)
	.unwrap();
	let mut roots = [Bn254Fr::from(0u64); ANCHOR_CT];
	roots[0] = tree.root();

	let (circuit, .., public_inputs) =
		AnchorR1CSProver_Bn254_Poseidon_30::setup_circuit_with_privates(
			curve,
			chain_id,
			secret,
			nullifier,
			&leaves,
			index,
			roots,
			arbitrary_input,
			DEFAULT_LEAF,
		)
		.unwrap();

	type GrothSetup = Groth16<Bn254>;

	let (pk, vk) = GrothSetup::circuit_specific_setup(circuit.clone(), rng).unwrap();
	let proof = GrothSetup::prove(&pk, circuit, rng).unwrap();

	// Without chain_id and nullifier
	let pi = public_inputs[2..].to_vec();
	let res = GrothSetup::verify(&vk, &pi, &proof);
	assert!(res.is_err());
}

#[test]
fn should_fail_with_invalid_set() {
	let rng = &mut test_rng();
	let curve = Curve::Bn254;

	let chain_id_u64 = 1u64;
	let chain_id = Bn254Fr::from(chain_id_u64);
	let arbitrary_input = Bn254Fr::rand(rng);

	let leaf =
		AnchorR1CSProver_Bn254_Poseidon_30::create_random_leaf(curve, chain_id_u64, rng).unwrap();
	let secret = Bn254Fr::from_le_bytes_mod_order(&leaf.secret_bytes);
	let nullifier = Bn254Fr::from_le_bytes_mod_order(&leaf.nullifier_bytes);
	let leaves = vec![Bn254Fr::from_le_bytes_mod_order(&leaf.leaf_bytes)];
	let index = 0;
	let roots = [Bn254Fr::rand(rng); ANCHOR_CT];

	let (circuit, .., public_inputs) =
		AnchorR1CSProver_Bn254_Poseidon_30::setup_circuit_with_privates(
			curve,
			chain_id,
			secret,
			nullifier,
			&leaves,
			index,
			roots,
			arbitrary_input,
			DEFAULT_LEAF,
		)
		.unwrap();

	let (pk, vk) = setup_keys::<Bn254, _, _>(circuit.clone(), rng).unwrap();
	let proof = prove::<Bn254, _, _>(circuit, &pk, rng).unwrap();
	let res = verify::<Bn254>(&public_inputs, &vk, &proof).unwrap();
	assert!(!res);
}

#[test]
fn should_fail_with_invalid_leaf() {
	let rng = &mut test_rng();
	let curve = Curve::Bn254;

	let params3 = setup_params::<Bn254Fr>(curve, 5, 3);
	let tree_hasher = Poseidon::<Bn254Fr> { params: params3 };

	let chain_id_u64 = 1u64;
	let chain_id = Bn254Fr::from(chain_id_u64);
	let arbitrary_input = Bn254Fr::rand(rng);

	let leaf =
		AnchorR1CSProver_Bn254_Poseidon_30::create_random_leaf(curve, chain_id_u64, rng).unwrap();
	let secret = Bn254Fr::from_le_bytes_mod_order(&leaf.secret_bytes);
	let nullifier = Bn254Fr::from_le_bytes_mod_order(&leaf.nullifier_bytes);
	let leaves = vec![Bn254Fr::rand(rng)];
	let index = 0;

	let (tree, _) = setup_tree_and_create_path::<Bn254Fr, Poseidon<Bn254Fr>, HEIGHT>(
		&tree_hasher,
		&leaves,
		index,
		&DEFAULT_LEAF,
	)
	.unwrap();
	let mut roots = [Bn254Fr::from(0u64); ANCHOR_CT];
	roots[0] = tree.root();

	let (circuit, .., public_inputs) =
		AnchorR1CSProver_Bn254_Poseidon_30::setup_circuit_with_privates(
			curve,
			chain_id,
			secret,
			nullifier,
			&leaves,
			index,
			roots,
			arbitrary_input,
			DEFAULT_LEAF,
		)
		.unwrap();

	let (pk, vk) = setup_keys::<Bn254, _, _>(circuit.clone(), rng).unwrap();
	let proof = prove::<Bn254, _, _>(circuit, &pk, rng).unwrap();
	let res = verify::<Bn254>(&public_inputs, &vk, &proof).unwrap();
	assert!(!res);
}

#[test]
fn should_fail_with_invalid_nullifier_hash() {
	let rng = &mut test_rng();
	let curve = Curve::Bn254;

	let params3 = setup_params::<Bn254Fr>(curve, 5, 3);
	let params4 = setup_params::<Bn254Fr>(curve, 5, 4);
	let tree_hasher = Poseidon::<Bn254Fr> { params: params3 };
	let leaf_hasher = Poseidon::<Bn254Fr> { params: params4 };

	let chain_id_u64 = 1u64;
	let chain_id = Bn254Fr::from(chain_id_u64);
	let arbitrary_input = Bn254Fr::rand(rng);

	let leaf =
		AnchorR1CSProver_Bn254_Poseidon_30::create_random_leaf(curve, chain_id_u64, rng).unwrap();
	let secret = Bn254Fr::from_le_bytes_mod_order(&leaf.secret_bytes);
	let nullifier = Bn254Fr::from_le_bytes_mod_order(&leaf.nullifier_bytes);
	let leaves = vec![Bn254Fr::from_le_bytes_mod_order(&leaf.leaf_bytes)];

	let nullifier_hash = Bn254Fr::rand(rng);
	let index = 0;
	let (tree, path) = setup_tree_and_create_path::<Bn254Fr, Poseidon<Bn254Fr>, HEIGHT>(
		&tree_hasher,
		&leaves,
		index,
		&DEFAULT_LEAF,
	)
	.unwrap();

	let mut roots_new = [Bn254Fr::from(0u64); ANCHOR_CT];
	roots_new[0] = tree.root();

	let mc = AnchorCircuit::<Bn254Fr, PoseidonGadget<Bn254Fr>, HEIGHT, ANCHOR_CT>::new(
		arbitrary_input.clone(),
		secret,
		nullifier,
		chain_id,
		roots_new,
		path,
		nullifier_hash,
		tree_hasher,
		leaf_hasher,
	);
	let public_inputs = AnchorR1CSProver_Bn254_Poseidon_30::construct_public_inputs(
		chain_id,
		nullifier_hash,
		roots_new,
		arbitrary_input,
	);

	let (pk, vk) = setup_keys::<Bn254, _, _>(mc.clone(), rng).unwrap();
	let proof = prove::<Bn254, _, _>(mc, &pk, rng).unwrap();
	let res = verify::<Bn254>(&public_inputs, &vk, &proof).unwrap();
	assert!(!res);
}

// What this test does
// We make a deposit in anchor 1 targeting anchor 2. That means the leaf =
// (chain_id_of_2, secret_1, nullifier_1) We want to prove this deposit exists
// in one of the tree roots in root_set from the smart contract where anchor 2
// is. In order to prove this, we must get the (path_1, nullifier_hash_1,
// chain_2, secret_1, nullifier_1)
//
// So, we create two trees
// Insert an element into both, let (m_a, m_b) be the merkle root of the trees
// on Anchors 1 and 2 Create the root sets that each anchor would have on the
// respective smart contract (m_1, m_2) on A, (m_2, m_1) on B
#[test]
fn setup_and_prove_2_anchors_using_zk_proof() {
	let rng = &mut test_rng();
	let curve = Curve::Bn254;

	let params3 = setup_params::<Bn254Fr>(curve, 5, 3);
	let params4 = setup_params::<Bn254Fr>(curve, 5, 4);

	let tree_hasher = Poseidon::<Bn254Fr> { params: params3 };
	let leaf_hasher = Poseidon::<Bn254Fr> { params: params4 };

	// setup chain id for first anchor
	let chain_id_u64_first_anchor = 1u64;
	let chain_id_first_anchor = Bn254Fr::from(chain_id_u64_first_anchor);

	// setup chain id for second anchor
	let chain_id_u64_second_anchor = 2u64;
	let chain_id_second_anchor = Bn254Fr::from(chain_id_u64_second_anchor);

	// setup leaf, secret, nullifier and leaves for first anchor
	// make the leaf you insert into the first anchor have the chain ID of the
	// chain_id_u64_second_anchor
	let leaf_first_anchor = AnchorR1CSProver_Bn254_Poseidon_30::create_random_leaf(
		curve,
		chain_id_u64_second_anchor,
		rng,
	)
	.unwrap();
	let secret_first_anchor = Bn254Fr::from_le_bytes_mod_order(&leaf_first_anchor.secret_bytes);
	let nullifier_first_anchor =
		Bn254Fr::from_le_bytes_mod_order(&leaf_first_anchor.nullifier_bytes);
	let leaves_first_anchor = vec![Bn254Fr::from_le_bytes_mod_order(
		&leaf_first_anchor.leaf_bytes,
	)];

	// setup leaf, secret, nullifier and leaves for second anchor
	let leaf_second_anchor = AnchorR1CSProver_Bn254_Poseidon_30::create_random_leaf(
		curve,
		chain_id_u64_second_anchor,
		rng,
	)
	.unwrap();
	let secret_second_anchor = Bn254Fr::from_le_bytes_mod_order(&leaf_second_anchor.secret_bytes);
	let nullifier_second_anchor =
		Bn254Fr::from_le_bytes_mod_order(&leaf_second_anchor.nullifier_bytes);
	let leaves_second_anchor = vec![Bn254Fr::from_le_bytes_mod_order(
		&leaf_second_anchor.leaf_bytes,
	)];

	// nullifier hash for first anchor
	let nullifier_hash_first_anchor = tree_hasher
		.hash_two(&nullifier_first_anchor, &nullifier_first_anchor)
		.unwrap();

	// nullifier hash for second anchor
	let nullifier_hash_second_anchor = tree_hasher
		.hash_two(&nullifier_second_anchor, &nullifier_second_anchor)
		.unwrap();

	let index = 0;

	// sets up a merkle tree and generates path for it
	// are the elements inserted into the tree, the leaves?
	// tree for first anchor
	let (tree_first_anchor, path_first_anchor) =
		setup_tree_and_create_path::<Bn254Fr, Poseidon<Bn254Fr>, HEIGHT>(
			&tree_hasher,
			&leaves_first_anchor,
			index,
			&DEFAULT_LEAF,
		)
		.unwrap();

	// tree for second anchor
	let (tree_second_anchor, path_second_anchor) =
		setup_tree_and_create_path::<Bn254Fr, Poseidon<Bn254Fr>, HEIGHT>(
			&tree_hasher,
			&leaves_second_anchor,
			index,
			&DEFAULT_LEAF,
		)
		.unwrap();

	// roots for first anchor (m_1, m_2)
	let mut roots_first_anchor = [Bn254Fr::from(0u64); ANCHOR_CT];
	roots_first_anchor[0] = tree_first_anchor.root();
	roots_first_anchor[1] = tree_second_anchor.root();

	// roots for second anchor (m_2, m_1)
	let mut roots_second_anchor = [Bn254Fr::from(0u64); ANCHOR_CT];
	roots_second_anchor[0] = tree_second_anchor.root();
	roots_second_anchor[1] = tree_first_anchor.root();

	// config for arbitrary input
	let commitment = vec![0u8; 32];
	let recipient = vec![0u8; 32];
	let relayer = vec![0u8; 32];
	let fee = 0u128;
	let refund = 0u128;

	// Create the arbitrary input data
	let mut arbitrary_data_bytes = Vec::new();
	arbitrary_data_bytes.extend(&recipient);
	arbitrary_data_bytes.extend(&relayer);
	// Using encode to be compatible with on chain types
	arbitrary_data_bytes.extend(fee.encode());
	arbitrary_data_bytes.extend(refund.encode());
	arbitrary_data_bytes.extend(&commitment);
	let arbitrary_data = keccak_256(&arbitrary_data_bytes);
	let arbitrary_input = Bn254Fr::from_le_bytes_mod_order(&arbitrary_data);

	// create a circuit for the second anchor
	// using the leaf secret values of the deposit in the first anchor
	// pass in the chain ID and root set of the second anchor
	let anchor_circuit_second_anchor =
		AnchorCircuit::<Bn254Fr, PoseidonGadget<Bn254Fr>, HEIGHT, ANCHOR_CT>::new(
			arbitrary_input,
			secret_first_anchor,
			nullifier_first_anchor,
			chain_id_second_anchor,
			roots_second_anchor,
			path_first_anchor,
			nullifier_hash_first_anchor,
			tree_hasher,
			leaf_hasher,
		);

	let public_inputs_second_anchor = AnchorR1CSProver_Bn254_Poseidon_30::construct_public_inputs(
		chain_id_second_anchor,
		nullifier_hash_first_anchor,
		roots_second_anchor,
		arbitrary_input,
	);

	let (pk_second_anchor, vk_second_anchor) =
		setup_keys::<Bn254, _, _>(anchor_circuit_second_anchor.clone(), rng).unwrap();
	//println!("pk second anchor is: {:?}", pk_second_anchor);

	let proof = prove::<Bn254, _, _>(anchor_circuit_second_anchor, &pk_second_anchor, rng).unwrap();
	println!("proof is: {:?}", proof);
	let res = verify::<Bn254>(&public_inputs_second_anchor, &vk_second_anchor, &proof).unwrap();
	println!("result: {:?}", res);
	assert_eq!(res, true);
}
