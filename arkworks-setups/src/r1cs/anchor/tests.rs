use crate::{common::*, AnchorProver};
use ark_std::marker::PhantomData;
use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_ff::{PrimeField, UniformRand};
use ark_groth16::Groth16;
use ark_snark::SNARK;
use ark_std::test_rng;
use arkworks_circuits::circuit::anchor::AnchorCircuit;
use arkworks_gadgets::{poseidon::{field_hasher::Poseidon, field_hasher_constraints::PoseidonGadget}, leaf::anchor::{Public, Private}};
use arkworks_utils::utils::common::{setup_params_x5_3, setup_params_x5_4, Curve};

use super::AnchorR1CSProver;

pub const HEIGHT: usize = 30;
pub const ANCHOR_CT: usize = 2;

#[test]
fn setup_random_anchor() {
    let rng = &mut test_rng();
    let curve = Curve::Bn254;

    let params3 = setup_params_x5_3::<Bn254Fr>(curve);
    let params4 = setup_params_x5_4::<Bn254Fr>(curve);
	let prover = AnchorR1CSProver::<Bn254, PoseidonGadget<Bn254Fr>, PoseidonGadget<Bn254Fr>, HEIGHT, ANCHOR_CT> {
		default_leaf: [0u8; 32],
		tree_hasher: Poseidon::<Bn254Fr> { params: params3 },
        leaf_hasher: Poseidon::<Bn254Fr> { params: params4 },
		engine: PhantomData::<Bn254>,
	};

    let (circuit, .., public_inputs) = prover.setup_random_circuit(rng).unwrap();
	let (pk, vk) = setup_keys::<Bn254, _, _>(circuit.clone(), rng).unwrap();
	let proof = prove::<Bn254, _, _>(circuit, &pk, rng).unwrap();
	let res = verify::<Bn254>(&public_inputs, &vk, &proof).unwrap();
	assert!(res);
}

#[test]
fn setup_and_prove_anchor_groth16() {
    let rng = &mut test_rng();
    let curve = Curve::Bn254;

    let params3 = setup_params_x5_3::<Bn254Fr>(curve);
    let params4 = setup_params_x5_4::<Bn254Fr>(curve);
	let prover = AnchorR1CSProver::<Bn254, PoseidonGadget<Bn254Fr>, PoseidonGadget<Bn254Fr>, HEIGHT, ANCHOR_CT> {
		default_leaf: [0u8; 32],
		tree_hasher: Poseidon::<Bn254Fr> { params: params3 },
        leaf_hasher: Poseidon::<Bn254Fr> { params: params4 },
		engine: PhantomData::<Bn254>,
	};

    let chain_id_u64 = 1u64;
    let chain_id = Bn254Fr::from(chain_id_u64);
    let recipient = Bn254Fr::rand(rng);
    let relayer = Bn254Fr::rand(rng);
    let fee = Bn254Fr::rand(rng);
    let refund = Bn254Fr::rand(rng);
    let commitment = Bn254Fr::rand(rng);

	let leaf = prover.create_leaf_with_privates(chain_id_u64, None, None, rng).unwrap();
	let secret = Bn254Fr::from_le_bytes_mod_order(&leaf.secret_bytes);
	let nullifier = Bn254Fr::from_le_bytes_mod_order(&leaf.nullifier_bytes);
	let leaves = vec![Bn254Fr::from_le_bytes_mod_order(&leaf.leaf_bytes)];
	let index = 0;

    let (tree, _) = prover.setup_tree_and_create_path(&leaves, index).unwrap();
    let mut roots = [Bn254Fr::from(0u64); ANCHOR_CT];
    roots[0] = tree.root();

	let (circuit, .., public_inputs) = prover
		.setup_circuit_with_privates(
			chain_id, secret, nullifier, &leaves, index, roots, recipient, relayer, fee, refund, commitment,
		)
		.unwrap();

	let (pk, vk) = setup_keys::<Bn254, _, _>(circuit.clone(), rng).unwrap();
	let proof = prove::<Bn254, _, _>(circuit, &pk, rng).unwrap();
	let res = verify::<Bn254>(&public_inputs, &vk, &proof).unwrap();
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

    let params3 = setup_params_x5_3::<Bn254Fr>(curve);
    let params4 = setup_params_x5_4::<Bn254Fr>(curve);
	let prover = AnchorR1CSProver::<Bn254, PoseidonGadget<Bn254Fr>, PoseidonGadget<Bn254Fr>, HEIGHT, ANCHOR_CT> {
		default_leaf: [0u8; 32],
		tree_hasher: Poseidon::<Bn254Fr> { params: params3 },
        leaf_hasher: Poseidon::<Bn254Fr> { params: params4 },
		engine: PhantomData::<Bn254>,
	};

    let chain_id_u64 = 1u64;
    let chain_id = Bn254Fr::from(chain_id_u64);
    let recipient = Bn254Fr::rand(rng);
    let relayer = Bn254Fr::rand(rng);
    let fee = Bn254Fr::rand(rng);
    let refund = Bn254Fr::rand(rng);
    let commitment = Bn254Fr::rand(rng);

	let leaf = prover.create_leaf_with_privates(chain_id_u64, None, None, rng).unwrap();
	let secret = Bn254Fr::from_le_bytes_mod_order(&leaf.secret_bytes);
	let nullifier = Bn254Fr::from_le_bytes_mod_order(&leaf.nullifier_bytes);
	let leaves = vec![Bn254Fr::from_le_bytes_mod_order(&leaf.leaf_bytes)];
	let index = 0;

    let (tree, _) = prover.setup_tree_and_create_path(&leaves, index).unwrap();
    let mut roots = [Bn254Fr::from(0u64); ANCHOR_CT];
    roots[0] = tree.root();

	let (circuit, .., public_inputs) = prover
		.setup_circuit_with_privates(
			chain_id, secret, nullifier, &leaves, index, roots, recipient, relayer, fee, refund, commitment,
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

    let params3 = setup_params_x5_3::<Bn254Fr>(curve);
    let params4 = setup_params_x5_4::<Bn254Fr>(curve);
	let prover = AnchorR1CSProver::<Bn254, PoseidonGadget<Bn254Fr>, PoseidonGadget<Bn254Fr>, HEIGHT, ANCHOR_CT> {
		default_leaf: [0u8; 32],
		tree_hasher: Poseidon::<Bn254Fr> { params: params3 },
        leaf_hasher: Poseidon::<Bn254Fr> { params: params4 },
		engine: PhantomData::<Bn254>,
	};

    let chain_id_u64 = 1u64;
    let chain_id = Bn254Fr::from(chain_id_u64);
    let recipient = Bn254Fr::rand(rng);
    let relayer = Bn254Fr::rand(rng);
    let fee = Bn254Fr::rand(rng);
    let refund = Bn254Fr::rand(rng);
    let commitment = Bn254Fr::rand(rng);

	let leaf = prover.create_leaf_with_privates(chain_id_u64, None, None, rng).unwrap();
	let secret = Bn254Fr::from_le_bytes_mod_order(&leaf.secret_bytes);
	let nullifier = Bn254Fr::from_le_bytes_mod_order(&leaf.nullifier_bytes);
	let leaves = vec![Bn254Fr::from_le_bytes_mod_order(&leaf.leaf_bytes)];
	let index = 0;
    let roots = [Bn254Fr::rand(rng); ANCHOR_CT];

	let (circuit, .., public_inputs) = prover
		.setup_circuit_with_privates(
			chain_id, secret, nullifier, &leaves, index, roots, recipient, relayer, fee, refund, commitment,
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

    let params3 = setup_params_x5_3::<Bn254Fr>(curve);
    let params4 = setup_params_x5_4::<Bn254Fr>(curve);
	let prover = AnchorR1CSProver::<Bn254, PoseidonGadget<Bn254Fr>, PoseidonGadget<Bn254Fr>, HEIGHT, ANCHOR_CT> {
		default_leaf: [0u8; 32],
		tree_hasher: Poseidon::<Bn254Fr> { params: params3 },
        leaf_hasher: Poseidon::<Bn254Fr> { params: params4 },
		engine: PhantomData::<Bn254>,
	};

    let chain_id_u64 = 1u64;
    let chain_id = Bn254Fr::from(chain_id_u64);
    let recipient = Bn254Fr::rand(rng);
    let relayer = Bn254Fr::rand(rng);
    let fee = Bn254Fr::rand(rng);
    let refund = Bn254Fr::rand(rng);
    let commitment = Bn254Fr::rand(rng);

	let leaf = prover.create_leaf_with_privates(chain_id_u64, None, None, rng).unwrap();
	let secret = Bn254Fr::from_le_bytes_mod_order(&leaf.secret_bytes);
	let nullifier = Bn254Fr::from_le_bytes_mod_order(&leaf.nullifier_bytes);
	let leaves = vec![Bn254Fr::rand(rng)];
	let index = 0;

    let (tree, _) = prover.setup_tree_and_create_path(&leaves, index).unwrap();
    let mut roots = [Bn254Fr::from(0u64); ANCHOR_CT];
    roots[0] = tree.root();

	let (circuit, .., public_inputs) = prover
		.setup_circuit_with_privates(
			chain_id, secret, nullifier, &leaves, index, roots, recipient, relayer, fee, refund, commitment,
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

    let params3 = setup_params_x5_3::<Bn254Fr>(curve);
    let params4 = setup_params_x5_4::<Bn254Fr>(curve);
	let prover = AnchorR1CSProver::<Bn254, PoseidonGadget<Bn254Fr>, PoseidonGadget<Bn254Fr>, HEIGHT, ANCHOR_CT> {
		default_leaf: [0u8; 32],
		tree_hasher: Poseidon::<Bn254Fr> { params: params3 },
        leaf_hasher: Poseidon::<Bn254Fr> { params: params4 },
		engine: PhantomData::<Bn254>,
	};

    let chain_id_u64 = 1u64;
    let chain_id = Bn254Fr::from(chain_id_u64);
    let relayer = Bn254Fr::rand(rng);
    let recipient = Bn254Fr::rand(rng);
    let fee = Bn254Fr::rand(rng);
    let refund = Bn254Fr::rand(rng);
    let commitment = Bn254Fr::rand(rng);

    let arbitrary_input =
        AnchorR1CSProver::<Bn254, PoseidonGadget<Bn254Fr>, PoseidonGadget<Bn254Fr>, HEIGHT, ANCHOR_CT>::setup_arbitrary_data(recipient, relayer, fee, refund, commitment);
	let leaf = prover.create_leaf_with_privates(chain_id_u64, None, None, rng).unwrap();
    let leaf_public = Public::new(chain_id);
    let leaf_private = Private::new(
        Bn254Fr::from_le_bytes_mod_order(&leaf.secret_bytes),
        Bn254Fr::from_le_bytes_mod_order(&leaf.nullifier_bytes),
    );
	let secret = Bn254Fr::from_le_bytes_mod_order(&leaf.secret_bytes);
	let nullifier = Bn254Fr::from_le_bytes_mod_order(&leaf.nullifier_bytes);
	let leaves = vec![Bn254Fr::from_le_bytes_mod_order(&leaf.leaf_bytes)];

    let nullifier_hash = Bn254Fr::rand(rng);
    let index = 0;
    let (tree, path) = prover.setup_tree_and_create_path(&leaves, index).unwrap();

    let mut roots_new = [Bn254Fr::from(0u64); ANCHOR_CT];
    roots_new[0] = tree.root();

    let mc = AnchorCircuit::<Bn254Fr, PoseidonGadget<Bn254Fr>, PoseidonGadget<Bn254Fr>, HEIGHT, ANCHOR_CT>::new(
        arbitrary_input.clone(),
        leaf_private,
        leaf_public,
        roots_new,
        path,
        nullifier_hash,
        prover.tree_hasher,
        prover.leaf_hasher,
    );
    let public_inputs = AnchorR1CSProver::<Bn254, PoseidonGadget<Bn254Fr>, PoseidonGadget<Bn254Fr>, HEIGHT, ANCHOR_CT>::construct_public_inputs(
        chain_id,
        nullifier_hash,
        roots_new,
        recipient,
        relayer,
        fee,
        refund,
        commitment,
    );

    let (pk, vk) = setup_keys::<Bn254, _, _>(mc.clone(), rng).unwrap();
    let proof = prove::<Bn254, _, _>(mc, &pk, rng).unwrap();
    let res = verify::<Bn254>(&public_inputs, &vk, &proof).unwrap();
    assert!(!res);
}
