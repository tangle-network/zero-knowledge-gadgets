use std::ptr::null;

use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use ark_std::{marker::PhantomData, test_rng, vec::Vec, One, Zero};
use arkworks_gadgets::{poseidon::{
	field_hasher::Poseidon, field_hasher_constraints::PoseidonGadget,
}, leaf::mixer::Private};
use arkworks_utils::utils::common::{setup_params_x5_3, setup_params_x5_5, Curve};

// merkle proof path legth
// TreeConfig_x5, x7 HEIGHT is hardcoded to 30
pub const LEN: usize = 30;

use crate::{common::{
	prove, prove_unchecked, setup_keys, setup_keys_unchecked, verify, verify_unchecked_raw,
}, MixerProver, r1cs::mixer::setup_arbitrary_data};

use super::MixerR1CSProver;

#[test]
fn setup_and_prove_mixer_groth16() {
	let rng = &mut test_rng();
	let curve = Curve::Bn254;
	let params3 = setup_params_x5_3::<Bn254Fr>(curve);
	let prover = MixerR1CSProver::<Bn254, PoseidonGadget<Bn254Fr>, LEN> {
		default_leaf: [0u8; 32],
		hasher: Poseidon::<Bn254Fr> { params: params3 },
		engine: PhantomData::<Bn254>,
	};
	let (circuit, .., public_inputs) = prover.setup_random_circuit(rng).unwrap();
	let (pk, vk) = setup_keys::<Bn254, _, _>(circuit.clone(), rng).unwrap();
	let proof = prove::<Bn254, _, _>(circuit, &pk, rng).unwrap();
	let res = verify::<Bn254>(&public_inputs, &vk, &proof).unwrap();
	assert!(res);
}

#[test]
fn setup_and_prove_mixer_groth16_2() {
	let rng = &mut test_rng();
	let curve = Curve::Bn254;

	let recipient = Bn254Fr::one();
	let relayer = Bn254Fr::zero();
	let fee = Bn254Fr::zero();
	let refund = Bn254Fr::zero();

	let params3 = setup_params_x5_3::<Bn254Fr>(curve);
	let prover = MixerR1CSProver::<Bn254, PoseidonGadget<Bn254Fr>, LEN> {
		default_leaf: [0u8; 32],
		hasher: Poseidon::<Bn254Fr> { params: params3 },
		engine: PhantomData,
	};

	let leaf = prover.create_leaf_with_privates(None, None, rng).unwrap();
	let secret = Bn254Fr::from_le_bytes_mod_order(&leaf.secret_bytes);
	let nullifier = Bn254Fr::from_le_bytes_mod_order(&leaf.nullifier_bytes);
	let leaves = vec![Bn254Fr::from_le_bytes_mod_order(&leaf.leaf_bytes)];
	let index = 0;
	let (circuit, .., public_inputs) = prover
		.setup_circuit_with_privates(
			secret, nullifier, &leaves, index, recipient, relayer, fee, refund,
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

	let recipient = Bn254Fr::one();
	let relayer = Bn254Fr::zero();
	let fee = Bn254Fr::zero();
	let refund = Bn254Fr::zero();

	let params3 = setup_params_x5_3::<Bn254Fr>(curve);
	let prover = MixerR1CSProver::<Bn254, PoseidonGadget<Bn254Fr>, LEN> {
		default_leaf: [0u8; 32],
		hasher: Poseidon::<Bn254Fr> { params: params3 },
		engine: PhantomData,
	};

	let leaf = prover.create_leaf_with_privates(None, None, rng).unwrap();
	let secret = Bn254Fr::from_le_bytes_mod_order(&leaf.secret_bytes);
	let nullifier = Bn254Fr::from_le_bytes_mod_order(&leaf.nullifier_bytes);
	let leaves = vec![Bn254Fr::from_le_bytes_mod_order(&leaf.leaf_bytes)];
	let index = 0;
	let (circuit, .., public_inputs) = prover
		.setup_circuit_with_privates(
			secret, nullifier, &leaves, index, recipient, relayer, fee, refund,
		)
		.unwrap();

	let (pk, vk) = setup_keys::<Bn254, _, _>(circuit.clone(), rng).unwrap();
	let proof = prove::<Bn254, _, _>(circuit, &pk, rng).unwrap();

	let vk = VerifyingKey::<Bn254>::deserialize(&vk[..]).unwrap();
	let proof = Proof::<Bn254>::deserialize(&proof[..]).unwrap();

	let pi = &public_inputs[1..];
	let res = Groth16::<Bn254>::verify(&vk, pi, &proof);
	assert!(res.is_err());
}

#[test]
fn should_fail_with_invalid_root() {
	let rng = &mut test_rng();
	let curve = Curve::Bn254;

	let recipient = Bn254Fr::one();
	let relayer = Bn254Fr::zero();
	let fee = Bn254Fr::zero();
	let refund = Bn254Fr::zero();

	let params3 = setup_params_x5_3::<Bn254Fr>(curve);
	let prover = MixerR1CSProver::<Bn254, PoseidonGadget<Bn254Fr>, LEN> {
		default_leaf: [0u8; 32],
		hasher: Poseidon::<Bn254Fr> { params: params3 },
		engine: PhantomData,
	};

	let leaf = prover.create_leaf_with_privates(None, None, rng).unwrap();
	let secret = Bn254Fr::from_le_bytes_mod_order(&leaf.secret_bytes);
	let nullifier = Bn254Fr::from_le_bytes_mod_order(&leaf.nullifier_bytes);
	let nullifier_hash = Bn254Fr::from_le_bytes_mod_order(&leaf.nullifier_hash_bytes);
	let leaves = vec![Bn254Fr::from_le_bytes_mod_order(&leaf.leaf_bytes)];

	let arbitrary_input =
		setup_arbitrary_data(recipient, relayer, fee, refund);
	let (_, path) = prover.setup_tree_and_create_path(&leaves, 0).unwrap();
	let bad_root = Bn254Fr::rand(rng);

	let index = 0;
	let (circuit, ..) = prover
		.setup_circuit_with_privates(
			secret, nullifier, &leaves, index, recipient, relayer, fee, refund,
		)
		.unwrap();

	let mut public_inputs = Vec::new();
	public_inputs.push(nullifier_hash);
	public_inputs.push(bad_root);
	public_inputs.push(arbitrary_input.recipient);
	public_inputs.push(arbitrary_input.relayer);
	public_inputs.push(arbitrary_input.fee);
	public_inputs.push(arbitrary_input.refund);

	let (pk, vk) = setup_keys::<Bn254, _, _>(circuit.clone(), rng).unwrap();
	let proof = prove::<Bn254, _, _>(circuit, &pk, rng).unwrap();
	let res = verify::<Bn254>(&public_inputs, &vk, &proof).unwrap();

	assert!(!res);
}

#[test]
fn should_fail_with_invalid_leaf() {
	let rng = &mut test_rng();
	let curve = Curve::Bn254;

	let recipient = Bn254Fr::one();
	let relayer = Bn254Fr::zero();
	let fee = Bn254Fr::zero();
	let refund = Bn254Fr::zero();

	let params3 = setup_params_x5_3::<Bn254Fr>(curve);
	let prover = MixerR1CSProver::<Bn254, PoseidonGadget<Bn254Fr>, LEN> {
		default_leaf: [0u8; 32],
		hasher: Poseidon::<Bn254Fr> { params: params3 },
		engine: PhantomData,
	};

	let leaf = prover.create_leaf_with_privates(None, None, rng).unwrap();
	let secret = Bn254Fr::from_le_bytes_mod_order(&leaf.secret_bytes);
	let nullifier = Bn254Fr::from_le_bytes_mod_order(&leaf.nullifier_bytes);
	let nullifier_hash = Bn254Fr::from_le_bytes_mod_order(&leaf.nullifier_hash_bytes);
	let leaves = vec![Bn254Fr::from_le_bytes_mod_order(&leaf.leaf_bytes)];
	let invalid_leaf_value = Bn254Fr::rand(rng);

	let arbitrary_input =
		setup_arbitrary_data(recipient, relayer, fee, refund);
	let (tree, path) = prover.setup_tree_and_create_path(&leaves, 0).unwrap();
	let root = tree.root();

	let index = 0;
	let (circuit, ..) = prover
		.setup_circuit_with_privates(
			secret, nullifier, &[invalid_leaf_value], index, recipient, relayer, fee, refund,
		)
		.unwrap();

	let mut public_inputs = Vec::new();
	public_inputs.push(nullifier_hash);
	public_inputs.push(root);
	public_inputs.push(arbitrary_input.recipient);
	public_inputs.push(arbitrary_input.relayer);
	public_inputs.push(arbitrary_input.fee);
	public_inputs.push(arbitrary_input.refund);

	let (pk, vk) = setup_keys::<Bn254, _, _>(circuit.clone(), rng).unwrap();
	let proof = prove::<Bn254, _, _>(circuit, &pk, rng).unwrap();
	let res = verify::<Bn254>(&public_inputs, &vk, &proof).unwrap();

	assert!(!res);
}

#[test]
fn should_fail_with_invalid_leaf_2() {
	let rng = &mut test_rng();
	let curve = Curve::Bn254;

	let recipient = Bn254Fr::one();
	let relayer = Bn254Fr::zero();
	let fee = Bn254Fr::zero();
	let refund = Bn254Fr::zero();

	let params3 = setup_params_x5_3::<Bn254Fr>(curve);
	let prover = MixerR1CSProver::<Bn254, PoseidonGadget<Bn254Fr>, LEN> {
		default_leaf: [0u8; 32],
		hasher: Poseidon::<Bn254Fr> { params: params3 },
		engine: PhantomData,
	};

	let leaf = prover.create_leaf_with_privates(None, None, rng).unwrap();
	let secret = Bn254Fr::from_le_bytes_mod_order(&leaf.secret_bytes);
	let nullifier = Bn254Fr::from_le_bytes_mod_order(&leaf.nullifier_bytes);
	let leaf_private = Private::new(secret, nullifier);
	let nullifier_hash = Bn254Fr::from_le_bytes_mod_order(&leaf.nullifier_hash_bytes);
	let invalid_leaf_value = Bn254Fr::rand(rng);

	let arbitrary_input =
		setup_arbitrary_data(recipient, relayer, fee, refund);

	let (tree, path) = prover.setup_tree_and_create_path(&[invalid_leaf_value], 0).unwrap();
	let root = tree.root();

	let circuit = prover.create_circuit(
		arbitrary_input.clone(),
		leaf_private,
		path,
		root,
		nullifier_hash,
	);

	let mut public_inputs = Vec::new();
	public_inputs.push(nullifier_hash);
	public_inputs.push(root);
	public_inputs.push(arbitrary_input.recipient);
	public_inputs.push(arbitrary_input.relayer);
	public_inputs.push(arbitrary_input.fee);
	public_inputs.push(arbitrary_input.refund);

	let (pk, vk) = setup_keys::<Bn254, _, _>(circuit.clone(), rng).unwrap();
	let proof = prove::<Bn254, _, _>(circuit, &pk, rng).unwrap();
	let res = verify::<Bn254>(&public_inputs, &vk, &proof).unwrap();

	assert!(!res);
}

#[test]
fn should_fail_with_invalid_nullifier() {
	let rng = &mut test_rng();
	let curve = Curve::Bn254;

	let recipient = Bn254Fr::one();
	let relayer = Bn254Fr::zero();
	let fee = Bn254Fr::zero();
	let refund = Bn254Fr::zero();

	let params3 = setup_params_x5_3::<Bn254Fr>(curve);
	let prover = MixerR1CSProver::<Bn254, PoseidonGadget<Bn254Fr>, LEN> {
		default_leaf: [0u8; 32],
		hasher: Poseidon::<Bn254Fr> { params: params3 },
		engine: PhantomData,
	};

	let leaf = prover.create_leaf_with_privates(None, None, rng).unwrap();
	let secret = Bn254Fr::from_le_bytes_mod_order(&leaf.secret_bytes);
	let nullifier_hash = Bn254Fr::from_le_bytes_mod_order(&leaf.nullifier_hash_bytes);
	let leaf_value = Bn254Fr::from_le_bytes_mod_order(&leaf.leaf_bytes);
	
	let arbitrary_input =
		setup_arbitrary_data(recipient, relayer, fee, refund);

	// Invalid nullifier
	let leaf_private = Private::new(secret, Bn254Fr::rand(rng));
	let (tree, path) = prover.setup_tree_and_create_path(&[leaf_value], 0).unwrap();
	let root = tree.root();

	let circuit = prover.create_circuit(
		arbitrary_input.clone(),
		leaf_private,
		path,
		root,
		nullifier_hash,
	);

	let mut public_inputs = Vec::new();
	public_inputs.push(nullifier_hash);
	public_inputs.push(root);
	public_inputs.push(arbitrary_input.recipient);
	public_inputs.push(arbitrary_input.relayer);
	public_inputs.push(arbitrary_input.fee);
	public_inputs.push(arbitrary_input.refund);

	let (pk, vk) = setup_keys::<Bn254, _, _>(circuit.clone(), rng).unwrap();
	let proof = prove::<Bn254, _, _>(circuit, &pk, rng).unwrap();
	let res = verify::<Bn254>(&public_inputs, &vk, &proof).unwrap();

	assert!(!res);
}

#[test]
fn setup_and_prove_mixer_raw_inputs() {
	let rng = &mut test_rng();
	let curve = Curve::Bn254;

	let recipient = Bn254Fr::one();
	let relayer = Bn254Fr::zero();
	let fee = 0;
	let refund = 0;

	let recipient_raw = recipient.into_repr().to_bytes_le();
	let relayer_raw = relayer.into_repr().to_bytes_le();

	let params3 = setup_params_x5_3::<Bn254Fr>(curve);
	let prover = MixerR1CSProver::<Bn254, PoseidonGadget<Bn254Fr>, LEN> {
		default_leaf: [0u8; 32],
		hasher: Poseidon::<Bn254Fr> { params: params3 },
		engine: PhantomData,
	};

	let leaf = prover.create_leaf_with_privates(None, None, rng).unwrap();
	let index = 0;
	let leaves_raw = vec![leaf.leaf_bytes];

	let (circuit, .., public_inputs_raw) = prover
		.setup_circuit_with_privates_raw(
			leaf.secret_bytes,
			leaf.nullifier_bytes,
			&leaves_raw,
			index,
			recipient_raw,
			relayer_raw,
			fee,
			refund,
		)
		.unwrap();

	let public_inputs: Vec<Bn254Fr> = public_inputs_raw
		.iter()
		.map(|x| Bn254Fr::from_le_bytes_mod_order(x))
		.collect();

	let (pk, vk) = setup_keys::<Bn254, _, _>(circuit.clone(), rng).unwrap();
	let proof = prove::<Bn254, _, _>(circuit, &pk, rng).unwrap();
	let res = verify::<Bn254>(&public_inputs, &vk, &proof).unwrap();
	assert!(
		res,
		"Failed to verify Proof, here is the inputs:
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
fn setup_and_prove_mixer_raw_inputs_unchecked() {
	let rng = &mut test_rng();
	let curve = Curve::Bn254;

	let recipient = Bn254Fr::one();
	let relayer = Bn254Fr::zero();
	let fee = 0;
	let refund = 0;

	let recipient_raw = recipient.into_repr().to_bytes_le();
	let relayer_raw = relayer.into_repr().to_bytes_le();

	let params3 = setup_params_x5_3::<Bn254Fr>(curve);
	let prover = MixerR1CSProver::<Bn254, PoseidonGadget<Bn254Fr>, LEN> {
		default_leaf: [0u8; 32],
		hasher: Poseidon::<Bn254Fr> { params: params3 },
		engine: PhantomData,
	};

	let leaf = prover.create_leaf_with_privates(None, None, rng).unwrap();
	let leaves_raw = vec![leaf.leaf_bytes];
	let index = 0;

	let (circuit, .., public_inputs_raw) = prover
		.setup_circuit_with_privates_raw(
			leaf.secret_bytes,
			leaf.nullifier_bytes,
			&leaves_raw,
			index,
			recipient_raw,
			relayer_raw,
			fee,
			refund,
		)
		.unwrap();

	let (pk, vk) = setup_keys_unchecked::<Bn254, _, _>(circuit.clone(), rng).unwrap();
	let proof = prove_unchecked::<Bn254, _, _>(circuit, &pk, rng).unwrap();
	let res = verify_unchecked_raw::<Bn254>(&public_inputs_raw, &vk, &proof).unwrap();
	assert!(
		res,
		"Failed to verify Proof, here is the inputs:
        recipient = {},
        relayer = {},
        fee = {},
        refund = {},
        public_inputs = {:?},
        proof = {:?},
        ",
		recipient, relayer, fee, refund, public_inputs_raw, proof
	);
}
