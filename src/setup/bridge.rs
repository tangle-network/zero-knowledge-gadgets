use ark_ec::PairingEngine;
use ark_ff::PrimeField;
use super::common::*;
use crate::{
	arbitrary::bridge_data::{constraints::BridgeDataGadget, BridgeData, Input as BridgeDataInput},
	circuit::bridge::BridgeCircuit,
	leaf::{
		bridge::{
			constraints::BridgeLeafGadget, BridgeLeaf, Private as LeafPrivate, Public as LeafPublic,
		},
		LeafCreation,
	},
	poseidon::PoseidonParameters,
	set::{
		membership::{constraints::SetMembershipGadget, SetMembership},
		Set,
	},
};
use ark_crypto_primitives::SNARK;
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_std::{
	rand::{CryptoRng, Rng, RngCore},
	vec::Vec,
};

pub type BridgeConstraintData<F> = BridgeData<F>;
pub type BridgeConstraintDataInput<F> = BridgeDataInput<F>;
pub type BridgeConstraintDataGadget<F> = BridgeDataGadget<F>;

pub type Leaf<F> = BridgeLeaf<F, PoseidonCRH5<F>>;
pub type LeafGadget<F> = BridgeLeafGadget<F, PoseidonCRH5<F>, PoseidonCRH5Gadget<F>, Leaf<F>>;

pub type TestSetMembership<F> = SetMembership<F>;
pub type TestSetMembershipGadget<F> = SetMembershipGadget<F>;

pub type Circuit<F>= BridgeCircuit<
	F,
	BridgeConstraintData<F>,
	BridgeConstraintDataGadget<F>,
	PoseidonCRH5<F>,
	PoseidonCRH5Gadget<F>,
	TreeConfig<F>,
	LeafCRHGadget<F>,
	PoseidonCRH3Gadget<F>,
	Leaf<F>,
	LeafGadget<F>,
	TestSetMembership<F>,
	TestSetMembershipGadget<F>,
>;

pub fn setup_leaf<R: Rng, F: PrimeField>(
	chain_id: F,
	params: &PoseidonParameters<F>,
	rng: &mut R,
) -> (
	LeafPrivate<F>,
	LeafPublic<F>,
	<Leaf<F> as LeafCreation<PoseidonCRH5<F>>>::Leaf,
	<Leaf<F> as LeafCreation<PoseidonCRH5<F>>>::Nullifier,
) {
	// Secret inputs for the leaf
	let leaf_private = Leaf::generate_secrets(rng).unwrap();
	// Public inputs for the leaf
	let leaf_public = LeafPublic::new(chain_id);

	// Creating the leaf
	let leaf = Leaf::create_leaf(&leaf_private, &leaf_public, params).unwrap();
	let nullifier_hash = Leaf::create_nullifier(&leaf_private, params).unwrap();
	(leaf_private, leaf_public, leaf, nullifier_hash)
}

pub fn setup_set<F: PrimeField>(
	root: &F,
	roots: &Vec<F>,
) -> <TestSetMembership<F> as Set<F>>::Private {
	TestSetMembership::generate_secrets(root, roots).unwrap()
}

pub fn setup_arbitrary_data<F: PrimeField>(
	recipient: F,
	relayer: F,
	fee: F,
) -> BridgeConstraintDataInput<F> {
	let arbitrary_input = BridgeConstraintDataInput::new(recipient, relayer, fee);
	arbitrary_input
}

pub fn setup_circuit<R: Rng, F: PrimeField>(
	chain_id: F,
	leaves: &[F],
	index: u64,
	roots: &[F],
	recipient: F,
	relayer: F,
	fee: F,
	rng: &mut R,
) -> (Circuit<F>, F, F, F, Vec<F>) {
	let params3 = setup_params_3::<F>();
	let params5 = setup_params_5::<F>();

	let arbitrary_input = setup_arbitrary_data(recipient, relayer, fee);
	let (leaf_private, leaf_public, leaf, nullifier_hash) = setup_leaf(chain_id, &params5, rng);
	let mut leaves_new = leaves.to_vec();
	leaves_new.push(leaf);
	let (tree, path) = setup_tree_and_create_path(&leaves_new, index, &params3);
	let root = tree.root().inner();
	let mut roots_new = roots.to_vec();
	roots_new.push(root);
	let set_private_inputs = setup_set(&root, &roots_new);

	let mc = Circuit::new(
		arbitrary_input.clone(),
		leaf_private,
		leaf_public,
		set_private_inputs,
		roots_new.clone(),
		params5,
		path,
		root.clone(),
		nullifier_hash,
	);
	let public_inputs = get_public_inputs(
		chain_id,
		nullifier_hash,
		roots_new,
		root,
		recipient,
		relayer,
		fee,
	);
	(mc, leaf, nullifier_hash, root, public_inputs)
}

pub fn setup_random_circuit<R: Rng, F: PrimeField>(rng: &mut R) -> (Circuit<F>, F, F, F, Vec<F>) {
	let chain_id = F::rand(rng);
	let leaves = Vec::new();
	let index = 0;
	let roots = Vec::new();
	let recipient = F::rand(rng);
	let relayer = F::rand(rng);
	let fee = F::rand(rng);
	setup_circuit::<R, F>(
		chain_id, &leaves, index, &roots, recipient, relayer, fee, rng,
	)
}

pub fn get_public_inputs<F: PrimeField>(
	chain_id: F,
	nullifier_hash: F,
	roots: Vec<F>,
	root: F,
	recipient: F,
	relayer: F,
	fee: F,
) -> Vec<F> {
	let mut public_inputs = Vec::new();
	public_inputs.push(chain_id);
	public_inputs.push(nullifier_hash);
	public_inputs.extend(roots);
	public_inputs.push(root);
	public_inputs.push(recipient);
	public_inputs.push(relayer);
	public_inputs.push(fee);
	public_inputs
}

pub fn prove_groth16<R: RngCore + CryptoRng, E: PairingEngine>(
	pk: &ProvingKey<E>,
	c: Circuit<E::Fr>,
	rng: &mut R,
) -> Proof<E> {
	Groth16::<E>::prove(pk, c, rng).unwrap()
}

pub fn setup_groth16<R: RngCore + CryptoRng, E: PairingEngine>(
	rng: &mut R,
	c: Circuit<E::Fr>,
) -> (ProvingKey<E>, VerifyingKey<E>) {
	let (pk, vk) = Groth16::<E>::circuit_specific_setup(c, rng).unwrap();
	(pk, vk)
}

pub fn setup_random_groth16<R: RngCore + CryptoRng, E: PairingEngine>(
	rng: &mut R,
) -> (ProvingKey<E>, VerifyingKey<E>) {
	let (circuit, ..) = setup_random_circuit(rng);
	let (pk, vk) = Groth16::<E>::circuit_specific_setup(circuit.clone(), rng).unwrap();
	(pk, vk)
}

#[cfg(test)]
mod test {
	use super::*;
	use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
	use ark_std::test_rng;
	use ark_bls12_381::{Bls12_381, Fr as Bls381};


	fn add_members_mock(_leaves: Vec<Bls381>) {}

	fn verify_zk_mock(
		_root: Bls381,
		_private_inputs: Vec<Bls381>,
		_nullifier_hash: Bls381,
		_proof_bytes: Vec<u8>,
		_path_index_commitments: Vec<Bls381>,
		_path_node_commitments: Vec<Bls381>,
		_recipient: Bls381,
		_relayer: Bls381,
	) {}

	#[test]
	fn should_create_setup() {
		let mut rng = test_rng();
		let chain_id = Bls381::from(0u8);
		let recipient = Bls381::from(0u8);
		let relayer = Bls381::from(0u8);
		let fee = Bls381::from(0u8);
		let leaves = Vec::new();
		let roots = Vec::new();
		let (circuit, leaf, nullifier, root, public_inputs) = setup_circuit::<_, Bls381>(
			chain_id, &leaves, 0, &roots, recipient, relayer, fee, &mut rng,
		);

		add_members_mock(vec![leaf]);

		// let (pk, vk) = setup_circuit_groth16(&mut rng, circuit.clone());
		let (pk, vk) = setup_random_groth16::<_, Bls12_381>(&mut rng);
		let proof = prove_groth16(&pk, circuit.clone(), &mut rng);
		let res = verify_groth16(&vk, &public_inputs, &proof);

		verify_zk_mock(
			root,
			Vec::new(),
			nullifier,
			Vec::new(),
			Vec::new(),
			Vec::new(),
			recipient,
			relayer,
		);

		assert!(res);
	}

	#[test]
	fn should_create_longer_setup() {
		let mut rng = test_rng();
		let chain_id = Bls381::from(0u8);
		let recipient = Bls381::from(0u8);
		let relayer = Bls381::from(0u8);
		let fee = Bls381::from(0u8);
		let leaves = Vec::new();
		let roots = Vec::new();

		let params3 = setup_params_3::<Bls381>();
		let params5 = setup_params_5::<Bls381>();

		let arbitrary_input = setup_arbitrary_data::<Bls381>(recipient, relayer, fee);
		let (leaf_private, leaf_public, leaf, nullifier_hash) =
			setup_leaf::<_, Bls381>(chain_id, &params5, &mut rng);
		let mut leaves_new = leaves.to_vec();
		leaves_new.push(leaf);
		let (tree, path) = setup_tree_and_create_path::<Bls381>(&leaves_new, 0, &params3);
		let root = tree.root().inner();
		let mut roots_new = roots.to_vec();
		roots_new.push(root);
		let set_private_inputs = setup_set::<Bls381>(&root, &roots_new);

		let mc = Circuit::<Bls381>::new(
			arbitrary_input.clone(),
			leaf_private,
			leaf_public,
			set_private_inputs,
			roots_new.clone(),
			params5,
			path,
			root.clone(),
			nullifier_hash,
		);
		let public_inputs = get_public_inputs::<Bls381>(
			chain_id,
			nullifier_hash,
			roots_new,
			root,
			recipient,
			relayer,
			fee,
		);

		add_members_mock(vec![leaf]);

		// let (pk, vk) = setup_random_groth16(&mut rng, circuit.clone());
		let (pk, vk) = setup_random_groth16::<_, Bls12_381>(&mut rng);
		let proof = prove_groth16(&pk, mc.clone(), &mut rng);
		let res = verify_groth16(&vk, &public_inputs, &proof);

		verify_zk_mock(
			root,
			Vec::new(),
			nullifier_hash,
			Vec::new(),
			Vec::new(),
			Vec::new(),
			recipient,
			relayer,
		);

		assert!(res);
	}

	#[test]
	fn should_handle_proof_deserialization() {
		let mut rng = test_rng();
		let chain_id = Bls381::from(0u8);
		let recipient = Bls381::from(0u8);
		let relayer = Bls381::from(0u8);
		let fee = Bls381::from(0u8);
		let leaves = Vec::new();
		let roots = Vec::new();
		let (circuit, leaf, nullifier, root, public_inputs) = setup_circuit::<_, Bls381>(
			chain_id, &leaves, 0, &roots, recipient, relayer, fee, &mut rng,
		);

		add_members_mock(vec![leaf]);

		// let (pk, vk) = setup_groth16(&mut rng, circuit.clone());
		let (pk, vk) = setup_random_groth16::<_, Bls12_381>(&mut rng);
		let proof = prove_groth16::<_, Bls12_381>(&pk, circuit.clone(), &mut rng);
		let mut proof_bytes = vec![0u8; proof.serialized_size()];
		proof.serialize(&mut proof_bytes[..]).unwrap();
		let proof_anew = Proof::<Bls12_381>::deserialize(&proof_bytes[..]).unwrap();
		let res = verify_groth16::<Bls12_381>(&vk, &public_inputs, &proof_anew);

		verify_zk_mock(
			root,
			Vec::new(),
			nullifier,
			Vec::new(),
			Vec::new(),
			Vec::new(),
			recipient,
			relayer,
		);

		assert!(res);
	}
}
