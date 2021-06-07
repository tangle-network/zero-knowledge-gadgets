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
use ark_bls12_381::{Bls12_381, Fr as Bls381};
use ark_crypto_primitives::SNARK;
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_std::{
	rand::{CryptoRng, Rng, RngCore},
	vec::Vec,
	UniformRand,
};

pub type BridgeConstraintData = BridgeData<Bls381>;
pub type BridgeConstraintDataInput = BridgeDataInput<Bls381>;
pub type BridgeConstraintDataGadget = BridgeDataGadget<Bls381>;

pub type Leaf = BridgeLeaf<Bls381, PoseidonCRH5>;
pub type LeafGadget = BridgeLeafGadget<Bls381, PoseidonCRH5, PoseidonCRH5Gadget, Leaf>;

pub type TestSetMembership = SetMembership<Bls381>;
pub type TestSetMembershipGadget = SetMembershipGadget<Bls381>;

pub type Circuit = BridgeCircuit<
	Bls381,
	BridgeConstraintData,
	BridgeConstraintDataGadget,
	PoseidonCRH5,
	PoseidonCRH5Gadget,
	TreeConfig,
	LeafCRHGadget,
	PoseidonCRH3Gadget,
	Leaf,
	LeafGadget,
	TestSetMembership,
	TestSetMembershipGadget,
>;

pub fn setup_leaf<R: Rng>(
	chain_id: Bls381,
	params: &PoseidonParameters<Bls381>,
	rng: &mut R,
) -> (
	LeafPrivate<Bls381>,
	LeafPublic<Bls381>,
	<Leaf as LeafCreation<PoseidonCRH5>>::Leaf,
	<Leaf as LeafCreation<PoseidonCRH5>>::Nullifier,
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

pub fn setup_set(
	root: &Bls381,
	roots: &Vec<Bls381>,
) -> <TestSetMembership as Set<Bls381>>::Private {
	TestSetMembership::generate_secrets(root, roots).unwrap()
}

pub fn setup_arbitrary_data(
	recipient: Bls381,
	relayer: Bls381,
	fee: Bls381,
) -> BridgeConstraintDataInput {
	let arbitrary_input = BridgeConstraintDataInput::new(recipient, relayer, fee);
	arbitrary_input
}

pub fn setup_circuit<R: Rng>(
	chain_id: Bls381,
	leaves: &[Bls381],
	index: u64,
	roots: &[Bls381],
	recipient: Bls381,
	relayer: Bls381,
	fee: Bls381,
	rng: &mut R,
) -> (Circuit, Bls381, Bls381, Bls381, Vec<Bls381>) {
	let params3 = setup_params_3::<Bls381>();
	let params5 = setup_params_5::<Bls381>();

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

pub fn setup_random_circuit<R: Rng>(rng: &mut R) -> (Circuit, Bls381, Bls381, Bls381, Vec<Bls381>) {
	let chain_id = Bls381::rand(rng);
	let leaves = Vec::new();
	let index = 0;
	let roots = Vec::new();
	let recipient = Bls381::rand(rng);
	let relayer = Bls381::rand(rng);
	let fee = Bls381::rand(rng);
	setup_circuit(
		chain_id, &leaves, index, &roots, recipient, relayer, fee, rng,
	)
}

pub fn get_public_inputs(
	chain_id: Bls381,
	nullifier_hash: Bls381,
	roots: Vec<Bls381>,
	root: Bls381,
	recipient: Bls381,
	relayer: Bls381,
	fee: Bls381,
) -> Vec<Bls381> {
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

pub fn prove_groth16<R: RngCore + CryptoRng>(
	pk: &ProvingKey<Bls12_381>,
	c: Circuit,
	rng: &mut R,
) -> Proof<Bls12_381> {
	Groth16::<Bls12_381>::prove(pk, c, rng).unwrap()
}

pub fn setup_groth16<R: RngCore + CryptoRng>(
	rng: &mut R,
	c: Circuit,
) -> (ProvingKey<Bls12_381>, VerifyingKey<Bls12_381>) {
	let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(c, rng).unwrap();
	(pk, vk)
}

pub fn setup_random_groth16<R: RngCore + CryptoRng>(
	rng: &mut R,
) -> (ProvingKey<Bls12_381>, VerifyingKey<Bls12_381>) {
	let (circuit, ..) = setup_random_circuit(rng);
	let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(circuit.clone(), rng).unwrap();
	(pk, vk)
}

#[cfg(test)]
mod test {
	use super::*;
	use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
	use ark_std::test_rng;

	fn add_members_mock(leaves: Vec<Bls381>) {}

	fn verify_zk_mock(
		root: Bls381,
		private_inputs: Vec<Bls381>,
		nullifier_hash: Bls381,
		proof_bytes: Vec<u8>,
		path_index_commitments: Vec<Bls381>,
		path_node_commitments: Vec<Bls381>,
		recipient: Bls381,
		relayer: Bls381,
	) {
	}
	#[test]
	fn should_create_setup() {
		let mut rng = test_rng();
		let chain_id = Bls381::from(0u8);
		let recipient = Bls381::from(0u8);
		let relayer = Bls381::from(0u8);
		let fee = Bls381::from(0u8);
		let leaves = Vec::new();
		let roots = Vec::new();
		let (circuit, leaf, nullifier, root, public_inputs) = setup_circuit(
			chain_id, &leaves, 0, &roots, recipient, relayer, fee, &mut rng,
		);

		add_members_mock(vec![leaf]);

		// let (pk, vk) = setup_circuit_groth16(&mut rng, circuit.clone());
		let (pk, vk) = setup_random_groth16(&mut rng);
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

		let arbitrary_input = setup_arbitrary_data(recipient, relayer, fee);
		let (leaf_private, leaf_public, leaf, nullifier_hash) =
			setup_leaf(chain_id, &params5, &mut rng);
		let mut leaves_new = leaves.to_vec();
		leaves_new.push(leaf);
		let (tree, path) = setup_tree_and_create_path(&leaves_new, 0, &params3);
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

		add_members_mock(vec![leaf]);

		// let (pk, vk) = setup_random_groth16(&mut rng, circuit.clone());
		let (pk, vk) = setup_random_groth16(&mut rng);
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
		let (circuit, leaf, nullifier, root, public_inputs) = setup_circuit(
			chain_id, &leaves, 0, &roots, recipient, relayer, fee, &mut rng,
		);

		add_members_mock(vec![leaf]);

		// let (pk, vk) = setup_groth16(&mut rng, circuit.clone());
		let (pk, vk) = setup_random_groth16(&mut rng);
		let proof = prove_groth16(&pk, circuit.clone(), &mut rng);
		let mut proof_bytes = vec![0u8; proof.serialized_size()];
		proof.serialize(&mut proof_bytes[..]).unwrap();
		let proof_anew = Proof::<Bls12_381>::deserialize(&proof_bytes[..]).unwrap();
		let res = verify_groth16(&vk, &public_inputs, &proof_anew);

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
