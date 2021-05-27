use crate::{
	arbitrary::mixer_data::{constraints::MixerDataGadget, Input as MixerDataInput, MixerData},
	circuit::mixer_circuit::MixerCircuit,
	leaf::{
		bridge::{
			constraints::BridgeLeafGadget, BridgeLeaf, Private as LeafPrivate, Public as LeafPublic,
		},
		LeafCreation,
	},
	merkle_tree::{Config as MerkleConfig, Path, SparseMerkleTree},
	set::{
		membership::{constraints::SetMembershipGadget, SetMembership},
		Set,
	},
	test_data::{get_mds_3, get_mds_5, get_rounds_3, get_rounds_5},
};
use ark_bls12_381::{Bls12_381, Fr as Bls381};
use ark_ff::fields::PrimeField;
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_std::{
	rand::{CryptoRng, Rng, RngCore},
	rc::Rc,
	vec::Vec,
	UniformRand,
};
use webb_crypto_primitives::{
	crh::{
		identity::{constraints::CRHGadget as IdentityCRHGadget, CRH as IdentityCRH},
		poseidon::{constraints::CRHGadget, sbox::PoseidonSbox, PoseidonParameters, Rounds, CRH},
	},
	SNARK,
};

pub type MixerConstraintData = MixerData<Bls381>;
pub type MixerConstraintDataInput = MixerDataInput<Bls381>;
pub type MixerConstraintDataGadget = MixerDataGadget<Bls381>;
#[derive(Default, Clone)]
pub struct PoseidonRounds5;

impl Rounds for PoseidonRounds5 {
	const FULL_ROUNDS: usize = 8;
	const PARTIAL_ROUNDS: usize = 57;
	const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
	const WIDTH: usize = 5;
}

pub type LeafCRH = IdentityCRH<Bls381>;
pub type LeafCRHGadget = IdentityCRHGadget<Bls381>;

pub type PoseidonCRH5 = CRH<Bls381, PoseidonRounds5>;
pub type PoseidonCRH5Gadget = CRHGadget<Bls381, PoseidonRounds5>;

#[derive(Default, Clone)]
pub struct PoseidonRounds3;

impl Rounds for PoseidonRounds3 {
	const FULL_ROUNDS: usize = 8;
	const PARTIAL_ROUNDS: usize = 57;
	const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
	const WIDTH: usize = 3;
}

pub type PoseidonCRH3 = CRH<Bls381, PoseidonRounds3>;
pub type PoseidonCRH3Gadget = CRHGadget<Bls381, PoseidonRounds3>;

pub type Leaf = BridgeLeaf<Bls381, PoseidonCRH5>;
pub type LeafGadget = BridgeLeafGadget<Bls381, PoseidonCRH5, PoseidonCRH5Gadget, Leaf>;

#[derive(Clone)]
pub struct MixerTreeConfig;
impl MerkleConfig for MixerTreeConfig {
	type H = PoseidonCRH3;
	type LeafH = LeafCRH;

	const HEIGHT: u8 = 30;
}

pub type MixerTree = SparseMerkleTree<MixerTreeConfig>;

pub type TestSetMembership = SetMembership<Bls381>;
pub type TestSetMembershipGadget = SetMembershipGadget<Bls381>;

pub type Circuit = MixerCircuit<
	Bls381,
	MixerConstraintData,
	MixerConstraintDataGadget,
	PoseidonCRH5,
	PoseidonCRH5Gadget,
	MixerTreeConfig,
	LeafCRHGadget,
	PoseidonCRH3Gadget,
	Leaf,
	LeafGadget,
	TestSetMembership,
	TestSetMembershipGadget,
>;

pub fn setup_params_3<F: PrimeField>() -> PoseidonParameters<F> {
	// Making params for poseidon in merkle tree
	let rounds3 = get_rounds_3::<F>();
	let mds3 = get_mds_3::<F>();
	let params3 = PoseidonParameters::<F>::new(rounds3, mds3);
	params3
}

pub fn setup_params_5<F: PrimeField>() -> PoseidonParameters<F> {
	// Round params for the poseidon in leaf creation gadget
	let rounds5 = get_rounds_5::<F>();
	let mds5 = get_mds_5::<F>();
	let params5 = PoseidonParameters::<F>::new(rounds5, mds5);
	params5
}

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

pub fn setup_tree(leaves: &[Bls381], params: &PoseidonParameters<Bls381>) -> MixerTree {
	let inner_params = Rc::new(params.clone());
	let mt = MixerTree::new_sequential(inner_params, Rc::new(()), leaves).unwrap();
	mt
}

pub fn setup_tree_and_create_path(
	leaves: &[Bls381],
	index: u64,
	params: &PoseidonParameters<Bls381>,
) -> (MixerTree, Path<MixerTreeConfig>) {
	// Making the merkle tree
	let mt = setup_tree(leaves, params);
	// Getting the proof path
	let path = mt.generate_membership_proof(index);
	(mt, path)
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
) -> MixerConstraintDataInput {
	let arbitrary_input = MixerConstraintDataInput::new(recipient, relayer, fee);
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

pub fn verify_groth16(
	vk: &VerifyingKey<Bls12_381>,
	public_inputs: &Vec<Bls381>,
	proof: &Proof<Bls12_381>,
) -> bool {
	let res = Groth16::<Bls12_381>::verify(vk, public_inputs, proof);
	match res {
		Ok(is_valid) => is_valid,
		Err(e) => panic!("{}", e),
	}
}

pub fn prove_groth16<R: RngCore + CryptoRng>(
	pk: &ProvingKey<Bls12_381>,
	c: Circuit,
	rng: &mut R,
) -> Proof<Bls12_381> {
	Groth16::<Bls12_381>::prove(pk, c, rng).unwrap()
}

pub fn setup_circuit_groth16<R: RngCore + CryptoRng>(
	rng: &mut R,
	c: Circuit,
) -> (ProvingKey<Bls12_381>, VerifyingKey<Bls12_381>) {
	let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(c, rng).unwrap();
	(pk, vk)
}

pub fn setup_groth16<R: RngCore + CryptoRng>(
	rng: &mut R,
) -> (ProvingKey<Bls12_381>, VerifyingKey<Bls12_381>) {
	let (circuit, ..) = setup_random_circuit(rng);
	let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(circuit.clone(), rng).unwrap();
	(pk, vk)
}

#[macro_export]
macro_rules! setup_types {
	($test_field:ty) => {
		type MixerConstraintData = MixerData<$test_field>;
		type MixerConstraintDataGadget = MixerDataGadget<$test_field>;
		#[derive(Default, Clone)]
		struct PoseidonRounds5;

		impl Rounds for PoseidonRounds5 {
			const FULL_ROUNDS: usize = 8;
			const PARTIAL_ROUNDS: usize = 57;
			const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
			const WIDTH: usize = 5;
		}

		type PoseidonCRH5 = CRH<$test_field, PoseidonRounds5>;
		type PoseidonCRH5Gadget = CRHGadget<$test_field, PoseidonRounds5>;

		#[derive(Default, Clone)]
		struct PoseidonRounds3;

		impl Rounds for PoseidonRounds3 {
			const FULL_ROUNDS: usize = 8;
			const PARTIAL_ROUNDS: usize = 57;
			const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
			const WIDTH: usize = 3;
		}

		type PoseidonCRH3 = CRH<$test_field, PoseidonRounds3>;
		type PoseidonCRH3Gadget = CRHGadget<$test_field, PoseidonRounds3>;

		type Leaf = BridgeLeaf<$test_field, PoseidonCRH5>;
		type LeafGadget = BridgeLeafGadget<$test_field, PoseidonCRH5, PoseidonCRH5Gadget, Leaf>;

		#[derive(Clone)]
		struct MixerTreeConfig;
		impl MerkleConfig for MixerTreeConfig {
			type H = PoseidonCRH3;
			type LeafH = PoseidonCRH3;

			const HEIGHT: u8 = 10;
		}

		type MixerTree = SparseMerkleTree<MixerTreeConfig>;

		type TestSetMembership = SetMembership<$test_field>;
		type TestSetMembershipGadget = SetMembershipGadget<$test_field>;

		type Circuit = MixerCircuit<
			$test_field,
			MixerConstraintData,
			MixerConstraintDataGadget,
			PoseidonCRH5,
			PoseidonCRH5Gadget,
			MixerTreeConfig,
			PoseidonCRH3Gadget,
			PoseidonCRH3Gadget,
			Leaf,
			LeafGadget,
			TestSetMembership,
			TestSetMembershipGadget,
		>;
	};
}

#[macro_export]
macro_rules! setup_params_3 {
	($test_field:ty) => {{
		// Making params for poseidon in merkle tree
		let rounds3 = get_rounds_3::<$test_field>();
		let mds3 = get_mds_3::<$test_field>();
		let params3 = PoseidonParameters::<$test_field>::new(rounds3, mds3);
		params3
	}};
}

#[macro_export]
macro_rules! setup_params_5 {
	($test_field:ty) => {{
		// Round params for the poseidon in leaf creation gadget
		let rounds5 = get_rounds_5::<$test_field>();
		let mds5 = get_mds_5::<$test_field>();
		let params5 = PoseidonParameters::<$test_field>::new(rounds5, mds5);
		params5
	}};
}

#[macro_export]
macro_rules! setup_leaf {
	($test_field:ty, $params:expr) => {{
		let rng = &mut test_rng();

		// Secret inputs for the leaf
		let leaf_private = Leaf::generate_secrets(rng).unwrap();
		// Public inputs for the leaf
		let chain_id = <$test_field>::one();
		let leaf_public = LeafPublic::new(chain_id);

		// Creating the leaf
		let leaf = Leaf::create_leaf(&leaf_private, &leaf_public, &$params).unwrap();
		let nullifier_hash = Leaf::create_nullifier(&leaf_private, &$params).unwrap();
		(leaf_private, leaf_public, leaf, nullifier_hash, chain_id)
	}};
}

#[macro_export]
macro_rules! setup_tree {
	($test_field:ty, $leaf:expr, $params3:expr) => {{
		let rng = &mut test_rng();
		let leaves = vec![
			<$test_field>::rand(rng),
			<$test_field>::rand(rng),
			$leaf,
			<$test_field>::rand(rng),
		];
		let inner_params = Rc::new($params3.clone());
		let leaf_params = inner_params.clone();
		// Making the merkle tree
		let mt = MixerTree::new_sequential(inner_params, leaf_params, &leaves).unwrap();
		// Getting the proof path
		let path = mt.generate_membership_proof(2);
		let root = mt.root();
		(root, path)
	}};
}

#[macro_export]
macro_rules! setup_set {
	($test_field:ty, $root:expr) => {{
		let rng = &mut test_rng();
		let roots = vec![
			<$test_field>::rand(rng),
			<$test_field>::rand(rng),
			<$test_field>::rand(rng),
			$root,
		];
		let set_private_inputs = TestSetMembership::generate_secrets(&$root, &roots).unwrap();
		(set_private_inputs, roots)
	}};
}

#[macro_export]
macro_rules! setup_arbitrary_data {
	($test_field:ty) => {{
		let rng = &mut test_rng();
		let fee = <$test_field>::rand(rng);
		let recipient = <$test_field>::rand(rng);
		let relayer = <$test_field>::rand(rng);
		// Arbitrary data
		let arbitrary_input = MixerDataInput::new(recipient, relayer, fee);
		arbitrary_input
	}};
}

#[macro_export]
macro_rules! setup_circuit {
	($test_field:ty) => {{
		setup_types!($test_field);
		let params5 = setup_params_5!($test_field);
		let params3 = setup_params_3!($test_field);

		let (leaf_private, leaf_public, leaf, nullifier_hash, chain_id) =
			setup_leaf!($test_field, params5);
		let arbitrary_input = setup_arbitrary_data!($test_field);
		let (root, path) = setup_tree!($test_field, leaf, params3);
		let (set_private_inputs, roots) = setup_set!($test_field, root.clone().inner());

		let mc = Circuit::new(
			arbitrary_input.clone(),
			leaf_private,
			leaf_public,
			set_private_inputs,
			roots.clone(),
			params5,
			path,
			root.clone().inner(),
			nullifier_hash,
		);
		let mut public_inputs = Vec::new();
		public_inputs.push(chain_id);
		public_inputs.push(nullifier_hash);
		public_inputs.extend(roots);
		public_inputs.push(root.inner());
		public_inputs.push(arbitrary_input.recipient);
		public_inputs.push(arbitrary_input.relayer);
		public_inputs.push(arbitrary_input.fee);
		(public_inputs, mc)
	}};
}

#[macro_export]
macro_rules! verify_groth16 {
	($engine:ty, $circuit:expr, $public_inputs:expr) => {{
		let rng = &mut test_rng();
		let (pk, vk) = Groth16::<$engine>::circuit_specific_setup($circuit.clone(), rng).unwrap();
		let proof = Groth16::<$engine>::prove(&pk, $circuit, rng).unwrap();
		let res = Groth16::<$engine>::verify(&vk, &$public_inputs, &proof).unwrap();
		res
	}};
}

#[cfg(test)]
mod test {
	use super::*;
	use ark_ff::to_bytes;
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
		let (pk, vk) = setup_groth16(&mut rng);
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

		// let (pk, vk) = setup_circuit_groth16(&mut rng, circuit.clone());
		let (pk, vk) = setup_groth16(&mut rng);
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

		// let (pk, vk) = setup_circuit_groth16(&mut rng, circuit.clone());
		let (pk, vk) = setup_groth16(&mut rng);
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
