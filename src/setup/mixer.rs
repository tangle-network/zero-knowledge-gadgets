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
use ark_bls12_381::{Bls12_381, Fr as BlsFr};
use ark_ff::fields::PrimeField;
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_std::{
	rand::{CryptoRng, Rng, RngCore},
	rc::Rc,
	vec::Vec,
	UniformRand,
};
use webb_crypto_primitives::{
	crh::poseidon::{constraints::CRHGadget, sbox::PoseidonSbox, PoseidonParameters, Rounds, CRH},
	SNARK,
};

pub type MixerConstraintData = MixerData<BlsFr>;
pub type MixerConstraintDataInput = MixerDataInput<BlsFr>;
pub type MixerConstraintDataGadget = MixerDataGadget<BlsFr>;
#[derive(Default, Clone)]
pub struct PoseidonRounds5;

impl Rounds for PoseidonRounds5 {
	const FULL_ROUNDS: usize = 8;
	const PARTIAL_ROUNDS: usize = 57;
	const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
	const WIDTH: usize = 5;
}

pub type PoseidonCRH5 = CRH<BlsFr, PoseidonRounds5>;
pub type PoseidonCRH5Gadget = CRHGadget<BlsFr, PoseidonRounds5>;

#[derive(Default, Clone)]
pub struct PoseidonRounds3;

impl Rounds for PoseidonRounds3 {
	const FULL_ROUNDS: usize = 8;
	const PARTIAL_ROUNDS: usize = 57;
	const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
	const WIDTH: usize = 3;
}

pub type PoseidonCRH3 = CRH<BlsFr, PoseidonRounds3>;
pub type PoseidonCRH3Gadget = CRHGadget<BlsFr, PoseidonRounds3>;

pub type Leaf = BridgeLeaf<BlsFr, PoseidonCRH5>;
pub type LeafGadget = BridgeLeafGadget<BlsFr, PoseidonCRH5, PoseidonCRH5Gadget, Leaf>;

#[derive(Clone)]
pub struct MixerTreeConfig;
impl MerkleConfig for MixerTreeConfig {
	type H = PoseidonCRH3;
	type LeafH = PoseidonCRH3;

	const HEIGHT: u8 = 30;
}

pub type MixerTree = SparseMerkleTree<MixerTreeConfig>;

pub type TestSetMembership = SetMembership<BlsFr>;
pub type TestSetMembershipGadget = SetMembershipGadget<BlsFr>;

pub type Circuit = MixerCircuit<
	BlsFr,
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
	chain_id: BlsFr,
	params: &PoseidonParameters<BlsFr>,
	rng: &mut R,
) -> (
	LeafPrivate<BlsFr>,
	LeafPublic<BlsFr>,
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

pub fn setup_tree(leaves: &[BlsFr], params: &PoseidonParameters<BlsFr>) -> MixerTree {
	let inner_params = Rc::new(params.clone());
	let leaf_params = inner_params.clone();
	let mt = MixerTree::new_sequential(inner_params, leaf_params, leaves).unwrap();
	mt
}

pub fn setup_tree_and_create_path(
	leaves: &[BlsFr],
	index: u64,
	params: &PoseidonParameters<BlsFr>,
) -> (MixerTree, Path<MixerTreeConfig>) {
	// Making the merkle tree
	let mt = setup_tree(leaves, params);
	// Getting the proof path
	let path = mt.generate_membership_proof(index);
	(mt, path)
}

pub fn setup_set(root: &BlsFr, roots: &Vec<BlsFr>) -> <TestSetMembership as Set<BlsFr>>::Private {
	TestSetMembership::generate_secrets(root, roots).unwrap()
}

pub fn setup_arbitrary_data(
	recipient: BlsFr,
	relayer: BlsFr,
	fee: BlsFr,
) -> MixerConstraintDataInput {
	let arbitrary_input = MixerConstraintDataInput::new(recipient, relayer, fee);
	arbitrary_input
}

pub fn setup_circuit<R: Rng>(
	chain_id: BlsFr,
	root: &BlsFr,
	leaves: &[BlsFr],
	index: u64,
	roots: &Vec<BlsFr>,
	recipient: BlsFr,
	relayer: BlsFr,
	fee: BlsFr,
	rng: &mut R,
) -> Circuit {
	let params3 = setup_params_3::<BlsFr>();
	let params5 = setup_params_5::<BlsFr>();

	let arbitrary_input = setup_arbitrary_data(recipient, relayer, fee);
	let (leaf_private, leaf_public, _, nullifier_hash) = setup_leaf(chain_id, &params3, rng);
	let (_, path) = setup_tree_and_create_path(leaves, index, &params3);
	let set_private_inputs = setup_set(root, roots);

	let mc = Circuit::new(
		arbitrary_input.clone(),
		leaf_private,
		leaf_public,
		set_private_inputs,
		roots.clone(),
		params5,
		path,
		root.clone(),
		nullifier_hash,
	);

	mc
}

pub fn setup_random_circuit<R: Rng>(rng: &mut R) -> Circuit {
	let chain_id = BlsFr::rand(rng);
	let root = BlsFr::rand(rng);
	let leaf = BlsFr::rand(rng);
	let leaves = vec![BlsFr::rand(rng), BlsFr::rand(rng), leaf, BlsFr::rand(rng)];
	let index = 2;
	let roots = vec![BlsFr::rand(rng), BlsFr::rand(rng), root, BlsFr::rand(rng)];
	let recipient = BlsFr::rand(rng);
	let relayer = BlsFr::rand(rng);
	let fee = BlsFr::rand(rng);
	setup_circuit(
		chain_id, &root, &leaves, index, &roots, recipient, relayer, fee, rng,
	)
}

pub fn get_public_inputs(
	chain_id: BlsFr,
	nullifier_hash: BlsFr,
	roots: Vec<BlsFr>,
	root: BlsFr,
	recipient: BlsFr,
	relayer: BlsFr,
	fee: BlsFr,
) -> Vec<BlsFr> {
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
	public_inputs: &Vec<BlsFr>,
	proof: &Proof<Bls12_381>,
) -> bool {
	let res = Groth16::<Bls12_381>::verify(vk, public_inputs, proof);
	match res {
		Ok(is_valid) => is_valid,
		Err(_) => false,
	}
}

pub fn setup_groth16<R: RngCore + CryptoRng>(
	rng: &mut R,
) -> (ProvingKey<Bls12_381>, VerifyingKey<Bls12_381>) {
	let circuit = setup_random_circuit(rng);
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
		let (leaf_private, leaf_public, leaf, nullifier_hash, chain_id) =
			setup_leaf!($test_field, params5);
		let arbitrary_input = setup_arbitrary_data!($test_field);
		let params3 = setup_params_3!($test_field);
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
