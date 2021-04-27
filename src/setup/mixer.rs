use crate::{
	arbitrary::mixer_data::{constraints::MixerDataGadget, Input as MixerDataInput, MixerData},
	circuit::mixer_circuit::MixerCircuit,
	leaf::{
		bridge::{
			constraints::BridgeLeafGadget, BridgeLeaf, Private as LeafPrivate, Public as LeafPublic,
		},
		LeafCreation,
	},
	set::membership::{constraints::SetMembershipGadget, SetMembership},
	test_data::{get_mds_3, get_mds_5, get_rounds_3, get_rounds_5},
};
use ark_bls12_381::{Bls12_381, Fr as BlsFr};
use ark_ff::fields::PrimeField;
use ark_std::rand::Rng;
use webb_crypto_primitives::{
	crh::poseidon::{constraints::CRHGadget, sbox::PoseidonSbox, PoseidonParameters, Rounds, CRH},
	merkle_tree::{Config as MerkleConfig, MerkleTree, Path},
	SNARK,
};

type MixerConstraintData = MixerData<BlsFr>;
type MixerConstraintDataGadget = MixerDataGadget<BlsFr>;
#[derive(Default, Clone)]
struct PoseidonRounds5;

impl Rounds for PoseidonRounds5 {
	const FULL_ROUNDS: usize = 8;
	const PARTIAL_ROUNDS: usize = 57;
	const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
	const WIDTH: usize = 5;
}

type PoseidonCRH5 = CRH<BlsFr, PoseidonRounds5>;
type PoseidonCRH5Gadget = CRHGadget<BlsFr, PoseidonRounds5>;

#[derive(Default, Clone)]
struct PoseidonRounds3;

impl Rounds for PoseidonRounds3 {
	const FULL_ROUNDS: usize = 8;
	const PARTIAL_ROUNDS: usize = 57;
	const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
	const WIDTH: usize = 3;
}

type PoseidonCRH3 = CRH<BlsFr, PoseidonRounds3>;
type PoseidonCRH3Gadget = CRHGadget<BlsFr, PoseidonRounds3>;

type Leaf = BridgeLeaf<BlsFr, PoseidonCRH5>;
type LeafGadget = BridgeLeafGadget<BlsFr, PoseidonCRH5, PoseidonCRH5Gadget, Leaf>;

#[derive(Clone)]
struct MixerTreeConfig;
impl MerkleConfig for MixerTreeConfig {
	type H = PoseidonCRH3;

	const HEIGHT: usize = 30;
}

type MixerTree = MerkleTree<MixerTreeConfig>;

type TestSetMembership = SetMembership<BlsFr>;
type TestSetMembershipGadget = SetMembershipGadget<BlsFr>;

type Circuit = MixerCircuit<
	BlsFr,
	MixerConstraintData,
	MixerConstraintDataGadget,
	PoseidonCRH5,
	PoseidonCRH5Gadget,
	MixerTreeConfig,
	PoseidonCRH3Gadget,
	Leaf,
	LeafGadget,
	TestSetMembership,
	TestSetMembershipGadget,
>;

fn setup_params_3<F: PrimeField>() -> PoseidonParameters<F> {
	// Making params for poseidon in merkle tree
	let rounds3 = get_rounds_3::<F>();
	let mds3 = get_mds_3::<F>();
	let params3 = PoseidonParameters::<F>::new(rounds3, mds3);
	params3
}

fn setup_params_5<F: PrimeField>() -> PoseidonParameters<F> {
	// Round params for the poseidon in leaf creation gadget
	let rounds5 = get_rounds_5::<F>();
	let mds5 = get_mds_5::<F>();
	let params5 = PoseidonParameters::<F>::new(rounds5, mds5);
	params5
}

fn setup_leaf<R: Rng>(
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

fn setup_tree_and_create_path(
	leaves: &[BlsFr],
	leaf: &BlsFr,
	index: usize,
	params: &PoseidonParameters<BlsFr>,
) -> (BlsFr, Path<MixerTreeConfig>) {
	// Making the merkle tree
	let mt = MixerTree::new(params.clone(), leaves).unwrap();
	// Getting the proof path
	let path = mt.generate_proof(index, leaf).unwrap();
	let root = mt.root();
	(root, path)
}
