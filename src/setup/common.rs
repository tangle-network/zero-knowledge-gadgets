use crate::{
	identity::{constraints::CRHGadget as IdentityCRHGadget, CRH as IdentityCRH},
	merkle_tree::{Config as MerkleConfig, Path, SparseMerkleTree},
	poseidon::{constraints::CRHGadget, sbox::PoseidonSbox, PoseidonParameters, Rounds, CRH},
	utils::{
		get_mds_poseidon_bn254_x5_3, get_mds_poseidon_bn254_x5_5, get_rounds_poseidon_bn254_x5_3,
		get_rounds_poseidon_bn254_x5_5,
	},
};
use ark_bls12_381::{Bls12_381, Fr as Bls381};
use ark_crypto_primitives::SNARK;
use ark_ff::fields::PrimeField;
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_std::{rc::Rc, vec::Vec};

#[derive(Default, Clone)]
pub struct PoseidonRounds5;

impl Rounds for PoseidonRounds5 {
	const FULL_ROUNDS: usize = 8;
	const PARTIAL_ROUNDS: usize = 57;
	const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
	const WIDTH: usize = 5;
}

pub type PoseidonCRH3 = CRH<Bls381, PoseidonRounds3>;
pub type PoseidonCRH3Gadget = CRHGadget<Bls381, PoseidonRounds3>;

pub type PoseidonCRH5 = CRH<Bls381, PoseidonRounds5>;
pub type PoseidonCRH5Gadget = CRHGadget<Bls381, PoseidonRounds5>;

pub type LeafCRH = IdentityCRH<Bls381>;
pub type LeafCRHGadget = IdentityCRHGadget<Bls381>;
pub type Tree = SparseMerkleTree<TreeConfig>;

#[derive(Default, Clone)]
pub struct PoseidonRounds3;

impl Rounds for PoseidonRounds3 {
	const FULL_ROUNDS: usize = 8;
	const PARTIAL_ROUNDS: usize = 57;
	const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
	const WIDTH: usize = 3;
}

#[derive(Clone)]
pub struct TreeConfig;
impl MerkleConfig for TreeConfig {
	type H = PoseidonCRH3;
	type LeafH = LeafCRH;

	const HEIGHT: u8 = 30;
}

pub fn setup_tree(leaves: &[Bls381], params: &PoseidonParameters<Bls381>) -> Tree {
	let inner_params = Rc::new(params.clone());
	let mt = Tree::new_sequential(inner_params, Rc::new(()), leaves).unwrap();
	mt
}

pub fn setup_tree_and_create_path(
	leaves: &[Bls381],
	index: u64,
	params: &PoseidonParameters<Bls381>,
) -> (Tree, Path<TreeConfig>) {
	// Making the merkle tree
	let mt = setup_tree(leaves, params);
	// Getting the proof path
	let path = mt.generate_membership_proof(index);
	(mt, path)
}

pub fn setup_params_3<F: PrimeField>() -> PoseidonParameters<F> {
	// Making params for poseidon in merkle tree
	let rounds3 = get_rounds_poseidon_bn254_x5_3::<F>();
	let mds3 = get_mds_poseidon_bn254_x5_3::<F>();
	let params3 = PoseidonParameters::<F>::new(rounds3, mds3);
	params3
}

pub fn setup_params_5<F: PrimeField>() -> PoseidonParameters<F> {
	// Round params for the poseidon in leaf creation gadget
	let rounds5 = get_rounds_poseidon_bn254_x5_5::<F>();
	let mds5 = get_mds_poseidon_bn254_x5_5::<F>();
	let params5 = PoseidonParameters::<F>::new(rounds5, mds5);
	params5
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
