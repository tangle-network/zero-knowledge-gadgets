use ark_ec::PairingEngine;
use ark_std::marker::PhantomData;
use crate::{
	identity::{constraints::CRHGadget as IdentityCRHGadget, CRH as IdentityCRH},
	merkle_tree::{Config as MerkleConfig, Path, SparseMerkleTree},
	poseidon::{constraints::CRHGadget, sbox::PoseidonSbox, PoseidonParameters, Rounds, CRH},
	utils::{get_mds_3, get_mds_5, get_rounds_3, get_rounds_5},
};
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

pub type PoseidonCRH3<F> = CRH<F, PoseidonRounds3>;
pub type PoseidonCRH3Gadget<F> = CRHGadget<F, PoseidonRounds3>;

pub type PoseidonCRH5<F> = CRH<F, PoseidonRounds5>;
pub type PoseidonCRH5Gadget<F> = CRHGadget<F, PoseidonRounds5>;

pub type LeafCRH<F> = IdentityCRH<F>;
pub type LeafCRHGadget<F>= IdentityCRHGadget<F>;
pub type Tree<F> = SparseMerkleTree<TreeConfig<F>>;

#[derive(Default, Clone)]
pub struct PoseidonRounds3;

impl Rounds for PoseidonRounds3 {
	const FULL_ROUNDS: usize = 8;
	const PARTIAL_ROUNDS: usize = 57;
	const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
	const WIDTH: usize = 3;
}

#[derive(Clone)]
pub struct TreeConfig<F: PrimeField>(PhantomData<F>);
impl<F: PrimeField> MerkleConfig for TreeConfig<F> {
	type H = PoseidonCRH3<F>;
	type LeafH = LeafCRH<F>;

	const HEIGHT: u8 = 30;
}

pub fn setup_tree<F: PrimeField>(leaves: &[F], params: &PoseidonParameters<F>) -> Tree<F> {
	let inner_params = Rc::new(params.clone());
	let mt = Tree::new_sequential(inner_params, Rc::new(()), leaves).unwrap();
	mt
}

pub fn setup_tree_and_create_path<F: PrimeField>(
	leaves: &[F],
	index: u64,
	params: &PoseidonParameters<F>,
) -> (Tree<F>, Path<TreeConfig<F>>) {
	// Making the merkle tree
	let mt = setup_tree(leaves, params);
	// Getting the proof path
	let path = mt.generate_membership_proof(index);
	(mt, path)
}

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

pub fn verify_groth16<E: PairingEngine>(
	vk: &VerifyingKey<E>,
	public_inputs: &Vec<E::Fr>,
	proof: &Proof<E>,
) -> bool {
	let res = Groth16::<E>::verify(vk, public_inputs, proof);
	match res {
		Ok(is_valid) => is_valid,
		Err(e) => panic!("{}", e),
	}
}
