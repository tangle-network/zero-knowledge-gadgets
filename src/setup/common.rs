use ark_ec::PairingEngine;
use ark_std::marker::PhantomData;
use crate::{
	identity::{constraints::CRHGadget as IdentityCRHGadget, CRH as IdentityCRH},
	merkle_tree::{Config as MerkleConfig, Path, SparseMerkleTree},
	poseidon::{constraints::CRHGadget, sbox::PoseidonSbox, PoseidonParameters, Rounds, CRH},
	utils::{
		// exp 5
		get_mds_poseidon_bls381_x5_3, get_mds_poseidon_bls381_x5_5,
		get_mds_poseidon_bn254_x5_3, get_mds_poseidon_bn254_x5_5,
		get_rounds_poseidon_bls381_x5_3, get_rounds_poseidon_bls381_x5_5,
		get_rounds_poseidon_bn254_x5_3, get_rounds_poseidon_bn254_x5_5,
		// exp 17
		get_mds_poseidon_bls381_x17_3, get_mds_poseidon_bls381_x17_5,
		get_mds_poseidon_bn254_x17_3, get_mds_poseidon_bn254_x17_5,
		get_rounds_poseidon_bls381_x17_3, get_rounds_poseidon_bls381_x17_5,
		get_rounds_poseidon_bn254_x17_3, get_rounds_poseidon_bn254_x17_5,
	},
};
use ark_crypto_primitives::SNARK;
use ark_ff::fields::PrimeField;
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_std::{rc::Rc, vec::Vec};


#[derive(Default, Clone)]
pub struct PoseidonRounds_x5_5;

impl Rounds for PoseidonRounds_x5_5 {
	const FULL_ROUNDS: usize = 8;
	const PARTIAL_ROUNDS: usize = 60;
	const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
	const WIDTH: usize = 5;
}

#[derive(Default, Clone)]
pub struct PoseidonRounds_x5_3;

impl Rounds for PoseidonRounds_x5_3 {
	const FULL_ROUNDS: usize = 8;
	const PARTIAL_ROUNDS: usize = 57;
	const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
	const WIDTH: usize = 3;
}

#[derive(Default, Clone)]
pub struct PoseidonRounds_x17_5;

impl Rounds for PoseidonRounds_x17_5 {
	const FULL_ROUNDS: usize = 8;
	const PARTIAL_ROUNDS: usize = 35;
	const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(17);
	const WIDTH: usize = 5;
}

#[derive(Default, Clone)]
pub struct PoseidonRounds_x17_3;

impl Rounds for PoseidonRounds_x17_3 {
	const FULL_ROUNDS: usize = 8;
	const PARTIAL_ROUNDS: usize = 33;
	const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(17);
	const WIDTH: usize = 3;
}

pub type PoseidonCRH_x5_3<F> = CRH<F, PoseidonRounds_x5_3>;
pub type PoseidonCRH_x5_3Gadget<F> = CRHGadget<F, PoseidonRounds_x5_3>;

pub type PoseidonCRH_x5_5<F> = CRH<F, PoseidonRounds_x5_5>;
pub type PoseidonCRH_x5_5Gadget<F> = CRHGadget<F, PoseidonRounds_x5_5>;

pub type PoseidonCRH_x17_3<F> = CRH<F, PoseidonRounds_x17_3>;
pub type PoseidonCRH_x17_3Gadget<F> = CRHGadget<F, PoseidonRounds_x17_3>;

pub type PoseidonCRH_x17_5<F> = CRH<F, PoseidonRounds_x17_5>;
pub type PoseidonCRH_x17_5Gadget<F> = CRHGadget<F, PoseidonRounds_x17_5>;


pub type LeafCRH<F> = IdentityCRH<F>;
pub type LeafCRHGadget<F>= IdentityCRHGadget<F>;
pub type Tree_x5<F> = SparseMerkleTree<TreeConfig_x5<F>>;
pub type Tree_x17<F> = SparseMerkleTree<TreeConfig_x17<F>>;


#[derive(Copy, Clone)]
pub enum Curve {
	Bls381,
	Bn254,
}

#[derive(Clone)]
pub struct TreeConfig_x5<F: PrimeField>(PhantomData<F>);
impl<F: PrimeField> MerkleConfig for TreeConfig_x5<F> {
	type H = PoseidonCRH_x5_3<F>;
	type LeafH = LeafCRH<F>;

	const HEIGHT: u8 = 30;
}

#[derive(Clone)]
pub struct TreeConfig_x17<F: PrimeField>(PhantomData<F>);
impl<F: PrimeField> MerkleConfig for TreeConfig_x17<F> {
	type H = PoseidonCRH_x17_3<F>;
	type LeafH = LeafCRH<F>;

	const HEIGHT: u8 = 30;
}

pub fn setup_tree_x5<F: PrimeField>(leaves: &[F], params: &PoseidonParameters<F>) -> Tree_x5<F> {
	let inner_params = Rc::new(params.clone());
	let mt = Tree_x5::new_sequential(inner_params, Rc::new(()), leaves).unwrap();
	mt
}

pub fn setup_tree_and_create_path_x5<F: PrimeField>(
	leaves: &[F],
	index: u64,
	params: &PoseidonParameters<F>,
) -> (Tree_x5<F>, Path<TreeConfig_x5<F>>) {
	// Making the merkle tree
	let mt = setup_tree_x5(leaves, params);
	// Getting the proof path
	let path = mt.generate_membership_proof(index);
	(mt, path)
}

pub fn setup_tree_x17<F: PrimeField>(leaves: &[F], params: &PoseidonParameters<F>) -> Tree_x17<F> {
	let inner_params = Rc::new(params.clone());
	let mt = Tree_x17::new_sequential(inner_params, Rc::new(()), leaves).unwrap();
	mt
}

pub fn setup_tree_and_create_path_x17<F: PrimeField>(
	leaves: &[F],
	index: u64,
	params: &PoseidonParameters<F>,
) -> (Tree_x17<F>, Path<TreeConfig_x17<F>>) {
	// Making the merkle tree
	let mt = setup_tree_x17(leaves, params);
	// Getting the proof path
	let path = mt.generate_membership_proof(index);
	(mt, path)
}

pub fn setup_params_x5_3<F: PrimeField>(curve: Curve) -> PoseidonParameters<F> {
	// Making params for poseidon in merkle tree
	match curve {
		Curve::Bls381 => {
			let rounds3 = get_rounds_poseidon_bls381_x5_3::<F>();
			let mds3 = get_mds_poseidon_bls381_x5_3::<F>();
			let params3 = PoseidonParameters::<F>::new(rounds3, mds3);
			params3
		},
		Curve::Bn254 => {
			let rounds3 = get_rounds_poseidon_bn254_x5_3::<F>();
			let mds3 = get_mds_poseidon_bn254_x5_3::<F>();
			let params3 = PoseidonParameters::<F>::new(rounds3, mds3);
			params3
		},
	}
}

pub fn setup_params_x5_5<F: PrimeField>(curve: Curve) -> PoseidonParameters<F> {
	// Making params for poseidon in merkle tree
	match curve {
		Curve::Bls381 => {
			let rounds5 = get_rounds_poseidon_bls381_x5_5::<F>();
			let mds5 = get_mds_poseidon_bls381_x5_5::<F>();
			let params5 = PoseidonParameters::<F>::new(rounds5, mds5);
			params5
		},
		Curve::Bn254 => {
			let rounds5 = get_rounds_poseidon_bn254_x5_5::<F>();
			let mds5 = get_mds_poseidon_bn254_x5_5::<F>();
			let params5 = PoseidonParameters::<F>::new(rounds5, mds5);
			params5
		},
	}
}

pub fn setup_params_x17_3<F: PrimeField>(curve: Curve) -> PoseidonParameters<F> {
	// Making params for poseidon in merkle tree
	match curve {
		Curve::Bls381 => {
			let rounds3 = get_rounds_poseidon_bls381_x17_3::<F>();
			let mds3 = get_mds_poseidon_bls381_x17_3::<F>();
			let params3 = PoseidonParameters::<F>::new(rounds3, mds3);
			params3
		},
		Curve::Bn254 => {
			let rounds3 = get_rounds_poseidon_bn254_x17_3::<F>();
			let mds3 = get_mds_poseidon_bn254_x17_3::<F>();
			let params3 = PoseidonParameters::<F>::new(rounds3, mds3);
			params3
		},
	}
}

pub fn setup_params_x17_5<F: PrimeField>(curve: Curve) -> PoseidonParameters<F> {
	// Making params for poseidon in merkle tree
	match curve {
		Curve::Bls381 => {
			let rounds5 = get_rounds_poseidon_bls381_x17_5::<F>();
			let mds5 = get_mds_poseidon_bls381_x17_5::<F>();
			let params5 = PoseidonParameters::<F>::new(rounds5, mds5);
			params5
		},
		Curve::Bn254 => {
			let rounds5 = get_rounds_poseidon_bn254_x17_5::<F>();
			let mds5 = get_mds_poseidon_bn254_x17_5::<F>();
			let params5 = PoseidonParameters::<F>::new(rounds5, mds5);
			params5
		},
	}
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
