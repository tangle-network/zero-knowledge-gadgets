use crate::{
	identity::{constraints::CRHGadget as IdentityCRHGadget, CRH as IdentityCRH},
	merkle_tree::{Config as MerkleConfig, Path, SparseMerkleTree},
	mimc::{MiMCParameters, Rounds as MiMCRounds},
	poseidon::{
		circom::{constraints::CircomCRHGadget, CircomCRH},
		constraints::CRHGadget,
		sbox::PoseidonSbox,
		PoseidonParameters, Rounds, CRH,
	},
	utils::{
		get_mds_poseidon_bls381_x17_3, get_mds_poseidon_bls381_x17_5, get_mds_poseidon_bls381_x3_3,
		get_mds_poseidon_bls381_x3_5, get_mds_poseidon_bls381_x5_3, get_mds_poseidon_bls381_x5_5,
		get_mds_poseidon_bn254_x17_3, get_mds_poseidon_bn254_x17_5, get_mds_poseidon_bn254_x3_3,
		get_mds_poseidon_bn254_x3_5, get_mds_poseidon_bn254_x5_2, get_mds_poseidon_bn254_x5_3,
		get_mds_poseidon_bn254_x5_4, get_mds_poseidon_bn254_x5_5,
		get_mds_poseidon_circom_bn254_x5_3, get_mds_poseidon_circom_bn254_x5_5,
		get_rounds_poseidon_bls381_x17_3, get_rounds_poseidon_bls381_x17_5,
		get_rounds_poseidon_bls381_x3_3, get_rounds_poseidon_bls381_x3_5,
		get_rounds_poseidon_bls381_x5_3, get_rounds_poseidon_bls381_x5_5,
		get_rounds_poseidon_bn254_x17_3, get_rounds_poseidon_bn254_x17_5,
		get_rounds_poseidon_bn254_x3_3, get_rounds_poseidon_bn254_x3_5,
		get_rounds_poseidon_bn254_x5_2, get_rounds_poseidon_bn254_x5_3,
		get_rounds_poseidon_bn254_x5_4, get_rounds_poseidon_bn254_x5_5,
		get_rounds_poseidon_circom_bn254_x5_3, get_rounds_poseidon_circom_bn254_x5_5,
	},
};
use ark_crypto_primitives::SNARK;
use ark_ec::PairingEngine;
use ark_ff::fields::PrimeField;
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_std::{marker::PhantomData, rc::Rc};
use paste::paste;

#[derive(Default, Clone)]
pub struct PoseidonRounds_x3_3;

impl Rounds for PoseidonRounds_x3_3 {
	const FULL_ROUNDS: usize = 8;
	const PARTIAL_ROUNDS: usize = 84;
	const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(3);
	const WIDTH: usize = 3;
}

#[derive(Default, Clone)]
pub struct PoseidonRounds_x3_5;

impl Rounds for PoseidonRounds_x3_5 {
	const FULL_ROUNDS: usize = 8;
	const PARTIAL_ROUNDS: usize = 85;
	const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(3);
	const WIDTH: usize = 5;
}

#[derive(Default, Clone)]
pub struct PoseidonRounds_x5_5;

impl Rounds for PoseidonRounds_x5_5 {
	const FULL_ROUNDS: usize = 8;
	const PARTIAL_ROUNDS: usize = 60;
	const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
	const WIDTH: usize = 5;
}

#[derive(Default, Clone)]
pub struct PoseidonRounds_x5_4;

impl Rounds for PoseidonRounds_x5_4 {
	const FULL_ROUNDS: usize = 8;
	const PARTIAL_ROUNDS: usize = 56;
	const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
	const WIDTH: usize = 4;
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
pub struct PoseidonRounds_x5_2;

impl Rounds for PoseidonRounds_x5_2 {
	const FULL_ROUNDS: usize = 8;
	const PARTIAL_ROUNDS: usize = 56;
	const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
	const WIDTH: usize = 2;
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

pub type PoseidonCRH_x3_3<F> = CRH<F, PoseidonRounds_x3_3>;
pub type PoseidonCRH_x3_3Gadget<F> = CRHGadget<F, PoseidonRounds_x3_3>;

pub type PoseidonCRH_x3_5<F> = CRH<F, PoseidonRounds_x3_5>;
pub type PoseidonCRH_x3_5Gadget<F> = CRHGadget<F, PoseidonRounds_x3_5>;

pub type PoseidonCRH_x5_3<F> = CRH<F, PoseidonRounds_x5_3>;
pub type PoseidonCRH_x5_3Gadget<F> = CRHGadget<F, PoseidonRounds_x5_3>;

pub type PoseidonCRH_x5_5<F> = CRH<F, PoseidonRounds_x5_5>;
pub type PoseidonCRH_x5_5Gadget<F> = CRHGadget<F, PoseidonRounds_x5_5>;

pub type PoseidonCRH_x5_4<F> = CRH<F, PoseidonRounds_x5_4>;
pub type PoseidonCRH_x5_4Gadget<F> = CRHGadget<F, PoseidonRounds_x5_4>;

pub type PoseidonCircomCRH_x5_3<F> = CircomCRH<F, PoseidonRounds_x5_3>;
pub type PoseidonCircomCRH_x5_3Gadget<F> = CircomCRHGadget<F, PoseidonRounds_x5_3>;

pub type PoseidonCRH_x5_2<F> = CRH<F, PoseidonRounds_x5_2>;
pub type PoseidonCRH_x5_2Gadget<F> = CRHGadget<F, PoseidonRounds_x5_2>;

pub type PoseidonCircomCRH_x5_5<F> = CircomCRH<F, PoseidonRounds_x5_5>;
pub type PoseidonCircomCRH_x5_5Gadget<F> = CircomCRHGadget<F, PoseidonRounds_x5_5>;

pub type PoseidonCRH_x17_3<F> = CRH<F, PoseidonRounds_x17_3>;
pub type PoseidonCRH_x17_3Gadget<F> = CRHGadget<F, PoseidonRounds_x17_3>;

pub type PoseidonCRH_x17_5<F> = CRH<F, PoseidonRounds_x17_5>;
pub type PoseidonCRH_x17_5Gadget<F> = CRHGadget<F, PoseidonRounds_x17_5>;

#[derive(Default, Clone)]
pub struct MiMCRounds_220_3;

impl crate::mimc::Rounds for MiMCRounds_220_3 {
	const ROUNDS: usize = 220;
	const WIDTH: usize = 3;
}

pub type MiMCCRH_220<F> = crate::mimc::CRH<F, MiMCRounds_220_3>;
pub type MiMCCRH_220Gadget<F> = crate::mimc::constraints::CRHGadget<F, MiMCRounds_220_3>;

pub type LeafCRH<F> = IdentityCRH<F>;
pub type LeafCRHGadget<F> = IdentityCRHGadget<F>;
pub type Tree_x5<F> = SparseMerkleTree<TreeConfig_x5<F>>;
pub type Tree_Circomx5<F> = SparseMerkleTree<TreeConfig_Circomx5<F>>;
pub type Tree_x17<F> = SparseMerkleTree<TreeConfig_x17<F>>;
pub type Tree_MiMC220<F> = SparseMerkleTree<TreeConfig_MiMC220<F>>;

#[derive(Copy, Clone)]
pub enum Curve {
	Bls381,
	Bn254,
}

#[derive(Clone, PartialEq)]
pub struct TreeConfig_x5<F: PrimeField>(PhantomData<F>);
impl<F: PrimeField> MerkleConfig for TreeConfig_x5<F> {
	type H = PoseidonCRH_x5_3<F>;
	type LeafH = LeafCRH<F>;

	const HEIGHT: u8 = 30;
}

#[derive(Clone)]
pub struct TreeConfig_Circomx5<F: PrimeField>(PhantomData<F>);
impl<F: PrimeField> MerkleConfig for TreeConfig_Circomx5<F> {
	type H = PoseidonCircomCRH_x5_3<F>;
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

#[derive(Clone)]
pub struct TreeConfig_MiMC220<F: PrimeField>(PhantomData<F>);
impl<F: PrimeField> MerkleConfig for TreeConfig_MiMC220<F> {
	type H = MiMCCRH_220<F>;
	type LeafH = LeafCRH<F>;

	const HEIGHT: u8 = 30;
}

// Generate tree setup functions
// 	1. `setup_<tree>`
//	2. `setup_tree_and_create_path_<tree>`

macro_rules! impl_setup_tree {
	(
		tree: $tree_ty:ident, // tree type
		config: $tc_ty:ident, // tree configuration type
		params: $param_ty:ident // parameters type
	) => {
		paste! {
			pub fn [<setup_ $tree_ty:lower>]<F: PrimeField>(
				leaves: &[F],
				params: &$param_ty<F>,
			) -> $tree_ty<F> {
				let inner_params = Rc::new(params.clone());
				let mt = $tree_ty::new_sequential(inner_params, Rc::new(()), leaves).unwrap();
				mt
			}

			pub fn [<setup_tree_and_create_path_ $tree_ty:lower>]<F: PrimeField, const N: usize>(
				leaves: &[F],
				index: u64,
				params: &$param_ty<F>,
			) -> ($tree_ty<F>, Path<$tc_ty<F>, N>) {
				// Making the merkle tree
				let mt = [<setup_ $tree_ty:lower>](leaves, params);
				// Getting the proof path
				let path = mt.generate_membership_proof(index);
				(mt, path)
			}
		}
	};
}

impl_setup_tree!(
	tree: Tree_x5,
	config: TreeConfig_x5,
	params: PoseidonParameters
);
impl_setup_tree!(
	tree: Tree_x17,
	config: TreeConfig_x17,
	params: PoseidonParameters
);
impl_setup_tree!(
	tree: Tree_Circomx5,
	config: TreeConfig_Circomx5,
	params: PoseidonParameters
);
impl_setup_tree!(
	tree: Tree_MiMC220,
	config: TreeConfig_MiMC220,
	params: MiMCParameters
);

pub fn setup_params_x3_3<F: PrimeField>(curve: Curve) -> PoseidonParameters<F> {
	// Making params for poseidon in merkle tree
	match curve {
		Curve::Bls381 => {
			let rounds3 = get_rounds_poseidon_bls381_x3_3::<F>();
			let mds3 = get_mds_poseidon_bls381_x3_3::<F>();
			PoseidonParameters::<F>::new(rounds3, mds3)
		}
		Curve::Bn254 => {
			let rounds3 = get_rounds_poseidon_bn254_x3_3::<F>();
			let mds3 = get_mds_poseidon_bn254_x3_3::<F>();
			PoseidonParameters::<F>::new(rounds3, mds3)
		}
	}
}
pub fn setup_params_x3_5<F: PrimeField>(curve: Curve) -> PoseidonParameters<F> {
	// Making params for poseidon in merkle tree
	match curve {
		Curve::Bls381 => {
			let rounds5 = get_rounds_poseidon_bls381_x3_5::<F>();
			let mds5 = get_mds_poseidon_bls381_x3_5::<F>();
			PoseidonParameters::<F>::new(rounds5, mds5)
		}
		Curve::Bn254 => {
			let rounds3 = get_rounds_poseidon_bn254_x3_5::<F>();
			let mds3 = get_mds_poseidon_bn254_x3_5::<F>();
			PoseidonParameters::<F>::new(rounds3, mds3)
		}
	}
}

pub fn setup_params_x5_3<F: PrimeField>(curve: Curve) -> PoseidonParameters<F> {
	// Making params for poseidon in merkle tree
	match curve {
		Curve::Bls381 => {
			let rounds3 = get_rounds_poseidon_bls381_x5_3::<F>();
			let mds3 = get_mds_poseidon_bls381_x5_3::<F>();
			PoseidonParameters::<F>::new(rounds3, mds3)
		}
		Curve::Bn254 => {
			let rounds3 = get_rounds_poseidon_bn254_x5_3::<F>();
			let mds3 = get_mds_poseidon_bn254_x5_3::<F>();
			PoseidonParameters::<F>::new(rounds3, mds3)
		}
	}
}

pub fn setup_params_x5_2<F: PrimeField>(curve: Curve) -> PoseidonParameters<F> {
	// Making params for poseidon in merkle tree
	match curve {
		Curve::Bls381 => {
			unimplemented!("we don't hava parameters for bls381 curve yet");
		}
		Curve::Bn254 => {
			let rounds2 = get_rounds_poseidon_bn254_x5_2::<F>();
			let mds2 = get_mds_poseidon_bn254_x5_2::<F>();
			PoseidonParameters::<F>::new(rounds2, mds2)
		}
	}
}

pub fn setup_circom_params_x5_3<F: PrimeField>(curve: Curve) -> PoseidonParameters<F> {
	// Making params for poseidon in merkle tree
	match curve {
		Curve::Bls381 => {
			unimplemented!("we don't hava parameters for bls381 curve yet");
		}
		Curve::Bn254 => {
			let rounds3 = get_rounds_poseidon_circom_bn254_x5_3::<F>();
			let mds3 = get_mds_poseidon_circom_bn254_x5_3::<F>();
			PoseidonParameters::<F>::new(rounds3, mds3)
		}
	}
}

pub fn setup_params_x5_4<F: PrimeField>(curve: Curve) -> PoseidonParameters<F> {
	// Making params for poseidon in merkle tree
	match curve {
		Curve::Bls381 => {
			unimplemented!("we don't hava parameters for bls381 curve yet");
		}
		Curve::Bn254 => {
			let rounds4 = get_rounds_poseidon_bn254_x5_4::<F>();
			let mds4 = get_mds_poseidon_bn254_x5_4::<F>();
			PoseidonParameters::<F>::new(rounds4, mds4)
		}
	}
}

pub fn setup_params_x5_5<F: PrimeField>(curve: Curve) -> PoseidonParameters<F> {
	// Making params for poseidon in merkle tree
	match curve {
		Curve::Bls381 => {
			let rounds5 = get_rounds_poseidon_bls381_x5_5::<F>();
			let mds5 = get_mds_poseidon_bls381_x5_5::<F>();
			PoseidonParameters::<F>::new(rounds5, mds5)
		}
		Curve::Bn254 => {
			let rounds5 = get_rounds_poseidon_bn254_x5_5::<F>();
			let mds5 = get_mds_poseidon_bn254_x5_5::<F>();
			PoseidonParameters::<F>::new(rounds5, mds5)
		}
	}
}

pub fn setup_circom_params_x5_5<F: PrimeField>(curve: Curve) -> PoseidonParameters<F> {
	// Making params for poseidon in merkle tree
	match curve {
		Curve::Bls381 => {
			unimplemented!("we don't hava parameters for bls381 curve yet");
		}
		Curve::Bn254 => {
			let rounds5 = get_rounds_poseidon_circom_bn254_x5_5::<F>();
			let mds5 = get_mds_poseidon_circom_bn254_x5_5::<F>();
			PoseidonParameters::<F>::new(rounds5, mds5)
		}
	}
}

pub fn setup_params_x17_3<F: PrimeField>(curve: Curve) -> PoseidonParameters<F> {
	// Making params for poseidon in merkle tree
	match curve {
		Curve::Bls381 => {
			let rounds3 = get_rounds_poseidon_bls381_x17_3::<F>();
			let mds3 = get_mds_poseidon_bls381_x17_3::<F>();
			PoseidonParameters::<F>::new(rounds3, mds3)
		}
		Curve::Bn254 => {
			let rounds3 = get_rounds_poseidon_bn254_x17_3::<F>();
			let mds3 = get_mds_poseidon_bn254_x17_3::<F>();
			PoseidonParameters::<F>::new(rounds3, mds3)
		}
	}
}

pub fn setup_params_x17_5<F: PrimeField>(curve: Curve) -> PoseidonParameters<F> {
	// Making params for poseidon in merkle tree
	match curve {
		Curve::Bls381 => {
			let rounds5 = get_rounds_poseidon_bls381_x17_5::<F>();
			let mds5 = get_mds_poseidon_bls381_x17_5::<F>();
			PoseidonParameters::<F>::new(rounds5, mds5)
		}
		Curve::Bn254 => {
			let rounds5 = get_rounds_poseidon_bn254_x17_5::<F>();
			let mds5 = get_mds_poseidon_bn254_x17_5::<F>();
			PoseidonParameters::<F>::new(rounds5, mds5)
		}
	}
}

pub fn setup_mimc_220<F: PrimeField>(curve: Curve) -> crate::mimc::MiMCParameters<F> {
	match curve {
		Curve::Bls381 => {
			unimplemented!();
		}
		Curve::Bn254 => crate::mimc::MiMCParameters::<F>::new(
			F::zero(),
			MiMCRounds_220_3::ROUNDS,
			MiMCRounds_220_3::WIDTH,
			MiMCRounds_220_3::WIDTH,
			crate::utils::get_rounds_mimc_220(),
		),
	}
}

pub fn verify_groth16<E: PairingEngine>(
	vk: &VerifyingKey<E>,
	public_inputs: &[E::Fr],
	proof: &Proof<E>,
) -> bool {
	let res = Groth16::<E>::verify(vk, public_inputs, proof);
	match res {
		Ok(is_valid) => is_valid,
		Err(e) => panic!("{}", e),
	}
}
