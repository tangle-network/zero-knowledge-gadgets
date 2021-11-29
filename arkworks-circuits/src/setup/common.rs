use arkworks_gadgets::{
	identity::{constraints::CRHGadget as IdentityCRHGadget, CRH as IdentityCRH},
	merkle_tree::{Config as MerkleConfig, Path, SparseMerkleTree},
	poseidon::{constraints::CRHGadget, CRH},
};
use arkworks_utils::{mimc::MiMCParameters, poseidon::PoseidonParameters};

use ark_ff::fields::PrimeField;
use ark_std::{marker::PhantomData, rc::Rc};
use paste::paste;

pub type PoseidonCRH_x3_3<F> = CRH<F>;
pub type PoseidonCRH_x3_3Gadget<F> = CRHGadget<F>;

pub type PoseidonCRH_x3_5<F> = CRH<F>;
pub type PoseidonCRH_x3_5Gadget<F> = CRHGadget<F>;

pub type PoseidonCRH_x5_3<F> = CRH<F>;
pub type PoseidonCRH_x5_3Gadget<F> = CRHGadget<F>;

pub type PoseidonCRH_x5_5<F> = CRH<F>;
pub type PoseidonCRH_x5_5Gadget<F> = CRHGadget<F>;

pub type PoseidonCRH_x5_4<F> = CRH<F>;
pub type PoseidonCRH_x5_4Gadget<F> = CRHGadget<F>;

pub type PoseidonCircomCRH_x5_3<F> = CRH<F>;
pub type PoseidonCircomCRH_x5_3Gadget<F> = CRHGadget<F>;

pub type PoseidonCRH_x5_2<F> = CRH<F>;
pub type PoseidonCRH_x5_2Gadget<F> = CRHGadget<F>;

pub type PoseidonCircomCRH_x5_5<F> = CRH<F>;
pub type PoseidonCircomCRH_x5_5Gadget<F> = CRHGadget<F>;

pub type PoseidonCRH_x17_3<F> = CRH<F>;
pub type PoseidonCRH_x17_3Gadget<F> = CRHGadget<F>;

pub type PoseidonCRH_x17_5<F> = CRH<F>;
pub type PoseidonCRH_x17_5Gadget<F> = CRHGadget<F>;

#[derive(Default, Clone)]
pub struct MiMCRounds_220_3;

impl arkworks_gadgets::mimc::Rounds for MiMCRounds_220_3 {
	const ROUNDS: usize = 220;
	const WIDTH: usize = 3;
}

pub type MiMCCRH_220<F> = arkworks_gadgets::mimc::CRH<F, MiMCRounds_220_3>;
pub type MiMCCRH_220Gadget<F> = arkworks_gadgets::mimc::constraints::CRHGadget<F, MiMCRounds_220_3>;

pub type LeafCRH<F> = IdentityCRH<F>;
pub type LeafCRHGadget<F> = IdentityCRHGadget<F>;
pub type Tree_x5<F> = SparseMerkleTree<TreeConfig_x5<F>>;
pub type Tree_Circomx5<F> = SparseMerkleTree<TreeConfig_Circomx5<F>>;
pub type Tree_x17<F> = SparseMerkleTree<TreeConfig_x17<F>>;
pub type Tree_MiMC220<F> = SparseMerkleTree<TreeConfig_MiMC220<F>>;

#[derive(Clone, PartialEq)]
pub struct TreeConfig_x5<F: PrimeField>(PhantomData<F>);
impl<F: PrimeField> MerkleConfig for TreeConfig_x5<F> {
	type H = PoseidonCRH_x5_3<F>;
	type LeafH = LeafCRH<F>;

	const HEIGHT: u8 = 30;
}

#[derive(Clone, PartialEq)]
pub struct TreeConfig_Circomx5<F: PrimeField>(PhantomData<F>);
impl<F: PrimeField> MerkleConfig for TreeConfig_Circomx5<F> {
	type H = PoseidonCircomCRH_x5_3<F>;
	type LeafH = LeafCRH<F>;

	const HEIGHT: u8 = 30;
}

#[derive(Clone, PartialEq)]
pub struct TreeConfig_x17<F: PrimeField>(PhantomData<F>);
impl<F: PrimeField> MerkleConfig for TreeConfig_x17<F> {
	type H = PoseidonCRH_x17_3<F>;
	type LeafH = LeafCRH<F>;

	const HEIGHT: u8 = 30;
}

#[derive(Clone, PartialEq)]
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
