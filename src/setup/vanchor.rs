use crate::{
	arbitrary::vanchor_data::VAnchorArbitraryData,
	leaf::vanchor::{Private as LeafPrivate, Public as LeafPublic, VAnchorLeaf},
	merkle_tree::{Config, Node, Path},
	poseidon::{constraints::CRHGadget, sbox::PoseidonSbox, Rounds, CRH},
	setup::common::*,
};
use ark_crypto_primitives::CRH as CRHTrait;
use paste::paste;

use ark_ff::{PrimeField, ToBytes};
use ark_std::{
	rand::{CryptoRng, Rng, RngCore},
	vec::Vec,
};

pub type PoseidonCRH_x5_5<F> = CRH<F, PoseidonRounds_x5_5>;
pub type PoseidonCRH_x5_5Gadget<F> = CRHGadget<F, PoseidonRounds_x5_5>;

pub fn generate_vanchor_leaf_rng<
	F: PrimeField,
	H2: CRHTrait,
	H4: CRHTrait,
	H5: CRHTrait,
	R: Rng,
>(
	chain_id: F,
	public_key: H2::Output,
	h_w2: &H2::Parameters,
	h_w5: &H5::Parameters,
	rng: &mut R,
) -> (LeafPrivate<F>, LeafPublic<F>, H5::Output) {
	let leaf_private = LeafPrivate::generate(rng);
	let leaf_public = LeafPublic::new(chain_id);
	let leaf_hash =
		VAnchorLeaf::<F, H2, H4, H5>::create_leaf(&leaf_private, &public_key, &leaf_public, h_w5)
			.unwrap();

	(leaf_private, leaf_public, leaf_hash)
}

pub fn setup_vanchor_arbitrary_data<F: PrimeField>(ext_data: F) -> VAnchorArbitraryData<F> {
	VAnchorArbitraryData::new(ext_data)
}

/*
// Generate code for leaf setup function: `setup_<leaf>`
macro_rules! impl_setup_bridge_leaf {
	(
		leaf: $leaf_ty:ident, // leaf type
		crh: $leaf_crh_ty:ident, // crh type
		params: $leaf_crh_param_ty:ident // crh params type
	) => {
		paste! {
			pub fn [<setup_ $leaf_ty:lower>]<R: Rng, F: PrimeField>(
				chain_id: F,
				params: &$leaf_crh_param_ty<F>,
				rng: &mut R,
			) -> (
				LeafPrivate<F>,
				LeafPublic<F>,
				<$leaf_ty<F> as LeafCreation<$leaf_crh_ty<F>>>::Leaf,
				<$leaf_ty<F> as LeafCreation<$leaf_crh_ty<F>>>::Nullifier,
			) {
				// Secret inputs for the leaf
				let leaf_private = $leaf_ty::generate_secrets(rng).unwrap();
				// Public inputs for the leaf
				let leaf_public = LeafPublic::new(chain_id);

				// Creating the leaf
				let leaf = $leaf_ty::create_leaf(&leaf_private, &leaf_public, params).unwrap();
				let nullifier_hash = $leaf_ty::create_nullifier_hash(&leaf_private, params).unwrap();
				(leaf_private, leaf_public, leaf, nullifier_hash)
			}
		}
	};
}

impl_setup_bridge_leaf!(
	leaf: Leaf_x5,
	crh: PoseidonCRH_x5_5,
	params: PoseidonParameters
);
impl_setup_bridge_leaf!(
	leaf: Leaf_Circomx5,
	crh: PoseidonCircomCRH_x5_5,
	params: PoseidonParameters
);
impl_setup_bridge_leaf!(
	leaf: Leaf_x17,
	crh: PoseidonCRH_x17_5,
	params: PoseidonParameters
);
*/
