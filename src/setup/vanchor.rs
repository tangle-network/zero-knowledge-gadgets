use crate::{
	arbitrary::vanchor_data::VAnchorArbitraryData,
	leaf::vanchor::{Private as LeafPrivate, Public as LeafPublic, VAnchorLeaf},
	merkle_tree::{Config, Node, Path},
	poseidon::{constraints::CRHGadget, sbox::PoseidonSbox, CRH},
	setup::common::*,
};
use ark_crypto_primitives::CRH as CRHTrait;
use paste::paste;

use ark_ff::{PrimeField, ToBytes};
use ark_std::{
	rand::{CryptoRng, Rng, RngCore},
	vec::Vec,
};

pub type PoseidonCRH_x5_5<F> = CRH<F>;
pub type PoseidonCRH_x5_5Gadget<F> = CRHGadget<F>;

pub fn generate_vanchor_leaf_rng<
	F: PrimeField,
	H2: CRHTrait,
	H4: CRHTrait,
	H5: CRHTrait,
	R: Rng,
>(
	chain_id: F,
	public_key: H2::Output,
	h_w5: &H5::Parameters,
	rng: &mut R,
) -> (LeafPrivate<F>, LeafPublic<F>, H5::Output) {
	let leaf_private = LeafPrivate::generate(rng);
	let leaf_public = LeafPublic::new(chain_id);
	let leaf_hash =
		VAnchorLeaf::<F, H4, H5>::create_leaf(&leaf_private, &public_key, &leaf_public, h_w5)
			.unwrap();

	(leaf_private, leaf_public, leaf_hash)
}

pub fn setup_vanchor_arbitrary_data<F: PrimeField>(ext_data: F) -> VAnchorArbitraryData<F> {
	VAnchorArbitraryData::new(ext_data)
}

// pub struct VAnchorPoverSetup<F: PrimeField, H2: CRHTrait, H4: CRHTrait, H5:
// CRHTrait, R: Rng> {}
