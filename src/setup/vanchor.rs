use std::marker::PhantomData;

use crate::{
	arbitrary::vanchor_data::VAnchorArbitraryData,
	keypair::vanchor::Keypair,
	leaf::vanchor::{Private as LeafPrivate, Public as LeafPublic, VAnchorLeaf},
	merkle_tree::{Config, Node, Path, SparseMerkleTree},
	poseidon::{constraints::CRHGadget, sbox::PoseidonSbox, Rounds, CRH},
	setup::common::*,
};
use ark_crypto_primitives::CRH as CRHTrait;
use blake2::crypto_mac::Key;
use paste::paste;

use ark_ff::{PrimeField, ToBytes};
use ark_std::{
	rand::{CryptoRng, Rng, RngCore},
	vec::Vec,
};

pub type PoseidonCRH_x5_5<F> = CRH<F, PoseidonRounds_x5_5>;
pub type PoseidonCRH_x5_5Gadget<F> = CRHGadget<F, PoseidonRounds_x5_5>;

pub struct VAnchorPoverSetup<
	F: PrimeField,
	H2: CRHTrait,
	H3: CRHTrait,
	H4: CRHTrait,
	H5: CRHTrait,
	P: Config,
	const N: usize,
> {
	h2_params: H2::Parameters,
	h3_params: H3::Parameters,
	h4_params: H4::Parameters,
	h5_params: H5::Parameters,
	_field: PhantomData<F>,
	_h2: PhantomData<H2>,
	_h3: PhantomData<H3>,
	_h4: PhantomData<H4>,
	_h5: PhantomData<H5>,
	_p: PhantomData<P>,
}

impl<F: PrimeField, H2: CRHTrait, H4: CRHTrait, H5: CRHTrait>
	VAnchorArbitraryData<F, H2, H3, H4, H5>
{
	pub fn generate_key_pair<R: Rng>(rng: &mut R) -> Keypair<F, H2> {
		let private_key = F::rand(rng);
		Keypair::new(private_key)
	}

	pub fn generate_leaf<R: Rng>(
		&self,
		keypair: &Keypair<F, H2>,
		rng: &mut R,
	) -> (LeafPrivate<F>, LeafPublic<F>, H5::Output) {
		let leaf_private = LeafPrivate::generate(rng);
		let leaf_public = LeafPublic::new(F::zero());

		let public_key = keypair.public_key(self.h2_params).unwrap();
		let leaf = VAnchorLeaf::<F, H4, H5>::create_leaf(
			&leaf_private,
			&keypair.public,
			&leaf_public,
			self.h5_params,
		)
		.unwrap();

		let nullifier = VAnchorLeaf::<F, H4, H5>::create_nullifier(
			&leaf_private,
			&public_key,
			&leaf_public,
			self.h5_params,
		)
		.unwrap();

		(leaf_private, leaf_public, leaf, nullifier)
	}

	pub fn setup_arbitrary_data(ext_data: F) -> VAnchorArbitraryData<F> {
		VAnchorArbitraryData::new(ext_data)
	}

	pub fn setup_tree(&self, leaves: &[F]) -> SparseMerkleTree<P> {
		let inner_params = Rc::new(self.params);
		let mt = SparseMerkleTree::new_sequential(inner_params, Rc::new(()), leaves).unwrap();
		mt
	}

	pub fn setup_tree_and_create_path(
		&self,
		leaves: &[F],
		index: u64,
	) -> (SparseMerkleTree<F>, Path<P, N>) {
		// Making the merkle tree
		let mt = self.setup_tree(leaves);
		// Getting the proof path
		let path = mt.generate_membership_proof(index);
		(mt, path)
	}
}
