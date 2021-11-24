use std::marker::PhantomData;

use crate::{
	arbitrary::vanchor_data::VAnchorArbitraryData,
	circuit::vanchor::VAnchorCircuit,
	keypair::vanchor::Keypair,
	leaf::vanchor::{Private as LeafPrivate, Public as LeafPublic, VAnchorLeaf},
	merkle_tree::{Config, Node, Path, SparseMerkleTree},
	poseidon::{constraints::CRHGadget, sbox::PoseidonSbox, Rounds, CRH},
	set::membership::{Private as SetMembershipPrivate, SetMembership},
	setup::common::*,
};
use ark_crypto_primitives::{CRHGadget, CRH as CRHTrait};
use blake2::crypto_mac::Key;
use paste::paste;

use ark_ff::{PrimeField, ToBytes};
use ark_std::{
	rand::{CryptoRng, Rng, RngCore},
	vec::Vec,
};

pub type PoseidonCRH_x5_5<F> = CRH<F, PoseidonRounds_x5_5>;
pub type PoseidonCRH_x5_5Gadget<F> = CRHGadget<F, PoseidonRounds_x5_5>;

pub struct VAnchorProverSetup<
	F: PrimeField,
	H2: CRHTrait,
	H3: CRHTrait,
	H4: CRHTrait,
	H5: CRHTrait,
	P: Config,
	const K: usize,
	const M: usize,
	const INS: usize,
	const OUTS: usize,
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

impl<
		F: PrimeField,
		H2: CRHTrait,
		H4: CRHTrait,
		H5: CRHTrait,
		P: Config,
		// Tree height
		const K: usize,
		// Set size
		const M: usize,
		// Number of input transactions
		const INS: usize,
		// Numer of output transactions
		const OUTS: usize,
	> VAnchorProverSetup<F, H2, H3, H4, H5, P, K, M, INS, OUTS>
{
	pub fn new_key_pairs(&self, private_keys: &[F]) -> (Vec<Keypair<F, H2>>, Vec<H2::Output>) {
		let mut keypairs = Vec::new();
		let mut pub_keys = Vec::new();
		for _ in 0..OUTS {
			let kp = Self::new_key_pair(private_keys[i]);
			keypairs.push(kp);
			pub_keys.push(kp.public_key(self.h2_params))
		}
		(keypairs, pub_keys)
	}

	pub fn new_key_pair(private_key: F) -> Keypair<F, H2> {
		let kp = Keypair::new(private_key);
		(keypairs, pub_keys)
	}

	fn new_input_leaves(
		&self,
		chain_ids: &[F],
		amounts: &[F],
		blindings: &[F],
		keypairs: &[Keypair<F, H2>],
	) -> (
		Vec<LeafPrivate<F>>,
		Vec<LeafPublic<F>>,
		Vec<H5::Output>,
		Vec<H4::Output>,
	) {
		self.new_n_leaves(chain_ids, amounts, blindings, keypairs, INS);
	}

	fn new_output_leaves(
		&self,
		chain_ids: &[F],
		amounts: &[F],
		blindings: &[F],
		keypairs: &[Keypair<F, H2>],
	) -> (
		Vec<LeafPrivate<F>>,
		Vec<LeafPublic<F>>,
		Vec<H5::Output>,
		Vec<H4::Output>,
	) {
		self.new_n_leaves(chain_ids, amounts, blindings, keypairs, OUTS);
	}

	fn new_n_leaves(
		&self,
		chain_ids: &[F],
		amounts: &[F],
		blindings: &[F],
		keypairs: &[Keypair<F, H2>],
		n: usize,
	) -> (
		Vec<LeafPrivate<F>>,
		Vec<LeafPublic<F>>,
		Vec<H5::Output>,
		Vec<H4::Output>,
	) {
		let mut private = Vec::new();
		let mut public = Vec::new();
		let mut leaves = Vec::new();
		let mut nullifiers = Vec::new();
		for i in 0..n {
			let (pv, pb, leaf, nullifier) =
				self.new_leaf(chain_ids[i], amounts[i], blindings[i], keypairs[i]);
			private.push(pv);
			public.push(pb);
			leaves.push(leaf);
			nullifiers.push(nullifier);
		}
		(private, public, leaves, nullifiers)
	}

	pub fn new_leaf(
		&self,
		chain_id: F,
		amount: F,
		blinding: F,
		keypair: &Keypair<F, H2>,
	) -> (LeafPrivate<F>, LeafPublic<F>, H5::Output, H4::Output) {
		let leaf_private = LeafPrivate::new(amount, blinding);
		let leaf_public = LeafPublic::new(chain_id);

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
			self.h4_params,
		)
		.unwrap();

		(leaf_private, leaf_public, leaf, nullifier)
	}

	pub fn new_arbitrary_data(ext_data: F) -> VAnchorArbitraryData<F> {
		VAnchorArbitraryData::new(ext_data)
	}

	pub fn new_tree(&self, leaves: &[F]) -> SparseMerkleTree<P> {
		let inner_params = Rc::new(self.h3_params);
		let mt = SparseMerkleTree::new_sequential(inner_params, Rc::new(()), leaves).unwrap();
		mt
	}

	pub fn new_tree_with_paths(
		&self,
		leaves: &[F],
		indices: &[u64],
	) -> (SparseMerkleTree<F>, Vec<Path<P, K>>) {
		// Making the merkle tree
		let mt = self.setup_tree(leaves);
		// Getting the proof paths
		let mut paths = Vec::new();
		for i in indices {
			let path = mt.generate_membership_proof(i);
			paths.push(path);
		}
		(mt, paths)
	}

	pub fn new_set(root: &F, roots: &[F; M]) -> SetMembershipPrivate<F, M> {
		SetMembership::generate_secrets(root, roots).unwrap()
	}

	pub fn setup_circuit<R: Rng>(
		self,
		rng: &R,
	) -> (
		VAnchorCircuit<
			F,
			H2,
			CRHGadget<H2, F>,
			H4,
			CRHGadget<H4, F>,
			H5,
			CRHGadget<H5, F>,
			C,
			CRHGadget<C::LeafH, F>,
			CRHGadget<C::H, F>,
			K,
			INS,
			OUTS,
			M,
		>,
		Vec<F>,
	) {
		let in_chain_ids: Vec<F> = (0..INS).iter().map(|_| F::rand(rng)).collect();
		// TODO: set proper input amounts
		let in_amounts: Vec<F> = (0..INS).iter().map(|_| F::rand(rng)).collect();
		let in_blindings: Vec<F> = (0..INS).iter().map(|_| F::rand(rng)).collect();
		let in_private_keys: Vec<F> = (0..INS).iter().map(|_| F::rand(rng)).collect();

		let out_chain_ids: Vec<F> = (0..OUTS).iter().map(|_| F::rand(rng)).collect();
		let out_amounts: Vec<F> = (0..OUTS).iter().map(|_| F::rand(rng)).collect();
		let out_blindings: Vec<F> = (0..OUTS).iter().map(|_| F::rand(rng)).collect();
		let out_private_keys: Vec<F> = (0..OUTS).iter().map(|_| F::rand(rng)).collect();

		let public_amount = F::from(5);
		let ext_data = F::rand(rng);
		let indicies: Vec<F> = (0..INS).iter().map(|x| F::from(x as u64)).collect();
		let mut root_set = [F::rand(rng); M];

		let arbitrary = self.new_arbitrary_data(ext_data);
		let (in_keypairs, _) = self.new_key_pairs(private_keys);
		let (_, out_public_keys) = self.new_key_pairs(private_keys);

		let (in_leaf_private, in_leaf_public, leaves, nullifier_hashes) =
			self.new_input_leaves(chain_ids, amounts, blindings, in_keypairs);
		let (out_leaf_private, out_leaf_public, out_commitments, _) = self.new_output_leaves(rng);

		let (tree, paths) = self.setup_tree_and_create_paths(leaves, indices);
		let root = tree.root();
		root_set[0] = root;

		let (in_set_private) = self.new_set(root, root_set);

		VAnchorCircuit::new(
			public_amount,
			ext_data_hash,
			in_leaf_private,
			in_keypairs,
			in_leaf_public,
			in_set_private,
			root_set,
			self.h2_params,
			self.h4_params,
			self.h5_params,
			paths,
			indices,
			nullifier_hashes,
			out_commitments,
			out_leaf_private,
			out_leaf_public,
			out_public_keys,
		)
	}
}

// For backwards compatability
// TODO: remove later
pub fn setup_vanchor_arbitrary_data(ext_data: F) -> VAnchorArbitraryData<F> {
	VAnchorArbitraryData::new(ext_data)
}
