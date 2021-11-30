use std::marker::PhantomData;

use crate::circuit::vanchor::VAnchorCircuit;
use ark_crypto_primitives::{CRHGadget, CRH as CRHTrait};
use ark_ff::{to_bytes, PrimeField, ToBytes};
use ark_std::{self, rc::Rc};
use arkworks_gadgets::{
	arbitrary::vanchor_data::VAnchorArbitraryData,
	keypair::vanchor::Keypair,
	leaf::vanchor::{Private as LeafPrivate, Public as LeafPublic, VAnchorLeaf},
	merkle_tree::{Config, Path, SparseMerkleTree},
	set::membership::{Private as SetMembershipPrivate, SetMembership},
};

use ark_std::{rand::Rng, vec::Vec};

pub struct VAnchorProverSetup<
	F: PrimeField,
	H: CRHTrait,
	HG: CRHGadget<H, F>,
	LHGT: CRHGadget<P::LeafH, F>,
	HGT: CRHGadget<P::H, F>,
	P: Config,
	const K: usize,
	const M: usize,
	const INS: usize,
	const OUTS: usize,
> {
	h2_params: H::Parameters,
	h4_params: H::Parameters,
	h5_params: H::Parameters,
	leaf_params: <P::LeafH as CRHTrait>::Parameters,
	inner_params: <P::H as CRHTrait>::Parameters,
	_field: PhantomData<F>,
	_h: PhantomData<H>,
	_hg: PhantomData<HG>,
	_lhgt: PhantomData<LHGT>,
	_hgt: PhantomData<HGT>,
	_p: PhantomData<P>,
}

impl<
		F: PrimeField,
		H: CRHTrait,
		HG: CRHGadget<H, F>,
		LHGT: CRHGadget<P::LeafH, F>,
		HGT: CRHGadget<P::H, F>,
		P: Config,
		// Tree height
		const K: usize,
		// Set size
		const M: usize,
		// Number of input transactions
		const INS: usize,
		// Numer of output transactions
		const OUTS: usize,
	> VAnchorProverSetup<F, H, HG, LHGT, HGT, P, K, M, INS, OUTS>
{
	pub fn new_key_pairs(&self, private_keys: &[F]) -> (Vec<Keypair<F, H>>, Vec<H::Output>) {
		let mut keypairs = Vec::new();
		let mut pub_keys = Vec::new();
		for i in 0..OUTS {
			let (kp, pub_key) = self.new_key_pair(private_keys[i]);
			keypairs.push(kp);
			pub_keys.push(pub_key);
		}
		(keypairs, pub_keys)
	}

	pub fn new_key_pair(&self, private_key: F) -> (Keypair<F, H>, H::Output) {
		let kp = Keypair::new(private_key);
		let pub_key = kp.public_key(&self.h2_params).unwrap();
		(kp, pub_key)
	}

	fn new_input_leaves(
		&self,
		chain_ids: Vec<F>,
		amounts: Vec<F>,
		blindings: Vec<F>,
		indices: &[F],
		keypairs: &[Keypair<F, H>],
	) -> (
		Vec<LeafPrivate<F>>,
		Vec<LeafPublic<F>>,
		Vec<H::Output>,
		Vec<H::Output>,
	) {
		self.new_n_leaves(chain_ids, amounts, blindings, indices, keypairs, INS)
	}

	fn new_output_leaves(
		&self,
		chain_ids: Vec<F>,
		amounts: Vec<F>,
		blindings: Vec<F>,
		indices: &[F],
		keypairs: &[Keypair<F, H>],
	) -> (
		Vec<LeafPrivate<F>>,
		Vec<LeafPublic<F>>,
		Vec<H::Output>,
		Vec<H::Output>,
	) {
		self.new_n_leaves(chain_ids, amounts, blindings, indices, keypairs, OUTS)
	}

	fn new_n_leaves(
		&self,
		chain_ids: Vec<F>,
		amounts: Vec<F>,
		blindings: Vec<F>,
		indices: &[F],
		keypairs: &[Keypair<F, H>],
		n: usize,
	) -> (
		Vec<LeafPrivate<F>>,
		Vec<LeafPublic<F>>,
		Vec<H::Output>,
		Vec<H::Output>,
	) {
		let mut private = Vec::new();
		let mut public = Vec::new();
		let mut leaves = Vec::new();
		let mut nullifiers = Vec::new();
		for i in 0..n {
			let (pv, pb, leaf, nullifier) = self.new_leaf(
				chain_ids[i],
				amounts[i],
				blindings[i],
				&indices[i],
				&keypairs[i],
			);
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
		index: &F,
		keypair: &Keypair<F, H>,
	) -> (LeafPrivate<F>, LeafPublic<F>, H::Output, H::Output) {
		let leaf_private = LeafPrivate::new(amount, blinding);
		let leaf_public = LeafPublic::new(chain_id);

		let public_key = keypair.public_key(&self.h2_params).unwrap();
		let leaf = VAnchorLeaf::<F, H>::create_leaf(
			&leaf_private,
			&leaf_public,
			&public_key,
			&self.h5_params,
		)
		.unwrap();

		let nullifier = VAnchorLeaf::<F, H>::create_nullifier(
			&keypair.private_key,
			&leaf,
			&self.h4_params,
			index,
		)
		.unwrap();

		(leaf_private, leaf_public, leaf, nullifier)
	}

	pub fn new_arbitrary_data(ext_data: F) -> VAnchorArbitraryData<F> {
		VAnchorArbitraryData::new(ext_data)
	}

	pub fn new_tree<L: Default + ToBytes + Clone>(&self, leaves: &[L]) -> SparseMerkleTree<P> {
		let inner_params = Rc::new(self.inner_params.clone());
		let leaf_params = Rc::new(self.leaf_params.clone());
		let mt = SparseMerkleTree::new_sequential(inner_params, leaf_params, leaves).unwrap();
		mt
	}

	pub fn new_paths<L: Default + ToBytes + Clone>(
		&self,
		leaves: &[L],
		indices: &[u64],
	) -> Vec<Path<P, K>> {
		// Making the merkle tree
		let mt = self.new_tree(leaves);
		// Getting the proof paths
		let mut paths = Vec::new();
		for i in indices {
			let path = mt.generate_membership_proof(*i);
			paths.push(path);
		}
		paths
	}

	pub fn new_set(root: &F, roots: &[F; M]) -> SetMembershipPrivate<F, M> {
		SetMembership::generate_secrets(root, roots).unwrap()
	}

	/* pub fn setup_circuit<R: Rng>(
		self,
		rng: &mut R,
	) -> (
		VAnchorCircuit<F, H, HG, P, LHGT, HGT, K, INS, OUTS, M>,
		Vec<F>,
	) {
		let in_chain_ids: Vec<F> = (0..INS).into_iter().map(|_| F::rand(rng)).collect();
		// TODO: set proper input amounts
		let in_amounts: Vec<F> = (0..INS).into_iter().map(|_| F::rand(rng)).collect();
		let in_blindings: Vec<F> = (0..INS).into_iter().map(|_| F::rand(rng)).collect();
		let in_private_keys: Vec<F> = (0..INS).into_iter().map(|_| F::rand(rng)).collect();

		let out_chain_ids: Vec<F> = (0..OUTS).into_iter().map(|_| F::rand(rng)).collect();
		// TODO: set proper output amounts
		let out_amounts: Vec<F> = (0..OUTS).into_iter().map(|_| F::rand(rng)).collect();
		let out_blindings: Vec<F> = (0..OUTS).into_iter().map(|_| F::rand(rng)).collect();
		let out_public_keys: Vec<F> = (0..OUTS).into_iter().map(|_| F::rand(rng)).collect();

		let public_amount = F::from(5 as u32);
		let ext_data = F::rand(rng);
		let indices: Vec<u64> = (0..INS).into_iter().map(|x| x as u64).collect();
		let indices_f: Vec<F> = (0..INS).into_iter().map(|x| F::from(x as u64)).collect();

		let arbitrary = Self::new_arbitrary_data(ext_data);
		let (in_keypairs, _) = self.new_key_pairs(&in_private_keys);

		let (in_leaf_private, in_leaf_public, in_leaves, in_nullifier_hashes) = self
			.new_input_leaves(
				in_chain_ids,
				in_amounts,
				in_blindings,
				&indices_f,
				&in_keypairs,
			);
		let (out_leaf_private, out_leaf_public, out_commitments, _) = self.new_output_leaves(
			out_chain_ids,
			out_amounts,
			out_blindings,
			&indices_f,
			&in_keypairs,
		);

		let paths = self.new_paths(&in_leaves, &indices);

		let mut root_set = [F::zero(); M];
		for (i, path) in paths.iter().enumerate() {
			let root = path.root_hash(&in_leaves[i]).unwrap();
			root_set[i] = F::from_le_bytes_mod_order(&to_bytes![root].unwrap());
		}

		let mut in_set_privates = Vec::new();
		for root in root_set {
			let in_set_private = Self::new_set(&root, &root_set);
			in_set_privates.push(in_set_private);
		}

		let in_leaf_public = in_leaf_public[0].clone();

		let in_nullifier_hashes_f: Vec<F> = in_nullifier_hashes
			.iter()
			.map(|x| F::from_be_bytes_mod_order(&to_bytes![x].unwrap()))
			.collect();

		let out_commitments_f: Vec<F> = out_commitments
			.iter()
			.map(|x| F::from_be_bytes_mod_order(&to_bytes![x].unwrap()))
			.collect();

		let mut public_inputs = Vec::new();
		public_inputs.push(in_leaf_public.chain_id);
		public_inputs.push(public_amount);
		public_inputs.extend(root_set);
		public_inputs.extend(in_nullifier_hashes_f);
		public_inputs.extend(out_commitments_f);
		public_inputs.push(ext_data);

		(
			VAnchorCircuit::new(
				public_amount,
				arbitrary,
				in_leaf_private,
				in_keypairs,
				in_leaf_public,
				in_set_privates,
				root_set,
				self.h2_params,
				self.h4_params,
				self.h5_params,
				paths,
				indices_f,
				in_nullifier_hashes,
				out_commitments,
				out_leaf_private,
				out_leaf_public,
				out_public_keys,
			),
			public_inputs,
		)
	} */
}

// For backwards compatability
// TODO: remove later
pub fn setup_vanchor_arbitrary_data<F: PrimeField>(ext_data: F) -> VAnchorArbitraryData<F> {
	VAnchorArbitraryData::new(ext_data)
}
