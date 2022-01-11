use super::{is_left_child, is_root, left_child, parent, right_child, sibling, tree_height};
use crate::poseidon::field_hasher::FieldHasher;
use ark_crypto_primitives::Error;
use ark_ff::PrimeField;
use ark_std::collections::BTreeMap;
use std::{collections::BTreeSet, marker::PhantomData};

// Path
#[derive(Clone)]
pub struct Path<F: PrimeField, H: FieldHasher<F>, const N: usize> {
	pub(crate) path: [(F, F); N],
	_marker: PhantomData<H>, // Do we need to include this as part of the path?
}

impl<F: PrimeField, H: FieldHasher<F>, const N: usize> Path<F, H, N> {
	/// Takes in an expected `root_hash` and raw input data (i.e. private
	/// inputs) for a leaf and checks that the leaf belongs to a tree having the
	/// expected hash.
	pub fn check_membership(&self, root_hash: &F, leaf: &F, hasher: &H) -> Result<bool, Error> {
		let root = self.calculate_root(leaf, hasher)?;
		Ok(root == *root_hash)
	}

	/// Assumes leaf is raw input, i.e. private inputs whose hash is stored
	/// at leaf level
	pub fn calculate_root(&self, leaf: &F, hasher: &H) -> Result<F, Error> {
		let claimed_leaf_hash = hasher.hash(&[*leaf])?;
		if claimed_leaf_hash != self.path[0].0 && claimed_leaf_hash != self.path[0].1 {
			panic!("Leaf is not on path");
		}

		let mut prev = claimed_leaf_hash;
		// Check levels between leaf level and root
		for &(ref left_hash, ref right_hash) in &self.path {
			if &prev != left_hash && &prev != right_hash {
				panic!("Path nodes are not consistent");
			}
			prev = hasher.hash_two(left_hash, right_hash)?;
		}

		Ok(prev)
	}

	/// Given leaf raw input data determine what the index of this leaf must be
	/// in the Merkle tree it belongs to.  Before doing so check that the leaf
	/// does indeed belong to a tree with the given `root_hash`
	pub fn get_index(&self, root_hash: &F, leaf: &F, hasher: &H) -> Result<F, Error> {
		if !self.check_membership(root_hash, leaf, hasher)? {
			panic!("Leaf is not in the path");
		}

		let mut prev = hasher.hash(&[*leaf])?;
		let mut index = F::zero();
		let mut twopower = F::one();
		// Check levels between leaf level and root
		for &(ref left_hash, ref right_hash) in &self.path {
			// Check if the previous hash is for a left node or right node
			if &prev != left_hash {
				index += twopower;
			}
			twopower = twopower + twopower;
			prev = hasher.hash_two(left_hash, right_hash)?;
		}

		Ok(index)
	}
}

// Merkle sparse tree
// We wanted the "default" or "empty" leaf to be specified as a constant in
// the struct's trait bounds but arrays are not allowed as constants.  Instead
// all constructor functions take in a default/empty leaf argument.  
pub struct SparseMerkleTree<F: PrimeField, H: FieldHasher<F>, const N: usize> {
	/// data of the tree
	pub tree: BTreeMap<u64, F>,
	empty_hashes: [F; N],
	_marker: PhantomData<H>,
}

impl<F: PrimeField, H: FieldHasher<F>, const N: usize> SparseMerkleTree<F, H, N> {
	/// Takes a collection of raw leaf data, hashes each one, inserts
	/// these hashes at leaf level, and propagates the changes up the tree to
	/// the root.
	pub fn insert_batch(&mut self, leaves: &BTreeMap<u32, F>, hasher: &H) -> Result<(), Error> {
		let last_level_index: u64 = (1u64 << self.empty_hashes.len()) - 1;

		let mut level_idxs: BTreeSet<u64> = BTreeSet::new();
		for (i, leaf) in leaves {
			let true_index = last_level_index + (*i as u64);
			let leaf_hash = hasher.hash(&[*leaf])?;
			self.tree.insert(true_index, leaf_hash);
			level_idxs.insert(parent(true_index).unwrap());
		}

		for level in 0..self.empty_hashes.len() {
			let mut new_idxs: BTreeSet<u64> = BTreeSet::new();
			for i in level_idxs {
				let left_index = left_child(i);
				let right_index = right_child(i);

				let empty_hash = self.empty_hashes[level].clone();
				let left = self.tree.get(&left_index).unwrap_or(&empty_hash);
				let right = self.tree.get(&right_index).unwrap_or(&empty_hash);
				#[allow(mutable_borrow_reservation_conflict)]
				self.tree.insert(i, hasher.hash_two(left, right)?);

				let parent = match parent(i) {
					Some(i) => i,
					None => break,
				};
				new_idxs.insert(parent);
			}
			level_idxs = new_idxs;
		}

		Ok(())
	}

	pub fn new(leaves: &BTreeMap<u32, F>, hasher: &H, empty_leaf: [u8; 32]) -> Result<Self, Error> {
		// Ensure the tree can hold this many leaves
		let last_level_size = leaves.len().next_power_of_two();
		let tree_size = 2 * last_level_size - 1;
		let tree_height = tree_height(tree_size as u64);
		assert!(tree_height <= N as u32);

		// Initialize the merkle tree
		let tree: BTreeMap<u64, F> = BTreeMap::new();
		let empty_hashes = gen_empty_hashes(hasher, empty_leaf)?;

		let mut smt = SparseMerkleTree::<F, H, N> {
			tree,
			empty_hashes,
			_marker: PhantomData,
		};
		smt.insert_batch(leaves, hasher)?;

		Ok(smt)
	}

	pub fn new_sequential(leaves: &[F], hasher: &H, empty_leaf: [u8; 32]) -> Result<Self, Error> {
		let pairs: BTreeMap<u32, F> = leaves
			.iter()
			.enumerate()
			.map(|(i, l)| (i as u32, l.clone()))
			.collect();
		let smt = Self::new(&pairs, hasher, empty_leaf)?;

		Ok(smt)
	}

	pub fn root(&self) -> F {
		self.tree.get(&0).cloned().unwrap()
	}

	/// Give the path leading from the leaf at `index` up to the root.  This is
	/// a "proof" in the sense of "valid path in a Merkle tree", not a ZK
	/// argument.
	pub fn generate_membership_proof(&self, index: u64) -> Path<F, H, N> {
		let mut path = [(F::zero(), F::zero()); N];

		let tree_index = convert_index_to_last_level(index, N);

		// Iterate from the leaf up to the root, storing all intermediate hash values.
		let mut current_node = tree_index;
		let mut level = 0;
		while !is_root(current_node) {
			let sibling_node = sibling(current_node).unwrap();

			let empty_hash = &self.empty_hashes[level];

			let current = self
				.tree
				.get(&current_node)
				.cloned()
				.unwrap_or_else(|| empty_hash.clone());
			let sibling = self
				.tree
				.get(&sibling_node)
				.cloned()
				.unwrap_or_else(|| empty_hash.clone());

			if is_left_child(current_node) {
				path[level] = (current, sibling);
			} else {
				path[level] = (sibling, current);
			}
			current_node = parent(current_node).unwrap();
			level += 1;
		}

		Path {
			path,
			_marker: PhantomData,
		}
	}
}

pub fn gen_empty_hashes<F: PrimeField, H: FieldHasher<F>, const N: usize>(
	hasher: &H,
	default_leaf: [u8; 32],
) -> Result<[F; N], Error> {
	let mut empty_hashes = [F::zero(); N];

	let mut empty_hash = hasher.hash(&[F::from_le_bytes_mod_order(&default_leaf)])?;
	empty_hashes[0] = empty_hash;

	for i in 1..N {
		empty_hash = hasher.hash_two(&empty_hash, &empty_hash)?;
		empty_hashes[i] = empty_hash;
	}

	Ok(empty_hashes)
}

fn convert_index_to_last_level(index: u64, height: usize) -> u64 {
	index + (1u64 << height) - 1
}

#[cfg(test)]
mod test {
	use super::{gen_empty_hashes, SparseMerkleTree};
	use crate::poseidon::field_hasher::{FieldHasher, Poseidon};
	use ark_bls12_381::Fq;
	use ark_ff::{PrimeField, UniformRand};
	use ark_std::{collections::BTreeMap, test_rng};
	use arkworks_utils::utils::common::{setup_params_x5_3, Curve};

	type BLSHash = Poseidon<Fq>;

	//helper to change leaves array to BTreeMap and then create SMT
	fn create_merkle_tree<F: PrimeField, H: FieldHasher<F>, const N: usize>(
		hasher: H,
		leaves: &[F],
		default_leaf: &[u8; 32],
	) -> SparseMerkleTree<F, H, N> {
		let pairs: BTreeMap<u32, F> = leaves
			.iter()
			.enumerate()
			.map(|(i, l)| (i as u32, *l))
			.collect();
		let smt = SparseMerkleTree::<F, H, N>::new(&pairs, &hasher, *default_leaf).unwrap();

		smt
	}

	#[test]
	fn should_create_tree_poseidon() {
		let rng = &mut test_rng();
		let curve = Curve::Bls381;

		let params = setup_params_x5_3(curve);
		let poseidon = Poseidon::new(params);
		let default_leaf = [0u8; 32];
		let leaves = [Fq::rand(rng), Fq::rand(rng), Fq::rand(rng)];
		const HEIGHT: usize = 3;
		let smt =
			create_merkle_tree::<Fq, BLSHash, HEIGHT>(poseidon.clone(), &leaves, &default_leaf);

		let root = smt.root();

		let empty_hashes =
			gen_empty_hashes::<Fq, BLSHash, HEIGHT>(&poseidon, default_leaf).unwrap();
		let hash1 = poseidon.hash(&leaves[0..1]).unwrap();
		let hash2 = poseidon.hash(&leaves[1..2]).unwrap();
		let hash3 = poseidon.hash(&leaves[2..3]).unwrap();

		let hash12 = poseidon.hash_two(&hash1, &hash2).unwrap();
		let hash34 = poseidon.hash_two(&hash3, &empty_hashes[0]).unwrap();

		let hash1234 = poseidon.hash_two(&hash12, &hash34).unwrap();
		let calc_root = poseidon.hash_two(&hash1234, &empty_hashes[2]).unwrap();

		assert_eq!(root, calc_root);
	}

	#[test]
	fn should_generate_and_validate_proof_poseidon() {
		let rng = &mut test_rng();
		let curve = Curve::Bls381;

		let params = setup_params_x5_3(curve);
		let poseidon = Poseidon::new(params);
		let default_leaf = [0u8; 32];
		let leaves = [Fq::rand(rng), Fq::rand(rng), Fq::rand(rng)];
		const HEIGHT: usize = 3;
		let smt =
			create_merkle_tree::<Fq, BLSHash, HEIGHT>(poseidon.clone(), &leaves, &default_leaf);

		let proof = smt.generate_membership_proof(0);

		let res = proof
			.check_membership(&smt.root(), &leaves[0], &poseidon)
			.unwrap();
		assert!(res);
	}

	#[test]
	fn should_find_the_index_poseidon() {
		let rng = &mut test_rng();
		let curve = Curve::Bls381;

		let params = setup_params_x5_3(curve);
		let poseidon = Poseidon::new(params);
		let default_leaf = [0u8; 32];
		let leaves = [Fq::rand(rng), Fq::rand(rng), Fq::rand(rng)];
		const HEIGHT: usize = 3;
		let smt =
			create_merkle_tree::<Fq, BLSHash, HEIGHT>(poseidon.clone(), &leaves, &default_leaf);

		let index = 2;

		let proof = smt.generate_membership_proof(index);

		let res = proof
			.get_index(&smt.root(), &leaves[index as usize], &poseidon)
			.unwrap();
		let desired_res = Fq::from(index);

		assert_eq!(res, desired_res);
	}
}
