// This file is part of Webb and was adapted from Arkworks.
//
// Copyright (C) 2021 Webb Technologies Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! This file provides a native implementation of the Sparse Merkle tree data
//! structure.
//!
//! # Overview
//! A Sparse Merkle tree is a type of Merkle tree, but it is much easier to
//! prove non-membership in a sparse Merkle tree than in an arbitrary Merkle
//! tree. For an explanation of sparse Merkle trees, see:
//! `<https://medium.com/@kelvinfichter/whats-a-sparse-merkle-tree-acda70aeb837>`
//!
//! In this file we define the `Path` and `SparseMerkleTree` structs.
//! These depend on your choice of a prime field F, a field hasher over F
//! (any hash function that maps F^2 to F will do, e.g. the poseidon hash
//! function of width 3 where an input of zero is used for padding), and the
//! height N of the sparse Merkle tree.
//!
//! The path corresponding to a given leaf node is stored as an N-tuple of pairs
//! of field elements. Each pair consists of a node lying on the path from the
//! leaf node to the root, and that node's sibling.  For example, suppose
//! ```text
//!           a
//!         /   \
//!        b     c
//!       / \   / \
//!      d   e f   g
//! ```
//! is our Sparse Merkle tree, and `a` through `g` are field elements stored at
//! the nodes. Then the merkle proof path `e-b-a` from leaf `e` to root `a` is
//! stored as `[(d,e), (b,c)]`
//!
//! # Usage
//! ```rust
//! //! Create a new Sparse Merkle Tree with 32 random leaves
//!
//! // Import dependencies
//! use ark_bn254::Fr;
//! use ark_ff::{BigInteger, PrimeField};
//! use ark_std::{collections::BTreeMap, test_rng, UniformRand};
//! use arkworks_native_gadgets::{
//! 	merkle_tree::SparseMerkleTree,
//! 	poseidon::{sbox::PoseidonSbox, Poseidon, PoseidonParameters},
//! };
//! use arkworks_utils::{
//! 	bytes_matrix_to_f, bytes_vec_to_f, parse_vec, poseidon_params::setup_poseidon_params, Curve,
//! };
//!
//! // Setup the Poseidon parameters and hasher for
//! // Curve BN254, a width of 3, and an exponentiation of 5.
//! let pos_data = setup_poseidon_params(Curve::Bn254, 5, 3).unwrap();
//!
//! let mds_f = bytes_matrix_to_f(&pos_data.mds);
//! let rounds_f = bytes_vec_to_f(&pos_data.rounds);
//!
//! let pos = PoseidonParameters {
//! 	mds_matrix: mds_f,
//! 	round_keys: rounds_f,
//! 	full_rounds: pos_data.full_rounds,
//! 	partial_rounds: pos_data.partial_rounds,
//! 	sbox: PoseidonSbox(pos_data.exp),
//! 	width: pos_data.width,
//! };
//!
//! let poseidon = Poseidon::new(pos);
//!
//! // Create a random number generator for generating 32 leaves.
//! let rng = &mut test_rng();
//! let leaves: Vec<Fr> = vec![Fr::rand(rng); 32];
//! let pairs: BTreeMap<u32, Fr> = leaves
//! 	.iter()
//! 	.enumerate()
//! 	.map(|(i, l)| (i as u32, *l))
//! 	.collect();
//!
//! // Create the tree with a default leaf of zero.
//! type SMT = SparseMerkleTree<Fr, Poseidon<Fr>, 30>;
//! let default_leaf = Fr::from(0u64).into_repr().to_bytes_le();
//! let smt = SMT::new(&pairs, &poseidon, &default_leaf).unwrap();
//! ```

use crate::poseidon::FieldHasher;
use ark_crypto_primitives::Error;
use ark_ff::PrimeField;
use ark_std::{
	borrow::ToOwned,
	collections::{BTreeMap, BTreeSet},
	marker::PhantomData,
};

/// Error enum for Sparse Merkle Tree.
#[derive(Debug)]
pub enum MerkleError {
	/// Thrown when the given leaf is not in the tree or the path.
	InvalidLeaf,
	/// Thrown when the merkle path is invalid.
	InvalidPathNodes,
}

impl core::fmt::Display for MerkleError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		let msg = match self {
			MerkleError::InvalidLeaf => "Invalid leaf".to_owned(),
			MerkleError::InvalidPathNodes => "Path nodes are not consistent".to_owned(),
		};
		write!(f, "{}", msg)
	}
}

impl ark_std::error::Error for MerkleError {}

/// The Path struct.
///
/// The path contains a sequence of sibling nodes that make up a merkle proof.
/// Each pair is used to identify whether an incremental merkle root
/// construction is valid at each intermediate step.
#[derive(Clone)]
pub struct Path<F: PrimeField, H: FieldHasher<F>, const N: usize> {
	/// The path represented as a sequence of sibling pairs.
	pub path: [(F, F); N],
	/// The phantom hasher type used to reconstruct the merkle root.
	pub marker: PhantomData<H>,
}

impl<F: PrimeField, H: FieldHasher<F>, const N: usize> Path<F, H, N> {
	/// Takes in an expected `root_hash` and leaf-level data (i.e. hashes of
	/// secrets) for a leaf and checks that the leaf belongs to a tree having
	/// the expected hash.
	pub fn check_membership(&self, root_hash: &F, leaf: &F, hasher: &H) -> Result<bool, Error> {
		let root = self.calculate_root(leaf, hasher)?;
		Ok(root == *root_hash)
	}

	/// Assumes leaf contains leaf-level data, i.e. hashes of secrets
	/// stored on leaf-level.
	pub fn calculate_root(&self, leaf: &F, hasher: &H) -> Result<F, Error> {
		if *leaf != self.path[0].0 && *leaf != self.path[0].1 {
			return Err(MerkleError::InvalidLeaf.into());
		}

		let mut prev = *leaf;
		// Check levels between leaf level and root
		for &(ref left_hash, ref right_hash) in &self.path {
			if &prev != left_hash && &prev != right_hash {
				return Err(MerkleError::InvalidPathNodes.into());
			}
			prev = hasher.hash_two(left_hash, right_hash)?;
		}

		Ok(prev)
	}

	/// Given leaf data determine what the index of this leaf must be
	/// in the Merkle tree it belongs to.  Before doing so check that the leaf
	/// does indeed belong to a tree with the given `root_hash`
	pub fn get_index(&self, root_hash: &F, leaf: &F, hasher: &H) -> Result<F, Error> {
		if !self.check_membership(root_hash, leaf, hasher)? {
			return Err(MerkleError::InvalidLeaf.into());
		}

		let mut prev = *leaf;
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

/// The Sparse Merkle Tree struct.
///
/// The Sparse Merkle Tree stores a set of leaves represented in a map and
/// a set of empty hashes that it uses to represent the sparse areas of the
/// tree.
pub struct SparseMerkleTree<F: PrimeField, H: FieldHasher<F>, const N: usize> {
	/// A map from leaf indices to leaf data stored as field elements.
	pub tree: BTreeMap<u64, F>,
	/// An array of default hashes hashed with themselves `N` times.
	empty_hashes: [F; N],
	/// The phantom hasher type used to build the merkle tree.
	marker: PhantomData<H>,
}

impl<F: PrimeField, H: FieldHasher<F>, const N: usize> SparseMerkleTree<F, H, N> {
	/// Takes a batch of field elements, inserts
	/// these hashes into the tree, and updates the merkle root.
	pub fn insert_batch(&mut self, leaves: &BTreeMap<u32, F>, hasher: &H) -> Result<(), Error> {
		let last_level_index: u64 = (1u64 << N) - 1;

		let mut level_idxs: BTreeSet<u64> = BTreeSet::new();
		for (i, leaf) in leaves {
			let true_index = last_level_index + (*i as u64);
			self.tree.insert(true_index, *leaf);
			level_idxs.insert(parent(true_index).unwrap());
		}

		for level in 0..N {
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

	/// Creates a new Sparse Merkle Tree from a map of indices to field
	/// elements.
	pub fn new(leaves: &BTreeMap<u32, F>, hasher: &H, empty_leaf: &[u8]) -> Result<Self, Error> {
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
			marker: PhantomData,
		};
		smt.insert_batch(leaves, hasher)?;

		Ok(smt)
	}

	/// Creates a new Sparse Merkle Tree from an array of field elements.
	pub fn new_sequential(leaves: &[F], hasher: &H, empty_leaf: &[u8]) -> Result<Self, Error> {
		let pairs: BTreeMap<u32, F> = leaves
			.iter()
			.enumerate()
			.map(|(i, l)| (i as u32, l.clone()))
			.collect();
		let smt = Self::new(&pairs, hasher, empty_leaf)?;

		Ok(smt)
	}

	/// Returns the Merkle tree root.
	pub fn root(&self) -> F {
		self.tree
			.get(&0)
			.cloned()
			.unwrap_or(*self.empty_hashes.last().unwrap())
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
			marker: PhantomData,
		}
	}
}

/// A function to generate empty hashes with a given `default_leaf`.
///
/// Given a `FieldHasher`, generate a list of `N` hashes consisting
/// of the `default_leaf` hashed with itself and repeated `N` times
/// with the intermediate results. These are used to initialize the
/// sparse portion of the Sparse Merkle Tree.
pub fn gen_empty_hashes<F: PrimeField, H: FieldHasher<F>, const N: usize>(
	hasher: &H,
	default_leaf: &[u8],
) -> Result<[F; N], Error> {
	let mut empty_hashes = [F::zero(); N];

	let mut empty_hash = F::from_le_bytes_mod_order(default_leaf);
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

/// Returns the log2 value of the given number.
#[inline]
fn log2(number: u64) -> u32 {
	ark_std::log2(number as usize)
}

/// Returns the height of the tree, given the size of the tree.
#[inline]
fn tree_height(tree_size: u64) -> u32 {
	log2(tree_size)
}

/// Returns true iff the index represents the root.
#[inline]
fn is_root(index: u64) -> bool {
	index == 0
}

/// Returns the index of the left child, given an index.
#[inline]
fn left_child(index: u64) -> u64 {
	2 * index + 1
}

/// Returns the index of the right child, given an index.
#[inline]
fn right_child(index: u64) -> u64 {
	2 * index + 2
}

/// Returns the index of the sibling, given an index.
#[inline]
fn sibling(index: u64) -> Option<u64> {
	if index == 0 {
		None
	} else if is_left_child(index) {
		Some(index + 1)
	} else {
		Some(index - 1)
	}
}

/// Returns true iff the given index represents a left child.
#[inline]
fn is_left_child(index: u64) -> bool {
	index % 2 == 1
}

/// Returns the index of the parent, given an index.
#[inline]
fn parent(index: u64) -> Option<u64> {
	if index > 0 {
		Some((index - 1) >> 1)
	} else {
		None
	}
}

#[cfg(test)]
mod test {
	use super::{gen_empty_hashes, SparseMerkleTree};
	use crate::poseidon::{test::setup_params, FieldHasher, Poseidon};
	use ark_ed_on_bls12_381::Fq;
	use ark_ff::{BigInteger, PrimeField, UniformRand};
	use ark_std::{collections::BTreeMap, test_rng};
	use arkworks_utils::{bytes_vec_to_f, parse_vec, Curve};

	type BLSHash = Poseidon<Fq>;
	use ark_bn254::Fr as Bn254Fr;

	//helper to change leaves array to BTreeMap and then create SMT
	fn create_merkle_tree<F: PrimeField, H: FieldHasher<F>, const N: usize>(
		hasher: H,
		leaves: &[F],
		default_leaf: &[u8],
	) -> SparseMerkleTree<F, H, N> {
		let pairs: BTreeMap<u32, F> = leaves
			.iter()
			.enumerate()
			.map(|(i, l)| (i as u32, *l))
			.collect();
		let smt = SparseMerkleTree::<F, H, N>::new(&pairs, &hasher, default_leaf).unwrap();

		smt
	}

	#[test]
	fn should_create_tree_poseidon() {
		let rng = &mut test_rng();
		let curve = Curve::Bls381;

		let params = setup_params(curve, 5, 3);
		let poseidon = Poseidon::new(params);
		let default_leaf = [0u8; 32];
		let leaves = [Fq::rand(rng), Fq::rand(rng), Fq::rand(rng)];
		const HEIGHT: usize = 3;
		let smt =
			create_merkle_tree::<Fq, BLSHash, HEIGHT>(poseidon.clone(), &leaves, &default_leaf);

		let root = smt.root();

		let empty_hashes =
			gen_empty_hashes::<Fq, BLSHash, HEIGHT>(&poseidon, &default_leaf).unwrap();
		let hash1 = leaves[0];
		let hash2 = leaves[1];
		let hash3 = leaves[2];

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

		let params = setup_params(curve, 5, 3);
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

		let params = setup_params(curve, 5, 3);
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

	#[test]
	fn compare_with_solidity_empty_hashes() {
		// These are taken from protocol-solidity/contracts/trees/MerkleTreePoseidon.sol
		let solidity_empty_hashes_hex = vec![
			"0x2fe54c60d3acabf3343a35b6eba15db4821b340f76e741e2249685ed4899af6c",
			"0x13e37f2d6cb86c78ccc1788607c2b199788c6bb0a615a21f2e7a8e88384222f8",
			"0x217126fa352c326896e8c2803eec8fd63ad50cf65edfef27a41a9e32dc622765",
			"0x0e28a61a9b3e91007d5a9e3ada18e1b24d6d230c618388ee5df34cacd7397eee",
			"0x27953447a6979839536badc5425ed15fadb0e292e9bc36f92f0aa5cfa5013587",
			"0x194191edbfb91d10f6a7afd315f33095410c7801c47175c2df6dc2cce0e3affc",
			"0x1733dece17d71190516dbaf1927936fa643dc7079fc0cc731de9d6845a47741f",
			"0x267855a7dc75db39d81d17f95d0a7aa572bf5ae19f4db0e84221d2b2ef999219",
			"0x1184e11836b4c36ad8238a340ecc0985eeba665327e33e9b0e3641027c27620d",
			"0x0702ab83a135d7f55350ab1bfaa90babd8fc1d2b3e6a7215381a7b2213d6c5ce",
			"0x2eecc0de814cfd8c57ce882babb2e30d1da56621aef7a47f3291cffeaec26ad7",
			"0x280bc02145c155d5833585b6c7b08501055157dd30ce005319621dc462d33b47",
			"0x045132221d1fa0a7f4aed8acd2cbec1e2189b7732ccb2ec272b9c60f0d5afc5b",
			"0x27f427ccbf58a44b1270abbe4eda6ba53bd6ac4d88cf1e00a13c4371ce71d366",
			"0x1617eaae5064f26e8f8a6493ae92bfded7fde71b65df1ca6d5dcec0df70b2cef",
			"0x20c6b400d0ea1b15435703c31c31ee63ad7ba5c8da66cec2796feacea575abca",
			"0x09589ddb438723f53a8e57bdada7c5f8ed67e8fece3889a73618732965645eec",
			"0x0064b6a738a5ff537db7b220f3394f0ecbd35bfd355c5425dc1166bf3236079b",
			"0x095de56281b1d5055e897c3574ff790d5ee81dbc5df784ad2d67795e557c9e9f",
			"0x11cf2e2887aa21963a6ec14289183efe4d4c60f14ecd3d6fe0beebdf855a9b63",
			"0x2b0f6fc0179fa65b6f73627c0e1e84c7374d2eaec44c9a48f2571393ea77bcbb",
			"0x16fdb637c2abf9c0f988dbf2fd64258c46fb6a273d537b2cf1603ea460b13279",
			"0x21bbd7e944f6124dad4c376df9cc12e7ca66e47dff703ff7cedb1a454edcf0ff",
			"0x2784f8220b1c963e468f590f137baaa1625b3b92a27ad9b6e84eb0d3454d9962",
			"0x16ace1a65b7534142f8cc1aad810b3d6a7a74ca905d9c275cb98ba57e509fc10",
			"0x2328068c6a8c24265124debd8fe10d3f29f0665ea725a65e3638f6192a96a013",
			"0x2ddb991be1f028022411b4c4d2c22043e5e751c120736f00adf54acab1c9ac14",
			"0x0113798410eaeb95056a464f70521eb58377c0155f2fe518a5594d38cc209cc0",
			"0x202d1ae61526f0d0d01ef80fb5d4055a7af45721024c2c24cffd6a3798f54d50",
			"0x23ab323453748129f2765f79615022f5bebd6f4096a796300aab049a60b0f187",
			"0x1f15585f8947e378bcf8bd918716799da909acdb944c57150b1eb4565fda8aa0",
			"0x1eb064b21055ac6a350cf41eb30e4ce2cb19680217df3a243617c2838185ad06",
		];
		let solidity_empty_hashes: Vec<Bn254Fr> =
			bytes_vec_to_f(&parse_vec(solidity_empty_hashes_hex).unwrap());

		// Generate again with this module's functions
		let curve = Curve::Bn254;
		let params = setup_params(curve, 5, 3);
		let poseidon = Poseidon::<Bn254Fr>::new(params.clone());

		let default_leaf_hex =
			vec!["0x2fe54c60d3acabf3343a35b6eba15db4821b340f76e741e2249685ed4899af6c"];
		let default_leaf_scalar: Vec<Bn254Fr> =
			bytes_vec_to_f(&parse_vec(default_leaf_hex).unwrap());
		let default_leaf_vec = default_leaf_scalar[0].into_repr().to_bytes_le();
		let empty_hashes =
			gen_empty_hashes::<Bn254Fr, _, 32usize>(&poseidon, &default_leaf_vec[..]).unwrap();

		assert_eq!(empty_hashes.to_vec(), solidity_empty_hashes);
	}
}
