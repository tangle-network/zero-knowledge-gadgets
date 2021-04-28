use ark_ff::{to_bytes, ToBytes};
use ark_std::{
	collections::{BTreeMap, BTreeSet},
	fmt::Debug,
	format,
	string::ToString,
	vec::Vec,
};
use webb_crypto_primitives::{Error, FixedLengthCRH};

/// constraints for the Merkle sparse tree
// #[cfg(feature = "r1cs")]
// pub mod constraints;

/// configuration of a Merkle tree
pub trait Config {
	/// Tree height
	const HEIGHT: u64;
	/// The CRH
	type H: FixedLengthCRH;
}

type HOutput<P: Config> = <P::H as FixedLengthCRH>::Output;
type HParameters<P: Config> = <P::H as FixedLengthCRH>::Parameters;

/// Stores the hashes of a particular path (in order) from leaf to root.
/// Our path `is_left_child()` if the boolean in `path` is true.
#[derive(Clone, Debug)]
pub struct Path<P: Config> {
	pub(crate) path: Vec<(HOutput<P>, HOutput<P>)>,
}

/// A modifying proof, consisting of two Merkle tree paths
pub struct TwoPaths<P: Config> {
	pub(crate) old_path: Path<P>,
	pub(crate) new_path: Path<P>,
}

impl<P: Config> Path<P> {
	/// verify the lookup proof, just checking the membership
	pub fn verify<L: ToBytes>(
		&self,
		parameters: &HParameters<P>,
		root_hash: &HOutput<P>,
		leaf: &L,
	) -> Result<bool, Error> {
		if self.path.len() != (P::HEIGHT - 1) as usize {
			return Ok(false);
		}
		// Check that the given leaf matches the leaf in the membership proof.
		if !self.path.is_empty() {
			let claimed_leaf_hash = hash_leaf::<P::H, L>(parameters, leaf)?;

			if claimed_leaf_hash != self.path[0].0 && claimed_leaf_hash != self.path[0].1 {
				return Ok(false);
			}

			let mut prev = claimed_leaf_hash;
			// Check levels between leaf level and root.
			for &(ref left_hash, ref right_hash) in &self.path {
				// Check if the previous hash matches the correct current hash.
				if &prev != left_hash && &prev != right_hash {
					return Ok(false);
				}
				prev = hash_inner_node::<P::H>(parameters, left_hash, right_hash)?;
			}

			if root_hash != &prev {
				return Ok(false);
			}
			Ok(true)
		} else {
			Ok(false)
		}
	}

	/// verify the lookup proof, given the location
	pub fn verify_with_index<L: ToBytes>(
		&self,
		parameters: &HParameters<P>,
		root_hash: &HOutput<P>,
		leaf: &L,
		index: u64,
	) -> Result<bool, Error> {
		if self.path.len() != (P::HEIGHT - 1) as usize {
			return Ok(false);
		}
		// Check that the given leaf matches the leaf in the membership proof.
		let last_level_index: u64 = (1u64 << (P::HEIGHT - 1)) - 1;
		let tree_index: u64 = last_level_index + index;

		let mut index_from_path: u64 = last_level_index;
		let mut index_offset: u64 = 1;

		if !self.path.is_empty() {
			let claimed_leaf_hash = hash_leaf::<P::H, L>(parameters, leaf)?;

			if tree_index % 2 == 1 {
				if claimed_leaf_hash != self.path[0].0 {
					return Ok(false);
				}
			} else if claimed_leaf_hash != self.path[0].1 {
				return Ok(false);
			}

			let mut prev = claimed_leaf_hash;
			let mut prev_index = tree_index;
			// Check levels between leaf level and root.
			for &(ref left_hash, ref right_hash) in &self.path {
				// Check if the previous hash matches the correct current hash.
				if prev_index % 2 == 1 {
					if &prev != left_hash {
						return Ok(false);
					}
				} else {
					if &prev != right_hash {
						return Ok(false);
					}
					index_from_path += index_offset;
				}
				index_offset *= 2;
				prev_index = (prev_index - 1) / 2;
				prev = hash_inner_node::<P::H>(parameters, left_hash, right_hash)?;
			}

			if root_hash != &prev {
				return Ok(false);
			}

			if index_from_path != tree_index {
				return Ok(false);
			}

			Ok(true)
		} else {
			Ok(false)
		}
	}
}

impl<P: Config> TwoPaths<P> {
	/// verify the modifying proof
	pub fn verify<L: ToBytes>(
		&self,
		parameters: &HParameters<P>,
		old_root_hash: &HOutput<P>,
		new_root_hash: &HOutput<P>,
		leaf: &L,
		index: u64,
	) -> Result<bool, Error> {
		if self.old_path.path.len() != (P::HEIGHT - 1) as usize
			|| self.new_path.path.len() != (P::HEIGHT - 1) as usize
		{
			return Ok(false);
		}
		// Check that the given leaf matches the leaf in the membership proof.
		let last_level_index: u64 = (1u64 << (P::HEIGHT - 1)) - 1;
		let tree_index: u64 = last_level_index + index;

		let mut index_from_path: u64 = last_level_index;
		let mut index_offset: u64 = 1;

		if !self.old_path.path.is_empty() && !self.new_path.path.is_empty() {
			// Check the new path first
			let claimed_leaf_hash = hash_leaf::<P::H, L>(parameters, leaf)?;

			if tree_index % 2 == 1 {
				if claimed_leaf_hash != self.new_path.path[0].0 {
					return Ok(false);
				}
			} else if claimed_leaf_hash != self.new_path.path[0].1 {
				return Ok(false);
			}

			let mut prev = claimed_leaf_hash;
			let mut prev_index = tree_index;

			// Check levels between leaf level and root.
			for &(ref left_hash, ref right_hash) in &self.new_path.path {
				// Check if the previous hash matches the correct current hash.
				if prev_index % 2 == 1 {
					if &prev != left_hash {
						return Ok(false);
					}
				} else {
					if &prev != right_hash {
						return Ok(false);
					}
					index_from_path += index_offset;
				}
				index_offset *= 2;
				prev_index = (prev_index - 1) / 2;
				prev = hash_inner_node::<P::H>(parameters, left_hash, right_hash)?;
			}

			if new_root_hash != &prev {
				return Ok(false);
			}

			if index_from_path != tree_index {
				return Ok(false);
			}

			if tree_index % 2 == 1 {
				prev = self.old_path.path[0].0.clone();
			} else {
				prev = self.old_path.path[0].1.clone();
			}

			prev_index = tree_index;
			let mut new_path_iter = self.new_path.path.iter();
			for &(ref left_hash, ref right_hash) in &self.old_path.path {
				// Check if the previous hash matches the correct current hash.
				if prev_index % 2 == 1 {
					if &prev != left_hash {
						return Ok(false);
					}
				} else if &prev != right_hash {
					return Ok(false);
				}

				let new_path_corresponding_entry = new_path_iter.next();

				// Check the co-path is unchanged
				match new_path_corresponding_entry {
					Some(x) => {
						if prev_index % 2 == 1 {
							if *right_hash != x.1 {
								return Ok(false);
							}
						} else if *left_hash != x.0 {
							return Ok(false);
						}
					}
					None => return Ok(false),
				}

				prev_index = (prev_index - 1) / 2;
				prev = hash_inner_node::<P::H>(parameters, left_hash, right_hash)?;
			}

			if old_root_hash != &prev {
				return Ok(false);
			}

			Ok(true)
		} else {
			Ok(false)
		}
	}
}

/// Merkle sparse tree
pub struct SparseMerkleTree<P: Config> {
	/// data of the tree
	pub tree: BTreeMap<u64, HOutput<P>>,
	parameters: HParameters<P>,
	root: Option<HOutput<P>>,
	empty_hashes: Vec<HOutput<P>>,
}

impl<P: Config> SparseMerkleTree<P> {
	/// obtain an empty tree
	pub fn blank<L: Default + ToBytes>(parameters: HParameters<P>) -> Self {
		let empty_hashes = gen_empty_hashes::<P, L>(&parameters, L::default()).unwrap();

		SparseMerkleTree {
			tree: BTreeMap::new(),
			parameters,
			root: Some(empty_hashes[(P::HEIGHT - 1) as usize].clone()),
			empty_hashes,
		}
	}

	/// initialize a tree (with optional data)
	pub fn new<L: Default + ToBytes>(
		parameters: HParameters<P>,
		leaves: &BTreeMap<u64, L>,
	) -> Result<Self, Error> {
		let last_level_size = leaves.len().next_power_of_two();
		let tree_size = 2 * last_level_size - 1;
		let tree_height = tree_height(tree_size as u64);
		assert!(tree_height <= P::HEIGHT);

		// Initialize the merkle tree.
		let mut tree: BTreeMap<u64, HOutput<P>> = BTreeMap::new();
		let empty_hashes = gen_empty_hashes::<P, L>(&parameters, L::default())?;

		// Compute and store the hash values for each leaf.
		let last_level_index: u64 = (1u64 << (P::HEIGHT - 1)) - 1;
		for (i, leaf) in leaves.iter() {
			tree.insert(
				last_level_index + *i,
				hash_leaf::<P::H, _>(&parameters, leaf)?,
			);
		}

		let mut middle_nodes: BTreeSet<u64> = BTreeSet::new();
		for i in leaves.keys() {
			middle_nodes.insert(parent(last_level_index + *i).unwrap());
		}

		// Compute the hash values for every node in parts of the tree.
		for level in 0..P::HEIGHT {
			// Iterate over the current level.
			for current_index in &middle_nodes {
				let left_index = left_child(*current_index);
				let right_index = right_child(*current_index);

				let mut left_hash = empty_hashes[level as usize].clone();
				let mut right_hash = empty_hashes[level as usize].clone();

				if tree.contains_key(&left_index) {
					match tree.get(&left_index) {
						Some(x) => left_hash = x.clone(),
						_ => return Err(SparseMerkleTreeError::IncorrectTreeStructure.into()),
					}
				}

				if tree.contains_key(&right_index) {
					match tree.get(&right_index) {
						Some(x) => right_hash = x.clone(),
						_ => return Err(SparseMerkleTreeError::IncorrectTreeStructure.into()),
					}
				}

				// Compute Hash(left || right).
				tree.insert(
					*current_index,
					hash_inner_node::<P::H>(&parameters, &left_hash, &right_hash)?,
				);
			}

			let tmp_middle_nodes = middle_nodes.clone();
			middle_nodes.clear();
			for i in tmp_middle_nodes {
				if !is_root(i) {
					middle_nodes.insert(parent(i).unwrap());
				}
			}
		}

		let root_hash;
		match tree.get(&0) {
			Some(x) => root_hash = (*x).clone(),
			_ => return Err(SparseMerkleTreeError::IncorrectTreeStructure.into()),
		}

		Ok(SparseMerkleTree {
			tree,
			parameters,
			root: Some(root_hash),
			empty_hashes,
		})
	}

	#[inline]
	/// obtain the root hash
	pub fn root(&self) -> HOutput<P> {
		self.root.clone().unwrap()
	}

	/// generate a membership proof (does not check the data point)
	pub fn generate_membership_proof(&self, index: u64) -> Result<Path<P>, Error> {
		let mut path = Vec::new();

		let tree_height = P::HEIGHT;
		let tree_index = convert_index_to_last_level(index, tree_height);

		// Iterate from the leaf up to the root, storing all intermediate hash values.
		let mut current_node = tree_index;
		let mut empty_hashes_iter = self.empty_hashes.iter();
		while !is_root(current_node) {
			let sibling_node = sibling(current_node).unwrap();

			let mut current_hash = empty_hashes_iter.next().unwrap().clone();
			let mut sibling_hash = current_hash.clone();

			if self.tree.contains_key(&current_node) {
				match self.tree.get(&current_node) {
					Some(x) => current_hash = x.clone(),
					_ => return Err(SparseMerkleTreeError::IncorrectTreeStructure.into()),
				}
			}

			if self.tree.contains_key(&sibling_node) {
				match self.tree.get(&sibling_node) {
					Some(x) => sibling_hash = x.clone(),
					_ => return Err(SparseMerkleTreeError::IncorrectTreeStructure.into()),
				}
			}

			if is_left_child(current_node) {
				path.push((current_hash, sibling_hash));
			} else {
				path.push((sibling_hash, current_hash));
			}
			current_node = parent(current_node).unwrap();
		}

		if path.len() != (P::HEIGHT - 1) as usize {
			Err(SparseMerkleTreeError::IncorrectPathLength(path.len()).into())
		} else {
			Ok(Path { path })
		}
	}

	/// generate a lookup proof
	pub fn generate_proof<L: ToBytes>(&self, index: u64, leaf: &L) -> Result<Path<P>, Error> {
		let leaf_hash = hash_leaf::<P::H, _>(&self.parameters, leaf)?;
		let tree_height = P::HEIGHT;
		let tree_index = convert_index_to_last_level(index, tree_height);

		// Check that the given index corresponds to the correct leaf.
		if let Some(x) = self.tree.get(&tree_index) {
			if leaf_hash != *x {
				return Err(SparseMerkleTreeError::IncorrectTreeStructure.into());
			}
		}

		self.generate_membership_proof(index)
	}

	/// update the tree and provide a modifying proof
	pub fn update_and_prove<L: ToBytes>(
		&mut self,
		index: u64,
		new_leaf: &L,
	) -> Result<TwoPaths<P>, Error> {
		let old_path = self.generate_membership_proof(index)?;

		let new_leaf_hash = hash_leaf::<P::H, _>(&self.parameters, new_leaf)?;

		let tree_height = P::HEIGHT;
		let tree_index = convert_index_to_last_level(index, tree_height);

		// Update the leaf and update the parents
		self.tree.insert(tree_index, new_leaf_hash);

		// Iterate from the leaf up to the root, storing all intermediate hash values.
		let mut current_node = tree_index;
		current_node = parent(current_node).unwrap();

		let mut empty_hashes_iter = self.empty_hashes.iter();
		loop {
			let left_node = left_child(current_node);
			let right_node = right_child(current_node);

			let mut left_hash = empty_hashes_iter.next().unwrap().clone();
			let mut right_hash = left_hash.clone();

			if self.tree.contains_key(&left_node) {
				match self.tree.get(&left_node) {
					Some(x) => left_hash = x.clone(),
					_ => return Err(SparseMerkleTreeError::IncorrectTreeStructure.into()),
				}
			}

			if self.tree.contains_key(&right_node) {
				match self.tree.get(&right_node) {
					Some(x) => right_hash = x.clone(),
					_ => return Err(SparseMerkleTreeError::IncorrectTreeStructure.into()),
				}
			}

			self.tree.insert(
				current_node,
				hash_inner_node::<P::H>(&self.parameters, &left_hash, &right_hash)?,
			);

			if is_root(current_node) {
				break;
			}

			current_node = parent(current_node).unwrap();
		}

		match self.tree.get(&0) {
			Some(x) => self.root = Some((*x).clone()),
			None => return Err(SparseMerkleTreeError::IncorrectTreeStructure.into()),
		}

		let new_path = self.generate_proof(index, new_leaf)?;

		Ok(TwoPaths { old_path, new_path })
	}

	/// check if the tree is structurally valid
	pub fn validate(&self) -> Result<bool, Error> {
		/* Finding the leaf nodes */
		let last_level_index: u64 = (1u64 << (P::HEIGHT - 1)) - 1;
		let mut middle_nodes: BTreeSet<u64> = BTreeSet::new();

		for key in self.tree.keys() {
			if *key >= last_level_index && !is_root(*key) {
				middle_nodes.insert(parent(*key).unwrap());
			}
		}

		for level in 0..P::HEIGHT {
			for current_index in &middle_nodes {
				let left_index = left_child(*current_index);
				let right_index = right_child(*current_index);

				let mut left_hash = self.empty_hashes[level as usize].clone();
				let mut right_hash = self.empty_hashes[level as usize].clone();

				if self.tree.contains_key(&left_index) {
					match self.tree.get(&left_index) {
						Some(x) => left_hash = x.clone(),
						_ => {
							return Ok(false);
						}
					}
				}

				if self.tree.contains_key(&right_index) {
					match self.tree.get(&right_index) {
						Some(x) => right_hash = x.clone(),
						_ => {
							return Ok(false);
						}
					}
				}

				let hash = hash_inner_node::<P::H>(&self.parameters, &left_hash, &right_hash)?;

				match self.tree.get(current_index) {
					Some(x) => {
						if *x != hash {
							return Ok(false);
						}
					}
					_ => {
						return Ok(false);
					}
				}
			}

			let tmp_middle_nodes = middle_nodes.clone();
			middle_nodes.clear();
			for i in tmp_middle_nodes {
				if !is_root(i) {
					middle_nodes.insert(parent(i).unwrap());
				}
			}
		}

		Ok(true)
	}
}

/// error for Merkle sparse tree
#[derive(Debug)]
pub enum SparseMerkleTreeError {
	/// the path's length does not work for this tree
	IncorrectPathLength(usize),
	/// tree structure is incorrect, some nodes are missing
	IncorrectTreeStructure,
}

impl core::fmt::Display for SparseMerkleTreeError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		let msg = match self {
			SparseMerkleTreeError::IncorrectPathLength(len) => {
				format!("incorrect path length: {}", len)
			}
			SparseMerkleTreeError::IncorrectTreeStructure => "incorrect tree structure".to_string(),
		};
		write!(f, "{}", msg)
	}
}

impl ark_std::error::Error for SparseMerkleTreeError {}

/// Returns the log2 value of the given number.
#[inline]
fn log2(number: u64) -> u64 {
	ark_std::log2(number as usize) as u64
}

/// Returns the height of the tree, given the size of the tree.
#[inline]
fn tree_height(tree_size: u64) -> u64 {
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

#[inline]
fn convert_index_to_last_level(index: u64, tree_height: u64) -> u64 {
	index + (1 << (tree_height - 1)) - 1
}

/// Returns the output hash, given a left and right hash value.
pub(crate) fn hash_inner_node<H: FixedLengthCRH>(
	parameters: &H::Parameters,
	left: &H::Output,
	right: &H::Output,
) -> Result<H::Output, Error> {
	let bytes = to_bytes![left, right]?;
	H::evaluate(parameters, &bytes)
}

/// Returns the hash of a leaf.
fn hash_leaf<H: FixedLengthCRH, L: ToBytes>(
	parameters: &H::Parameters,
	leaf: &L,
) -> Result<H::Output, Error> {
	H::evaluate(parameters, &to_bytes![leaf]?)
}

fn hash_empty<H: FixedLengthCRH, L: ToBytes>(
	parameters: &H::Parameters,
	empty_leaf: L,
) -> Result<H::Output, Error> {
	H::evaluate(parameters, &[0u8; vec![0u8; H::INPUT_SIZE_BITS / 8]])
}

fn gen_empty_hashes<P: Config, L: ToBytes>(
	parameters: &HParameters<P>,
	empty_leaf: L,
) -> Result<Vec<HOutput<P>>, Error> {
	let mut empty_hashes = Vec::with_capacity(P::HEIGHT as usize);

	let mut empty_hash = hash_empty::<P::H, L>(&parameters, empty_leaf)?;
	empty_hashes.push(empty_hash.clone());

	for _ in 1..=P::HEIGHT {
		empty_hash = hash_inner_node::<P::H>(&parameters, &empty_hash, &empty_hash)?;
		empty_hashes.push(empty_hash.clone());
	}

	Ok(empty_hashes)
}
