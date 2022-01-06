use std::{marker::PhantomData, collections::BTreeSet};
use ark_std::collections::BTreeMap;
use crate::poseidon::field_hasher::FieldHasher;
use ark_crypto_primitives::Error;
use ark_ff::PrimeField;
use super::{parent, left_child, right_child, tree_height, sibling, is_root, is_left_child};

// Path
#[derive(Clone)]
pub struct Path<F: PrimeField, H: FieldHasher<F>, const N: usize> {
	pub(crate) path: [(F, F); N],
	_marker: PhantomData<H>, // Do we need to include this as part of the path?
}

impl<F: PrimeField, H: FieldHasher<F>, const N: usize> Path<F, H, N> {
	pub fn check_membership(&self, root_hash: &F, leaf: &F, hasher: &H) -> Result<bool, Error> {
		let root = self.calculate_root(leaf, hasher)?;
		Ok(root == *root_hash)
	}

	/// Assumes leaf is a hash output, i.e. the hash stored at leaf level
	/// of the Merkle tree.  (As opposed to the data used to produce that hash)
	pub fn calculate_root(&self, leaf: &F, hasher: &H) -> Result<F, Error> {
		if *leaf != self.path[0].0 && *leaf != self.path[0].1 {
			panic!("Leaf is not on path");
		}

		let mut prev = *leaf;
		// Check levels between leaf level and root
		for &(ref left_hash, ref right_hash) in &self.path {
			if &prev != left_hash && &prev != right_hash {
				panic!("Path nodes are not consistent");
			}
			prev = hasher.hash_two(left_hash, right_hash)?;
		}

        Ok(prev)
	}
}

// Merkle sparse tree
// The D parameter was intended to be a [u8; 32] array, but these are not 
// allowable as constant generics.  So now D represents the length of that array
// and I will assume all entries would have be
pub struct SparseMerkleTree<F: PrimeField, H: FieldHasher<F>, const N: usize> {
    /// data of the tree
    pub tree: BTreeMap<u64, F>,
    empty_hashes: [F; N],
    _marker: PhantomData<H>,
}

impl<F: PrimeField, H: FieldHasher<F>, const N: usize> SparseMerkleTree<F, H, N> {

    pub fn insert_batch(
        &mut self,
        leaves: &BTreeMap<u32, F>,
        hasher: &H,
    ) -> Result<(), Error> {
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
                self.tree.insert(
                    i,
                    hasher.hash_two(left, right)?,
                );

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
    
    pub fn new(
        leaves: &BTreeMap<u32, F>,
        hasher: &H,
        empty_leaf: [u8; 32], 
    ) -> Result<Self, Error> {
        let last_level_size = leaves.len().next_power_of_two();
        let tree_size = 2 * last_level_size - 1;
        let tree_height = tree_height(tree_size as u64);
        // assert!(tree_height <= HEIGHT);  //What to put here?

        // Initialize the merkle tree
        let tree: BTreeMap<u64, F> = BTreeMap::new();
        let empty_hashes = gen_empty_hashes(hasher, empty_leaf)?;

        let mut smt = SparseMerkleTree::<F, H, N> {
            tree,
            empty_hashes,
            _marker: PhantomData
        };
        smt.insert_batch(leaves, hasher)?;

        Ok(smt)
    }
    
    pub fn new_sequential(
        leaves: &[F],
        hasher: &H,
        empty_leaf: [u8; 32],
    ) -> Result<Self, Error>{
        let pairs: BTreeMap<u32, F> = leaves
            .iter()
            .enumerate()
            .map(|(i, l)| (i as u32, l.clone()))
            .collect();
        let smt = Self::new(&pairs, hasher, empty_leaf)?;

        Ok(smt)
    }
    
    pub fn root(&self) -> F {
        F::from(1u64)
    }
    
    pub fn generate_membership_proof(&self, index: u64) -> Path<F, H, N> {
        let mut path = [ (F::zero(), F::zero()) ; N];

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
            path: path,
            _marker: PhantomData,
        }
    }
}

pub fn gen_empty_hashes<F: PrimeField, H: FieldHasher<F>, const N: usize>(
    hasher: &H,
    default_leaf: [u8; 32],
) -> Result<[F; N], Error> {
    let mut empty_hashes = [ F::zero() ; N];

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