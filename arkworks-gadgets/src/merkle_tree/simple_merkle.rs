use std::marker::PhantomData;

use crate::poseidon::field_hasher::FieldHasher;
use ark_crypto_primitives::Error;
use ark_ff::PrimeField;

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
