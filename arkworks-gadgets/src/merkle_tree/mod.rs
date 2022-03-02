#[cfg(feature = "r1cs")]
pub mod simple_merkle_constraints;

pub mod simple_merkle;

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
