use ark_ff::PrimeField;
use ark_r1cs_std::{boolean::AllocatedBit, prelude::*, uint64::UInt64};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};

use crate::building_blocks::{crh::CRHforMerkleTreeGadget, mt::merkle_sparse_tree::*};
use ark_std::borrow::Borrow;

/// Gadgets for one Merkle tree path
#[derive(Debug)]
pub struct MerkleSparseTreePathVar<P, HVar, ConstraintF>
where
	P: MerkleSparseTreeConfig,
	HVar: CRHforMerkleTreeGadget<P::H, ConstraintF>,
	ConstraintF: PrimeField,
{
	path: Vec<(HVar::OutputVar, HVar::OutputVar)>,
}

/// Gadgets for two Merkle tree paths
#[derive(Debug)]
pub struct MerkleSparseTreeTwoPathsVar<P, HVar, ConstraintF>
where
	P: MerkleSparseTreeConfig,
	HVar: CRHforMerkleTreeGadget<P::H, ConstraintF>,
	ConstraintF: PrimeField,
{
	old_path: Vec<(HVar::OutputVar, HVar::OutputVar)>,
	new_path: Vec<(HVar::OutputVar, HVar::OutputVar)>,
}

impl<P, CRHVar, ConstraintF> MerkleSparseTreePathVar<P, CRHVar, ConstraintF>
where
	P: MerkleSparseTreeConfig,
	ConstraintF: PrimeField,
	CRHVar: CRHforMerkleTreeGadget<P::H, ConstraintF>,
{
	/// check a lookup proof (does not enforce index consistency)
	pub fn check_membership(
		&self,
		cs: ConstraintSystemRef<ConstraintF>,
		parameters: &<P::H as CRHforMerkleTree>::Parameters,
		root: &CRHVar::OutputVar,
		leaf: impl ToBytesGadget<ConstraintF>,
	) -> Result<(), SynthesisError> {
		self.conditionally_check_membership(cs, parameters, root, leaf, &Boolean::Constant(true))
	}

	/// conditionally check a lookup proof (does not enforce index consistency)
	pub fn conditionally_check_membership(
		&self,
		cs: ConstraintSystemRef<ConstraintF>,
		parameters: &<P::H as CRHforMerkleTree>::Parameters,
		root: &CRHVar::OutputVar,
		leaf: impl ToBytesGadget<ConstraintF>,
		should_enforce: &Boolean<ConstraintF>,
	) -> Result<(), SynthesisError> {
		assert_eq!(self.path.len(), (P::HEIGHT - 1) as usize);
		// Check that the hash of the given leaf matches the leaf hash in the membership
		// proof.
		let leaf_bits = leaf.to_bytes()?;
		let leaf_hash = CRHVar::hash_bytes(parameters, &leaf_bits)?;

		// Check if leaf is one of the bottom-most siblings.
		let leaf_is_left = Boolean::Is(AllocatedBit::new_witness(
			ark_relations::ns!(cs, "leaf_is_left"),
			|| Ok(leaf_hash.value()? == self.path[0].0.value()?),
		)?);

		leaf_hash.conditional_enforce_equal(
			&CRHVar::OutputVar::conditionally_select(
				&leaf_is_left,
				&self.path[0].0,
				&self.path[0].1,
			)?,
			should_enforce,
		)?;

		// Check levels between leaf level and root.
		let mut previous_hash = leaf_hash;
		for &(ref left_hash, ref right_hash) in self.path.iter() {
			// Check if the previous_hash matches the correct current hash.
			let previous_is_left = Boolean::Is(AllocatedBit::new_witness(
				ark_relations::ns!(cs, "previous_is_left"),
				|| Ok(previous_hash.value()? == left_hash.value()?),
			)?);

			previous_hash.conditional_enforce_equal(
				&CRHVar::OutputVar::conditionally_select(&previous_is_left, left_hash, right_hash)?,
				should_enforce,
			)?;

			previous_hash = hash_inner_node_gadget::<P::H, CRHVar, ConstraintF>(
				parameters, left_hash, right_hash,
			)?;
		}

		root.conditional_enforce_equal(&previous_hash, should_enforce)
	}

	/// check a lookup proof (with index)
	pub fn check_membership_with_index(
		&self,
		parameters: &<P::H as CRHforMerkleTree>::Parameters,
		root: &CRHVar::OutputVar,
		leaf: impl ToBytesGadget<ConstraintF>,
		index: &UInt64<ConstraintF>,
	) -> Result<(), SynthesisError> {
		self.conditionally_check_membership_with_index(
			parameters,
			root,
			leaf,
			index,
			&Boolean::Constant(true),
		)
	}

	/// conditionally check a lookup proof (with index)
	pub fn conditionally_check_membership_with_index(
		&self,
		parameters: &<P::H as CRHforMerkleTree>::Parameters,
		root: &CRHVar::OutputVar,
		leaf: impl ToBytesGadget<ConstraintF>,
		index: &UInt64<ConstraintF>,
		should_enforce: &Boolean<ConstraintF>,
	) -> Result<(), SynthesisError> {
		assert_eq!(self.path.len(), (P::HEIGHT - 1) as usize);
		// Check that the hash of the given leaf matches the leaf hash in the membership
		// proof.
		let leaf_bits = leaf.to_bytes()?;
		let leaf_hash = CRHVar::hash_bytes(parameters, &leaf_bits)?;

		// Check levels between leaf level and root.
		let mut previous_hash = leaf_hash;
		let index_bits = index.to_bits_le();
		for (i, &(ref left_hash, ref right_hash)) in self.path.iter().enumerate() {
			// Check if the previous_hash matches the correct current hash.
			let previous_is_left = index_bits[i].not();

			previous_hash.conditional_enforce_equal(
				&CRHVar::OutputVar::conditionally_select(&previous_is_left, left_hash, right_hash)?,
				should_enforce,
			)?;

			previous_hash = hash_inner_node_gadget::<P::H, CRHVar, ConstraintF>(
				parameters, left_hash, right_hash,
			)?;
		}

		root.conditional_enforce_equal(&previous_hash, should_enforce)
	}
}

impl<P, CRHVar, ConstraintF> MerkleSparseTreeTwoPathsVar<P, CRHVar, ConstraintF>
where
	P: MerkleSparseTreeConfig,
	ConstraintF: PrimeField,
	CRHVar: CRHforMerkleTreeGadget<P::H, ConstraintF>,
{
	/// check a modifying proof
	pub fn check_update(
		&self,
		parameters: &<P::H as CRHforMerkleTree>::Parameters,
		old_root: &CRHVar::OutputVar,
		new_root: &CRHVar::OutputVar,
		new_leaf: impl ToBytesGadget<ConstraintF>,
		index: &UInt64<ConstraintF>,
	) -> Result<(), SynthesisError> {
		self.conditionally_check_update(
			parameters,
			old_root,
			new_root,
			new_leaf,
			index,
			&Boolean::Constant(true),
		)
	}

	/// conditionally check a modifying proof
	pub fn conditionally_check_update(
		&self,
		parameters: &<P::H as CRHforMerkleTree>::Parameters,
		old_root: &CRHVar::OutputVar,
		new_root: &CRHVar::OutputVar,
		new_leaf: impl ToBytesGadget<ConstraintF>,
		index: &UInt64<ConstraintF>,
		should_enforce: &Boolean<ConstraintF>,
	) -> Result<(), SynthesisError> {
		assert_eq!(self.old_path.len(), (P::HEIGHT - 1) as usize);
		assert_eq!(self.new_path.len(), (P::HEIGHT - 1) as usize);
		// Check that the hash of the given leaf matches the leaf hash in the membership
		// proof.
		let new_leaf_bits = new_leaf.to_bytes()?;
		let new_leaf_hash = CRHVar::hash_bytes(parameters, &new_leaf_bits)?;

		// Check levels between leaf level and root of the new tree.
		let mut previous_hash = new_leaf_hash;
		let index_bits = index.to_bits_le();
		for (i, &(ref left_hash, ref right_hash)) in self.new_path.iter().enumerate() {
			// Check if the previous_hash matches the correct current hash.
			let previous_is_left = index_bits[i].not();

			previous_hash.conditional_enforce_equal(
				&CRHVar::OutputVar::conditionally_select(&previous_is_left, left_hash, right_hash)?,
				should_enforce,
			)?;

			previous_hash = hash_inner_node_gadget::<P::H, CRHVar, ConstraintF>(
				parameters, left_hash, right_hash,
			)?;
		}

		new_root.conditional_enforce_equal(&previous_hash, should_enforce)?;

		let mut old_path_iter = self.old_path.iter();
		let old_path_first_entry = old_path_iter.next().unwrap();

		previous_hash = hash_inner_node_gadget::<P::H, CRHVar, ConstraintF>(
			parameters,
			&old_path_first_entry.0,
			&old_path_first_entry.1,
		)?;

		let mut current_loc = 1;
		loop {
			let pair = old_path_iter.next();

			match pair {
				Some((left_hash, right_hash)) => {
					// Check if the previous_hash matches the correct current hash.
					let previous_is_left = index_bits[current_loc].not();

					previous_hash.conditional_enforce_equal(
						&CRHVar::OutputVar::conditionally_select(
							&previous_is_left,
							left_hash,
							right_hash,
						)?,
						should_enforce,
					)?;

					previous_hash = hash_inner_node_gadget::<P::H, CRHVar, ConstraintF>(
						parameters, left_hash, right_hash,
					)?;
				}
				None => break,
			}
			current_loc += 1;
		}

		old_path_iter = self.old_path.iter();
		for (i, &(ref left_hash, ref right_hash)) in self.new_path.iter().enumerate() {
			// Check if the previous_hash matches the correct current hash.
			let previous_is_left = index_bits[i].not();
			let previous_is_right = previous_is_left.not();

			let old_path_corresponding_entry = old_path_iter.next().unwrap();

			right_hash
				.conditional_enforce_equal(&old_path_corresponding_entry.1, &previous_is_left)?;

			left_hash
				.conditional_enforce_equal(&old_path_corresponding_entry.0, &previous_is_right)?;
		}

		old_root.conditional_enforce_equal(&previous_hash, should_enforce)
	}
}

pub(crate) fn hash_inner_node_gadget<H, HG, ConstraintF>(
	parameters: &H::Parameters,
	left_child: &HG::OutputVar,
	right_child: &HG::OutputVar,
) -> Result<HG::OutputVar, SynthesisError>
where
	ConstraintF: PrimeField,
	H: CRHforMerkleTree,
	HG: CRHforMerkleTreeGadget<H, ConstraintF>,
{
	HG::two_to_one_compress(parameters, left_child, right_child)
}

impl<P, HVar, ConstraintF> AllocVar<MerkleSparseTreePath<P>, ConstraintF>
	for MerkleSparseTreePathVar<P, HVar, ConstraintF>
where
	P: MerkleSparseTreeConfig,
	HVar: CRHforMerkleTreeGadget<P::H, ConstraintF>,
	ConstraintF: PrimeField,
{
	fn new_variable<T: Borrow<MerkleSparseTreePath<P>>>(
		cs: impl Into<Namespace<ConstraintF>>,
		f: impl FnOnce() -> Result<T, SynthesisError>,
		mode: AllocationMode,
	) -> Result<Self, SynthesisError> {
		let ns = cs.into();
		let cs = ns.cs();

		let mut path = Vec::new();
		for &(ref l, ref r) in f()?.borrow().path.iter() {
			let l_hash = HVar::OutputVar::new_variable(
				ark_relations::ns!(cs, "l_child"),
				|| Ok(l.clone()),
				mode,
			)?;
			let r_hash = HVar::OutputVar::new_variable(
				ark_relations::ns!(cs, "r_child"),
				|| Ok(r.clone()),
				mode,
			)?;
			path.push((l_hash, r_hash));
		}
		Ok(MerkleSparseTreePathVar { path })
	}
}

impl<P, HVar, ConstraintF> AllocVar<MerkleSparseTreeTwoPaths<P>, ConstraintF>
	for MerkleSparseTreeTwoPathsVar<P, HVar, ConstraintF>
where
	P: MerkleSparseTreeConfig,
	HVar: CRHforMerkleTreeGadget<P::H, ConstraintF>,
	ConstraintF: PrimeField,
{
	fn new_variable<T: Borrow<MerkleSparseTreeTwoPaths<P>>>(
		cs: impl Into<Namespace<ConstraintF>>,
		f: impl FnOnce() -> Result<T, SynthesisError>,
		mode: AllocationMode,
	) -> Result<Self, SynthesisError> {
		let ns = cs.into();
		let cs = ns.cs();

		let mut old_path = Vec::new();

		let t = f()?;
		let paths = t.borrow();
		for &(ref l, ref r) in paths.old_path.path.iter() {
			let l_hash = HVar::OutputVar::new_variable(
				ark_relations::ns!(cs, "old_path_l_child"),
				|| Ok(l.clone()),
				mode,
			)?;
			let r_hash = HVar::OutputVar::new_variable(
				ark_relations::ns!(cs, "old_path_r_child"),
				|| Ok(r.clone()),
				mode,
			)?;
			old_path.push((l_hash, r_hash));
		}
		let mut new_path = Vec::new();
		for &(ref l, ref r) in paths.new_path.path.iter() {
			let l_hash = HVar::OutputVar::new_variable(
				ark_relations::ns!(cs, "new_path_l_child"),
				|| Ok(l.clone()),
				mode,
			)?;
			let r_hash = HVar::OutputVar::new_variable(
				ark_relations::ns!(cs, "new_path_r_child"),
				|| Ok(r.clone()),
				mode,
			)?;
			new_path.push((l_hash, r_hash));
		}
		Ok(MerkleSparseTreeTwoPathsVar { old_path, new_path })
	}
}
