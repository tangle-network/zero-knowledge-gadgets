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

//! This file provides the R1CS constraints implementation of the Sparse Merkle
//! tree data structure.

//! For a more through description of the sparse merkle tree data structure
//! refer to [arkworks_native_gadgets::merkle_tree]
//!
//!
//! # Usage
//! ```rust
//! //! Create a new Sparse Merkle Tree with 32 random leaves
//!
//! // Import dependencies
//! use crate::arkworks_r1cs_gadgets::poseidon::{FieldHasherGadget, PoseidonGadget};
//! use ark_ed_on_bn254::Fq;
//! use ark_ff::{BigInteger, PrimeField};
//! use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, prelude::FieldVar};
//! use ark_relations::r1cs::ConstraintSystem;
//! use ark_std::{collections::BTreeMap, test_rng, UniformRand};
//! use arkworks_native_gadgets::{
//! 	merkle_tree::SparseMerkleTree,
//! 	poseidon::{sbox::PoseidonSbox, Poseidon, PoseidonParameters},
//! };
//! use arkworks_r1cs_gadgets::merkle_tree::PathVar;
//! use arkworks_utils::{
//! 	bytes_matrix_to_f, bytes_vec_to_f, parse_vec, poseidon_params::setup_poseidon_params, Curve,
//! };
//!
//! type SMTCRHGadget = PoseidonGadget<Fq>;
//! const HEIGHT: usize = 30;
//! const DEFAULT_LEAF: [u8; 32] = [0; 32];
//! type SMT = SparseMerkleTree<Fq, Poseidon<Fq>, HEIGHT>;
//!
//! let rng = &mut test_rng();
//! let exp = 5;
//! let width = 3;
//! let curve = Curve::Bn254;
//!
//! let pos_data = setup_poseidon_params(curve, exp, width).unwrap();
//!
//! let mds_f = bytes_matrix_to_f(&pos_data.mds);
//! let rounds_f = bytes_vec_to_f(&pos_data.rounds);
//!
//! let params3 = PoseidonParameters {
//! 	mds_matrix: mds_f,
//! 	round_keys: rounds_f,
//! 	full_rounds: pos_data.full_rounds,
//! 	partial_rounds: pos_data.partial_rounds,
//! 	sbox: PoseidonSbox(pos_data.exp),
//! 	width: pos_data.width,
//! };
//! let hasher = Poseidon::<Fq> { params: params3 };
//!
//! let mut cs = ConstraintSystem::<Fq>::new_ref();
//! let hasher_gadget = PoseidonGadget::from_native(&mut cs, hasher.clone()).unwrap();
//!
//! let leaves = vec![Fq::rand(rng), Fq::rand(rng), Fq::rand(rng)];
//! let smt = SMT::new_sequential(&leaves, &hasher, &DEFAULT_LEAF).unwrap();
//! let root = smt.root();
//! let path = smt.generate_membership_proof(0);
//!
//! let path_var =
//! 	PathVar::<_, SMTCRHGadget, HEIGHT>::new_witness(cs.clone(), || Ok(path)).unwrap();
//!
//! let root_var = FpVar::new_witness(cs.clone(), || Ok(root)).unwrap();
//!
//! let leaf_var = FpVar::new_witness(cs.clone(), || Ok(leaves[0])).unwrap();
//!
//! let res = path_var
//! 	.check_membership(&root_var, &leaf_var, &hasher_gadget)
//! 	.unwrap();
//! ```
// Import dependencies
use ark_ff::PrimeField;
use ark_r1cs_std::{
	alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, prelude::*, select::CondSelectGadget,
};
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::{borrow::Borrow, marker::PhantomData, vec::Vec};
use arkworks_native_gadgets::{merkle_tree::Path, poseidon::FieldHasher};
use core::convert::TryInto;

use crate::poseidon::FieldHasherGadget;

/// Gadgets for one Merkle tree path
#[derive(Debug, Clone)]
pub struct PathVar<F, HG, const N: usize>
where
	F: PrimeField,
	HG: FieldHasherGadget<F>,
{
	#[allow(clippy::type_complexity)]
	path: [(FpVar<F>, FpVar<F>); N],
	phantom: PhantomData<HG>,
}

impl<F, HG, const N: usize> PathVar<F, HG, N>
where
	F: PrimeField,
	HG: FieldHasherGadget<F>,
{
	/// check whether path belongs to merkle path (does not check if indexes
	/// match)
	pub fn check_membership(
		&self,
		root: &FpVar<F>,
		leaf: &FpVar<F>,
		hasher: &HG,
	) -> Result<Boolean<F>, SynthesisError> {
		let computed_root = self.root_hash(leaf, hasher)?;

		root.is_eq(&computed_root)
	}

	/// Creates circuit to calculate merkle root and deny any invalid paths
	pub fn root_hash(&self, leaf: &FpVar<F>, hasher: &HG) -> Result<FpVar<F>, SynthesisError> {
		assert_eq!(self.path.len(), N);
		// Check if leaf is one of the bottom-most siblings.
		let leaf_is_left = leaf.is_eq(&self.path[0].0)?;

		// Checks if leaf hash matches path value
		leaf.enforce_equal(&FpVar::<F>::conditionally_select(
			&leaf_is_left,
			&self.path[0].0,
			&self.path[0].1,
		)?)?;

		// Check levels between leaf level and root.
		let mut previous_hash = leaf.clone();
		for &(ref left_hash, ref right_hash) in self.path.iter() {
			// Check if the previous_hash matches the correct current hash.
			let previous_is_left = previous_hash.is_eq(left_hash)?;

			previous_hash.enforce_equal(&FpVar::<F>::conditionally_select(
				&previous_is_left,
				left_hash,
				right_hash,
			)?)?;

			previous_hash = hasher.hash_two(left_hash, right_hash)?;
		}

		Ok(previous_hash)
	}

	/// Creates circuit to get index of a leaf hash
	pub fn get_index(
		&self,
		root: &FpVar<F>,
		leaf: &FpVar<F>,
		hasher: &HG,
	) -> Result<FpVar<F>, SynthesisError> {
		let mut index = FpVar::<F>::zero();
		let mut twopower = FpVar::<F>::one();
		let mut rightvalue: FpVar<F>;

		// Check levels between leaf level and root.
		let mut previous_hash = leaf.clone();
		for &(ref left_hash, ref right_hash) in self.path.iter() {
			// Check if the previous_hash is for a left node.
			let previous_is_left = previous_hash.is_eq(left_hash)?;

			rightvalue = index.clone() + twopower.clone();
			index = FpVar::<F>::conditionally_select(&previous_is_left, &index, &rightvalue)?;
			twopower = twopower.clone() + twopower.clone();

			previous_hash = hasher.hash_two(left_hash, right_hash)?;
		}

		// Now check that path has the correct Merkle root
		let is_on_path = previous_hash.is_eq(root);
		is_on_path.unwrap().enforce_equal(&Boolean::TRUE)?;

		Ok(index)
	}
}

impl<F, H, HG, const N: usize> AllocVar<Path<F, H, N>, F> for PathVar<F, HG, N>
where
	F: PrimeField,
	H: FieldHasher<F>,
	HG: FieldHasherGadget<F>,
{
	fn new_variable<T: Borrow<Path<F, H, N>>>(
		cs: impl Into<Namespace<F>>,
		f: impl FnOnce() -> Result<T, SynthesisError>,
		mode: AllocationMode,
	) -> Result<Self, SynthesisError> {
		let ns = cs.into();
		let cs = ns.cs();

		let mut path = Vec::new();
		let path_obj = f()?;
		for &(ref l, ref r) in &path_obj.borrow().path {
			let l_hash =
				FpVar::<F>::new_variable(ark_relations::ns!(cs, "l_child"), || Ok(*l), mode)?;
			let r_hash =
				FpVar::<F>::new_variable(ark_relations::ns!(cs, "r_child"), || Ok(*r), mode)?;
			path.push((l_hash, r_hash));
		}

		Ok(PathVar {
			path: path.try_into().unwrap_or_else(
				#[allow(clippy::type_complexity)]
				|v: Vec<(FpVar<F>, FpVar<F>)>| {
					panic!("Expected a Vec of length {} but it was {}", N, v.len())
				},
			),
			phantom: PhantomData,
		})
	}
}

#[cfg(test)]
mod test {
	use super::PathVar;
	use crate::poseidon::{FieldHasherGadget, PoseidonGadget};
	use arkworks_native_gadgets::{
		merkle_tree::SparseMerkleTree,
		poseidon::{sbox::PoseidonSbox, Poseidon, PoseidonParameters},
	};

	use ark_ed_on_bn254::Fq;
	use ark_ff::PrimeField;
	use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, R1CSVar};
	use ark_relations::r1cs::ConstraintSystem;
	use ark_std::{test_rng, UniformRand};
	use arkworks_utils::{
		bytes_matrix_to_f, bytes_vec_to_f, poseidon_params::setup_poseidon_params, Curve,
	};

	pub fn setup_params<F: PrimeField>(curve: Curve, exp: i8, width: u8) -> PoseidonParameters<F> {
		let pos_data = setup_poseidon_params(curve, exp, width).unwrap();

		let mds_f = bytes_matrix_to_f(&pos_data.mds);
		let rounds_f = bytes_vec_to_f(&pos_data.rounds);

		PoseidonParameters {
			mds_matrix: mds_f,
			round_keys: rounds_f,
			full_rounds: pos_data.full_rounds,
			partial_rounds: pos_data.partial_rounds,
			sbox: PoseidonSbox(pos_data.exp),
			width: pos_data.width,
		}
	}

	type FieldVar = FpVar<Fq>;

	type SMTCRHGadget = PoseidonGadget<Fq>;

	const HEIGHT: usize = 30;
	const DEFAULT_LEAF: [u8; 32] = [0; 32];
	type SMT = SparseMerkleTree<Fq, Poseidon<Fq>, HEIGHT>;

	#[test]
	fn should_verify_path() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;

		let params3 = setup_params(curve, 5, 3);
		let hasher = Poseidon::<Fq> { params: params3 };

		let mut cs = ConstraintSystem::<Fq>::new_ref();
		let hasher_gadget = PoseidonGadget::from_native(&mut cs, hasher.clone()).unwrap();

		let leaves = vec![Fq::rand(rng), Fq::rand(rng), Fq::rand(rng)];
		let smt = SMT::new_sequential(&leaves, &hasher, &DEFAULT_LEAF).unwrap();
		let root = smt.root();
		let path = smt.generate_membership_proof(0);

		let path_var =
			PathVar::<_, SMTCRHGadget, HEIGHT>::new_witness(cs.clone(), || Ok(path)).unwrap();
		let root_var = FieldVar::new_witness(cs.clone(), || Ok(root)).unwrap();
		let leaf_var = FieldVar::new_witness(cs.clone(), || Ok(leaves[0])).unwrap();

		let res = path_var
			.check_membership(&root_var, &leaf_var, &hasher_gadget)
			.unwrap();
		assert!(res.cs().is_satisfied().unwrap());
		assert!(res.value().unwrap());
	}

	#[test]
	fn should_verify_index() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;

		let params3 = setup_params(curve, 5, 3);
		let hasher = Poseidon::<Fq> { params: params3 };

		let index = 2;
		let mut cs = ConstraintSystem::<Fq>::new_ref();
		let hasher_gadget = PoseidonGadget::from_native(&mut cs, hasher.clone()).unwrap();

		let leaves = vec![Fq::rand(rng), Fq::rand(rng), Fq::rand(rng)];
		let smt = SMT::new_sequential(&leaves, &hasher, &DEFAULT_LEAF).unwrap();
		let root = smt.root();
		let path = smt.generate_membership_proof(index);

		let path_var =
			PathVar::<_, SMTCRHGadget, HEIGHT>::new_witness(cs.clone(), || Ok(path)).unwrap();
		let root_var = FieldVar::new_witness(cs.clone(), || Ok(root)).unwrap();
		let leaf_var = FieldVar::new_witness(cs.clone(), || Ok(leaves[index as usize])).unwrap();

		let res = path_var
			.get_index(&root_var, &leaf_var, &hasher_gadget)
			.unwrap();
		let desired_res = Fq::from(index);

		assert!(res.cs().is_satisfied().unwrap());
		assert_eq!(res.value().unwrap(), desired_res);
	}

	// This test demonstrates that the get_index method verifies
	// that the path is consistent with the given Merkle root
	#[should_panic(expected = "assertion failed: res.cs().is_satisfied().unwrap()")]
	#[test]
	fn get_index_should_fail() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;

		let params3 = setup_params(curve, 5, 3);
		let hasher = Poseidon::<Fq> { params: params3 };

		let index = 2;

		let mut cs = ConstraintSystem::<Fq>::new_ref();
		let hasher_gadget = PoseidonGadget::from_native(&mut cs, hasher.clone()).unwrap();

		let leaves = vec![Fq::rand(rng), Fq::rand(rng), Fq::rand(rng)];
		let smt = SMT::new_sequential(&leaves, &hasher, &DEFAULT_LEAF).unwrap();
		let path = smt.generate_membership_proof(index);

		// Now generate a bad root to make this fail:
		let bad_leaves = vec![Fq::rand(rng), Fq::rand(rng), Fq::rand(rng)];
		let bad_smt = SMT::new_sequential(&bad_leaves, &hasher, &DEFAULT_LEAF).unwrap();
		let bad_root = bad_smt.root();

		let path_var =
			PathVar::<_, SMTCRHGadget, HEIGHT>::new_witness(cs.clone(), || Ok(path)).unwrap();
		let bad_root_var = FieldVar::new_witness(cs.clone(), || Ok(bad_root)).unwrap();
		let leaf_var = FieldVar::new_witness(cs.clone(), || Ok(leaves[index as usize])).unwrap();

		let res = path_var
			.get_index(&bad_root_var, &leaf_var, &hasher_gadget)
			.unwrap();
		let desired_res = Fq::from(index);

		assert!(res.cs().is_satisfied().unwrap());
		assert_eq!(res.value().unwrap(), desired_res);
	}
}
