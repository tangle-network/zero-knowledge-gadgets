use core::convert::TryInto;
use std::marker::PhantomData;

use super::{simple_merkle::Path};
use crate::{Vec, poseidon::{field_hasher_constraints::FieldHasherGadget, field_hasher::FieldHasher}};
use ark_ff::PrimeField;
use ark_r1cs_std::{
	alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, prelude::*, select::CondSelectGadget,
};
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::{borrow::Borrow};

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
	/// conditionally check a lookup proof (does not enforce index consistency)
	pub fn check_membership(
		&self,
		root: &FpVar<F>,
		leaf: &FpVar<F>,
		hasher: &HG,
	) -> Result<Boolean<F>, SynthesisError> {
		let computed_root = self.root_hash(leaf, hasher)?;

		root.is_eq(&computed_root)
	}

	pub fn root_hash(
		&self,
		leaf: &FpVar<F>,
		hasher: &HG,
	) -> Result<FpVar<F>, SynthesisError> {
		assert_eq!(self.path.len(), N);
		let mut cs = leaf.cs();
		// Check if leaf is one of the bottom-most siblings.
		let leaf_is_left = leaf.is_eq(&self.path[0].0)?;

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

			previous_hash = hasher.hash_two(&mut cs, left_hash, right_hash)?;
		}

		Ok(previous_hash)
	}

	pub fn get_index(
		&self,
		root: &FpVar<F>,
		leaf: &FpVar<F>,
		hasher: &HG,
	) -> Result<FpVar<F>, SynthesisError> {
		let mut cs = leaf.cs();
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

			previous_hash = hasher.hash_two(&mut cs, left_hash, right_hash)?;
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
				FpVar::<F>::new_variable(ark_relations::ns!(cs, "l_child"), || Ok(l.clone()), mode)?;
			let r_hash =
				FpVar::<F>::new_variable(ark_relations::ns!(cs, "r_child"), || Ok(r.clone()), mode)?;
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
	use super::{PathVar};
	use crate::{
		ark_std::UniformRand,
		merkle_tree::{Config, simple_merkle::{Path, SparseMerkleTree}},
		poseidon::{constraints::CRHGadget as PoseidonCRHGadget, CRH as PoseidonCRH, field_hasher::{FieldHasher, Poseidon}, field_hasher_constraints::{FieldHasherGadget, PoseidonGadget, PoseidonParametersVar}},
	};

	use ark_ed_on_bn254::Fq;
	use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, R1CSVar};
	use ark_relations::r1cs::ConstraintSystem;
	use ark_std::{rc::Rc, test_rng};
	use arkworks_utils::utils::common::{setup_params_x5_3, Curve};

	type FieldVar = FpVar<Fq>;

	type SMTCRHGadget = PoseidonGadget<Fq>;

	const HEIGHT: usize = 30;
	const DEFAULT_LEAF: [u8; 32] = [0; 32];
	type SMT = SparseMerkleTree<Fq, Poseidon<Fq>, HEIGHT>;

	#[test]
	fn should_verify_path() {
		let rng = &mut test_rng();
		let curve = Curve::Bls381;

		let params3 = setup_params_x5_3(curve);
		let hasher = Poseidon::<Fq> {
			params: params3,
		};

		let mut cs = ConstraintSystem::<Fq>::new_ref();
		let hasher_gadget = PoseidonGadget::from_native(&mut cs, hasher.clone());

		let leaves = vec![Fq::rand(rng), Fq::rand(rng), Fq::rand(rng)];
		let smt = SMT::new_sequential(&leaves, &hasher, &DEFAULT_LEAF).unwrap();
		let root = smt.root();
		let path = smt.generate_membership_proof(0);

		let path_var =
			PathVar::<_, SMTCRHGadget, HEIGHT>::new_witness(cs.clone(), || {
				Ok(path)
			})
			.unwrap();
		let root_var = FieldVar::new_witness(cs.clone(), || Ok(root)).unwrap();
		let leaf_var = FieldVar::new_witness(cs.clone(), || Ok(leaves[0])).unwrap();

		let res = path_var.check_membership(&root_var, &leaf_var, &hasher_gadget).unwrap();
		assert!(res.cs().is_satisfied().unwrap());
		assert!(res.value().unwrap());
	}

	#[test]
	fn should_verify_index() {
		let rng = &mut test_rng();
		let curve = Curve::Bls381;

		let params3 = setup_params_x5_3(curve);
		let hasher = Poseidon::<Fq> {
			params: params3,
		};

		let index = 2;
		let mut cs = ConstraintSystem::<Fq>::new_ref();
		let hasher_gadget = PoseidonGadget::from_native(&mut cs, hasher.clone());

		let leaves = vec![Fq::rand(rng), Fq::rand(rng), Fq::rand(rng)];
		let smt = SMT::new_sequential(&leaves, &hasher, &DEFAULT_LEAF).unwrap();
		let root = smt.root();
		let path = smt.generate_membership_proof(index);

		let path_var =
			PathVar::<_, SMTCRHGadget, HEIGHT>::new_witness(cs.clone(), || {
				Ok(path)
			})
			.unwrap();
		let root_var = FieldVar::new_witness(cs.clone(), || Ok(root)).unwrap();
		let leaf_var = FieldVar::new_witness(cs.clone(), || Ok(leaves[index as usize])).unwrap();

		let res = path_var.get_index(&root_var, &leaf_var, &hasher_gadget).unwrap();
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
		let curve = Curve::Bls381;

		let params3 = setup_params_x5_3(curve);
		let hasher = Poseidon::<Fq> {
			params: params3,
		};

		let index = 2;

		let mut cs = ConstraintSystem::<Fq>::new_ref();
		let hasher_gadget = PoseidonGadget::from_native(&mut cs, hasher.clone());

		let leaves = vec![Fq::rand(rng), Fq::rand(rng), Fq::rand(rng)];
		let smt = SMT::new_sequential(&leaves, &hasher, &DEFAULT_LEAF).unwrap();
		let path = smt.generate_membership_proof(index);

		// Now generate a bad root to make this fail:
		let bad_leaves = vec![Fq::rand(rng), Fq::rand(rng), Fq::rand(rng)];
		let bad_smt = SMT::new_sequential(&bad_leaves, &hasher, &DEFAULT_LEAF).unwrap();
		let bad_root = bad_smt.root();

		let path_var =
			PathVar::<_, SMTCRHGadget, HEIGHT>::new_witness(cs.clone(), || {
				Ok(path)
			})
			.unwrap();
		let bad_root_var = FieldVar::new_witness(cs.clone(), || Ok(bad_root)).unwrap();
		let leaf_var = FieldVar::new_witness(cs.clone(), || Ok(leaves[index as usize])).unwrap();

		let res = path_var.get_index(&bad_root_var, &leaf_var, &hasher_gadget).unwrap();
		let desired_res = Fq::from(index);

		assert!(res.cs().is_satisfied().unwrap());
		assert_eq!(res.value().unwrap(), desired_res);
	}
}
