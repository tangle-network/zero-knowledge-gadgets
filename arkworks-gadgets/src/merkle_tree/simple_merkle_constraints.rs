use core::convert::TryInto;
use std::marker::PhantomData;

use super::{simple_merkle::Path};
use crate::{Vec, poseidon::{field_hasher_constraints::FieldHasherGadget, field_hasher::FieldHasher}};
use ark_ff::PrimeField;
use ark_r1cs_std::{
	alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, prelude::*, select::CondSelectGadget,
};
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::{borrow::Borrow, rc::Rc};

/// Gadgets for one Merkle tree path
#[derive(Debug)]
pub struct PathVar<F, HG, LHG, const N: usize>
where
	F: PrimeField,
	HG: FieldHasherGadget<F>,
	LHG: FieldHasherGadget<F>,
{
	#[allow(clippy::type_complexity)]
	path: [(FpVar<F>, FpVar<F>); N],
    phantom: PhantomData<(HG, LHG)>,
}

impl<F, HG, LHG, const N: usize> PathVar<F, HG, LHG, N>
where
	F: PrimeField,
	HG: FieldHasherGadget<F>,
	LHG: FieldHasherGadget<F>,
{
	/// conditionally check a lookup proof (does not enforce index consistency)
	pub fn check_membership(
		&self,
		root: &FpVar<F>,
		leaf: FpVar<F>,
        hasher: &HG,
	) -> Result<Boolean<F>, SynthesisError> {
		let computed_root = self.root_hash(leaf, hasher)?;

		root.is_eq(&computed_root)
	}

	pub fn root_hash(
		&self,
		leaf: FpVar<F>,
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
		let mut previous_hash = leaf;
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
		leaf: FpVar<F>,
        hasher: &HG,
	) -> Result<FpVar<F>, SynthesisError> {
        let mut cs = leaf.cs();
		let mut index = FpVar::<F>::zero();
		let mut twopower = FpVar::<F>::one();
		let mut rightvalue: FpVar<F>;

		// Check levels between leaf level and root.
		let mut previous_hash = leaf;
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

impl<F, H, HG, LHG, const N: usize> AllocVar<Path<F, H, N>, F> for PathVar<F, HG, LHG, N>
where
	F: PrimeField,
    H: FieldHasher<F>,
	HG: FieldHasherGadget<F>,
	LHG: FieldHasherGadget<F>,
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
		poseidon::{constraints::CRHGadget as PoseidonCRHGadget, CRH as PoseidonCRH, field_hasher::FieldHasher, field_hasher_constraints::{FieldHasherGadget, PoseidonGadget}},
	};

	use ark_ed_on_bn254::Fq;
	use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, R1CSVar};
	use ark_relations::r1cs::ConstraintSystem;
	use ark_std::{rc::Rc, test_rng};
	use arkworks_utils::utils::common::{setup_params_x5_3, Curve};

	type FieldVar = FpVar<Fq>;

	type SMTCRH = FieldHasher<Fq>;
	type SMTCRHGadget = PoseidonGadget<Fq>;


    const HEIGHT: usize = 30;
	type SMT = SparseMerkleTree<Fq, SMTCRH, HEIGHT>;

	#[test]
	fn should_verify_path() {
		let rng = &mut test_rng();
		let curve = Curve::Bls381;

		let params3 = setup_params_x5_3(curve);

		let inner_params = Rc::new(params3);
		let leaf_params = inner_params.clone();

		let cs = ConstraintSystem::<Fq>::new_ref();

		let leaves = vec![Fq::rand(rng), Fq::rand(rng), Fq::rand(rng)];
		let smt = SMT::new_sequential(inner_params, leaf_params, &leaves).unwrap();
		let root = smt.root();
		let path = smt.generate_membership_proof(0);

		let path_var =
			PathVar::<_, _, _, _, { SMTConfig::HEIGHT as usize }>::new_witness(cs.clone(), || {
				Ok(path)
			})
			.unwrap();
		let root_var = SMTNode::new_witness(cs.clone(), || Ok(root)).unwrap();
		let leaf_var = FieldVar::new_witness(cs.clone(), || Ok(leaves[0])).unwrap();

		let res = path_var.check_membership(&root_var, &leaf_var).unwrap();
		assert!(res.cs().is_satisfied().unwrap());
		assert!(res.value().unwrap());
	}

	#[test]
	fn should_verify_index() {
		let rng = &mut test_rng();
		let curve = Curve::Bls381;

		let params3 = setup_params_x5_3(curve);

		let inner_params = Rc::new(params3);
		let leaf_params = inner_params.clone();
		let index = 2;
		let cs = ConstraintSystem::<Fq>::new_ref();

		let leaves = vec![Fq::rand(rng), Fq::rand(rng), Fq::rand(rng)];
		let smt = SMT::new_sequential(inner_params, leaf_params, &leaves).unwrap();
		let root = smt.root();
		let path = smt.generate_membership_proof(index);

		let path_var =
			PathVar::<_, _, _, _, { SMTConfig::HEIGHT as usize }>::new_witness(cs.clone(), || {
				Ok(path)
			})
			.unwrap();
		let root_var = SMTNode::new_witness(cs.clone(), || Ok(root)).unwrap();
		let leaf_var = FieldVar::new_witness(cs.clone(), || Ok(leaves[index as usize])).unwrap();

		let res = path_var.get_index(&root_var, &leaf_var).unwrap();
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

		let inner_params = Rc::new(params3);
		let leaf_params = inner_params.clone();
		let index = 2;
		let cs = ConstraintSystem::<Fq>::new_ref();

		let leaves = vec![Fq::rand(rng), Fq::rand(rng), Fq::rand(rng)];
		let smt = SMT::new_sequential(inner_params.clone(), leaf_params.clone(), &leaves).unwrap();
		let path = smt.generate_membership_proof(index);

		// Now generate a bad root to make this fail:
		let bad_leaves = vec![Fq::rand(rng), Fq::rand(rng), Fq::rand(rng)];
		let bad_smt = SMT::new_sequential(inner_params, leaf_params, &bad_leaves).unwrap();
		let bad_root = bad_smt.root();

		let path_var =
			PathVar::<_, _, _, _, { SMTConfig::HEIGHT as usize }>::new_witness(cs.clone(), || {
				Ok(path)
			})
			.unwrap();
		let bad_root_var = SMTNode::new_witness(cs.clone(), || Ok(bad_root)).unwrap();
		let leaf_var = FieldVar::new_witness(cs.clone(), || Ok(leaves[index as usize])).unwrap();

		let res = path_var.get_index(&bad_root_var, &leaf_var).unwrap();
		let desired_res = Fq::from(index);

		assert!(res.cs().is_satisfied().unwrap());
		assert_eq!(res.value().unwrap(), desired_res);
	}

	#[should_panic(expected = "Expected a Vec of length 2 but it was 3")]
	#[test]
	fn should_fail_path_creation_with_invalid_size() {
		let rng = &mut test_rng();
		let curve = Curve::Bls381;

		let params3 = setup_params_x5_3(curve);

		let inner_params = Rc::new(params3);
		let leaf_params = inner_params.clone();

		let cs = ConstraintSystem::<Fq>::new_ref();

		let leaves = vec![Fq::rand(rng), Fq::rand(rng), Fq::rand(rng)];
		let smt = SMT::new_sequential(inner_params, leaf_params, &leaves).unwrap();
		let root = smt.root();
		let path = smt.generate_membership_proof(0);

		// pass a size one less than tree HEIGHT
		// should panic here
		let path_var = PathVar::<_, _, _, _, { (SMTConfig::HEIGHT - 1) as usize }>::new_witness(
			cs.clone(),
			|| Ok(path),
		)
		.unwrap();
		let root_var = SMTNode::new_witness(cs.clone(), || Ok(root)).unwrap();
		let leaf_var = FieldVar::new_witness(cs.clone(), || Ok(leaves[0])).unwrap();

		let res = path_var.check_membership(&root_var, &leaf_var).unwrap();
		assert!(res.cs().is_satisfied().unwrap());
		assert!(res.value().unwrap());
	}

	#[should_panic(expected = "assertion failed: `(left == right)`
  left: `2`,
 right: `3`")]
	#[test]
	fn should_fail_membership_with_invalid_size() {
		let rng = &mut test_rng();
		let curve = Curve::Bls381;

		let params3 = setup_params_x5_3(curve);

		let inner_params = Rc::new(params3);
		let leaf_params = inner_params.clone();

		let cs = ConstraintSystem::<Fq>::new_ref();

		let leaves = vec![Fq::rand(rng), Fq::rand(rng), Fq::rand(rng)];
		let smt = SMT::new_sequential(inner_params.clone(), leaf_params.clone(), &leaves).unwrap();
		let root = smt.root();
		let path: Path<SMTConfig, { (SMTConfig::HEIGHT) as usize }> =
			smt.generate_membership_proof(0);

		let new_path = Path::<SMTConfig, { (SMTConfig::HEIGHT - 1) as usize }> {
			path: [path.path[0].clone(), path.path[1].clone()],
			inner_params: inner_params.clone(),
			leaf_params,
		};

		let path_var = PathVar::<_, _, _, _, { (SMTConfig::HEIGHT - 1) as usize }>::new_witness(
			cs.clone(),
			|| Ok(new_path),
		)
		.unwrap();
		let root_var = SMTNode::new_witness(cs.clone(), || Ok(root)).unwrap();
		let leaf_var = FieldVar::new_witness(cs.clone(), || Ok(leaves[0])).unwrap();

		let res = path_var.check_membership(&root_var, &leaf_var).unwrap();
		assert!(res.cs().is_satisfied().unwrap());
		assert!(res.value().unwrap());
	}
}
