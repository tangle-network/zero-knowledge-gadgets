use core::convert::TryInto;

use super::{Config, Node, Path};
use crate::Vec;
use ark_crypto_primitives::CRHGadget;
use ark_ff::PrimeField;
use ark_r1cs_std::{
	alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, prelude::*, select::CondSelectGadget,
	ToBytesGadget,
};
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::{borrow::Borrow, rc::Rc};

#[derive(Debug)]
pub enum NodeVar<F, P, HG, LHG>
where
	F: PrimeField,
	P: Config,
	HG: CRHGadget<P::H, F>,
	LHG: CRHGadget<P::LeafH, F>,
{
	Leaf(LHG::OutputVar),
	Inner(HG::OutputVar),
}

impl<F, P, HG, LHG> Clone for NodeVar<F, P, HG, LHG>
where
	F: PrimeField,
	P: Config,
	HG: CRHGadget<P::H, F>,
	LHG: CRHGadget<P::LeafH, F>,
{
	fn clone(&self) -> Self {
		match self {
			NodeVar::Inner(inner) => NodeVar::Inner(inner.clone()),
			NodeVar::Leaf(leaf) => NodeVar::Leaf(leaf.clone()),
		}
	}
}

impl<F, P, HG, LHG> CondSelectGadget<F> for NodeVar<F, P, HG, LHG>
where
	F: PrimeField,
	P: Config,
	HG: CRHGadget<P::H, F>,
	LHG: CRHGadget<P::LeafH, F>,
{
	fn conditionally_select(
		cond: &Boolean<F>,
		true_value: &Self,
		false_value: &Self,
	) -> Result<Self, SynthesisError> {
		match (true_value, false_value) {
			(NodeVar::Inner(in1), NodeVar::Inner(in2)) => Ok(NodeVar::Inner(
				HG::OutputVar::conditionally_select(cond, in1, in2)?,
			)),
			(NodeVar::Leaf(l1), NodeVar::Leaf(l2)) => Ok(NodeVar::Leaf(
				LHG::OutputVar::conditionally_select(cond, l1, l2)?,
			)),
			_ => Err(SynthesisError::Unsatisfiable),
		}
	}
}

impl<F, P, HG, LHG> EqGadget<F> for NodeVar<F, P, HG, LHG>
where
	F: PrimeField,
	P: Config,
	HG: CRHGadget<P::H, F>,
	LHG: CRHGadget<P::LeafH, F>,
{
	fn is_eq(&self, other: &Self) -> Result<Boolean<F>, SynthesisError> {
		match (self, other) {
			(NodeVar::Leaf(l1), NodeVar::Leaf(l2)) => l1.is_eq(l2),
			(NodeVar::Inner(in1), NodeVar::Inner(in2)) => in1.is_eq(in2),
			_ => Ok(Boolean::FALSE),
		}
	}
}

impl<F, P, HG, LHG> ToBytesGadget<F> for NodeVar<F, P, HG, LHG>
where
	F: PrimeField,
	P: Config,
	HG: CRHGadget<P::H, F>,
	LHG: CRHGadget<P::LeafH, F>,
{
	fn to_bytes(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
		match self {
			NodeVar::Inner(inner) => inner.to_bytes(),
			NodeVar::Leaf(leaf) => leaf.to_bytes(),
		}
	}
}

impl<F, P, HG, LHG> AllocVar<Node<P>, F> for NodeVar<F, P, HG, LHG>
where
	F: PrimeField,
	P: Config,
	HG: CRHGadget<P::H, F>,
	LHG: CRHGadget<P::LeafH, F>,
{
	fn new_variable<T: Borrow<Node<P>>>(
		cs: impl Into<Namespace<F>>,
		f: impl FnOnce() -> Result<T, SynthesisError>,
		mode: AllocationMode,
	) -> Result<Self, SynthesisError> {
		let node = f()?.borrow().clone();
		let node_var = match node {
			Node::Leaf(leaf) => NodeVar::Leaf(LHG::OutputVar::new_variable(cs, || Ok(leaf), mode)?),
			Node::Inner(inner) => {
				NodeVar::Inner(HG::OutputVar::new_variable(cs, || Ok(inner), mode)?)
			}
		};
		Ok(node_var)
	}
}

/// Gadgets for one Merkle tree path
#[derive(Debug)]
pub struct PathVar<F, P, HG, LHG, const N: usize>
where
	F: PrimeField,
	P: Config,
	HG: CRHGadget<P::H, F>,
	LHG: CRHGadget<P::LeafH, F>,
{
	path: [(NodeVar<F, P, HG, LHG>, NodeVar<F, P, HG, LHG>); N],
	inner_params: Rc<HG::ParametersVar>,
	leaf_params: Rc<LHG::ParametersVar>,
}

impl<F, P, HG, LHG, const N: usize> PathVar<F, P, HG, LHG, N>
where
	F: PrimeField,
	P: Config,
	HG: CRHGadget<P::H, F>,
	LHG: CRHGadget<P::LeafH, F>,
{
	/// conditionally check a lookup proof (does not enforce index consistency)
	pub fn check_membership<L: ToBytesGadget<F>>(
		&self,
		root: &NodeVar<F, P, HG, LHG>,
		leaf: L,
	) -> Result<Boolean<F>, SynthesisError> {
		let computed_root = self.root_hash(&leaf)?;

		root.is_eq(&computed_root)
	}

	pub fn root_hash<L: ToBytesGadget<F>>(
		&self,
		leaf: &L,
	) -> Result<NodeVar<F, P, HG, LHG>, SynthesisError> {
		assert_eq!(self.path.len(), P::HEIGHT as usize);
		// Check that the hash of the given leaf matches the leaf hash in the membership
		// proof.
		let leaf_hash = hash_leaf_gadget::<F, P, HG, LHG, L>(self.leaf_params.borrow(), &leaf)?;

		// Check if leaf is one of the bottom-most siblings.
		let leaf_is_left = leaf_hash.is_eq(&self.path[0].0)?;

		leaf_hash.enforce_equal(&NodeVar::conditionally_select(
			&leaf_is_left,
			&self.path[0].0,
			&self.path[0].1,
		)?)?;

		// Check levels between leaf level and root.
		let mut previous_hash = leaf_hash;
		for &(ref left_hash, ref right_hash) in self.path.iter() {
			// Check if the previous_hash matches the correct current hash.
			let previous_is_left = previous_hash.is_eq(&left_hash)?;

			previous_hash.enforce_equal(&NodeVar::conditionally_select(
				&previous_is_left,
				left_hash,
				right_hash,
			)?)?;

			previous_hash = hash_inner_node_gadget::<F, P, HG, LHG>(
				self.inner_params.borrow(),
				left_hash,
				right_hash,
			)?;
		}

		Ok(previous_hash)
	}

	pub fn get_index<L: ToBytesGadget<F>>(
		&self,
		root: &NodeVar<F, P, HG, LHG>,
		leaf: L,
	) -> Result<FpVar<F>, SynthesisError> {
		// First, check if the provided leaf is on the path
		let isonpath = self.check_membership(root, &leaf);
		isonpath.unwrap().enforce_equal(&Boolean::TRUE)?;

		let mut index = FpVar::<F>::zero();
		let mut twopower = FpVar::<F>::one();
		let mut rightvalue: FpVar<F>;

		//Compute the hash of the provided leaf
		let leaf_hash = hash_leaf_gadget::<F, P, HG, LHG, L>(self.leaf_params.borrow(), &leaf)?;

		// Check levels between leaf level and root.
		let mut previous_hash = leaf_hash;
		for &(ref left_hash, ref right_hash) in self.path.iter() {
			// Check if the previous_hash is for a left node.
			let previous_is_left = previous_hash.is_eq(&left_hash)?;

			rightvalue = index.clone() + twopower.clone();
			index = FpVar::<F>::conditionally_select(&previous_is_left, &index, &rightvalue)?;
			twopower = twopower.clone() + twopower.clone();

			previous_hash = hash_inner_node_gadget::<F, P, HG, LHG>(
				self.inner_params.borrow(),
				left_hash,
				right_hash,
			)?;
		}

		Ok(index)
	}
}

pub(crate) fn hash_leaf_gadget<F, P, HG, LHG, L>(
	leaf_params: &LHG::ParametersVar,
	leaf: &L,
) -> Result<NodeVar<F, P, HG, LHG>, SynthesisError>
where
	F: PrimeField,
	P: Config,
	L: ToBytesGadget<F>,
	HG: CRHGadget<P::H, F>,
	LHG: CRHGadget<P::LeafH, F>,
{
	Ok(NodeVar::Leaf(LHG::evaluate(
		&leaf_params,
		&leaf.to_bytes()?,
	)?))
}

pub(crate) fn hash_inner_node_gadget<F, P, HG, LHG>(
	inner_params: &HG::ParametersVar,
	left_child: &NodeVar<F, P, HG, LHG>,
	right_child: &NodeVar<F, P, HG, LHG>,
) -> Result<NodeVar<F, P, HG, LHG>, SynthesisError>
where
	F: PrimeField,
	P: Config,
	HG: CRHGadget<P::H, F>,
	LHG: CRHGadget<P::LeafH, F>,
{
	let mut bytes = Vec::new();
	bytes.extend(left_child.to_bytes()?);
	bytes.extend(right_child.to_bytes()?);
	let res = HG::evaluate(inner_params, &bytes)?;
	Ok(NodeVar::Inner(res))
}

impl<F, P, HG, LHG, const N: usize> AllocVar<Path<P, N>, F> for PathVar<F, P, HG, LHG, N>
where
	F: PrimeField,
	P: Config,
	HG: CRHGadget<P::H, F>,
	LHG: CRHGadget<P::LeafH, F>,
{
	fn new_variable<T: Borrow<Path<P, N>>>(
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
				NodeVar::new_variable(ark_relations::ns!(cs, "l_child"), || Ok(l.clone()), mode)?;
			let r_hash =
				NodeVar::new_variable(ark_relations::ns!(cs, "r_child"), || Ok(r.clone()), mode)?;
			path.push((l_hash, r_hash));
		}

		let inner_params_var = HG::ParametersVar::new_input(cs.clone(), || {
			Ok(path_obj.borrow().inner_params.borrow())
		})?;
		let leaf_params_var =
			LHG::ParametersVar::new_input(cs, || Ok(path_obj.borrow().leaf_params.borrow()))?;

		Ok(PathVar {
			path: path.try_into().unwrap_or_else(
				|v: Vec<(NodeVar<F, P, HG, LHG>, NodeVar<F, P, HG, LHG>)>| {
					panic!("Expected a Vec of length {} but it was {}", N, v.len())
				},
			),
			inner_params: Rc::new(inner_params_var),
			leaf_params: Rc::new(leaf_params_var),
		})
	}
}

#[cfg(feature = "default_poseidon")]
#[cfg(test)]
mod test {
	use super::{NodeVar, PathVar};
	use crate::{ark_std::UniformRand, merkle_tree::{Config, SparseMerkleTree}, poseidon::{
			constraints::CRHGadget as PoseidonCRHGadget, CRH as PoseidonCRH,
		}, setup::common::{Curve, setup_params_x5_3}};
	use ark_bls12_381::Fq;
	use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, R1CSVar};
	use ark_relations::r1cs::ConstraintSystem;
	use ark_std::{rc::Rc, test_rng};

	use crate::merkle_tree::Path;

	type FieldVar = FpVar<Fq>;

	type SMTCRH = PoseidonCRH<Fq>;
	type SMTCRHGadget = PoseidonCRHGadget<Fq>;

	#[derive(Clone, Debug, Eq, PartialEq)]
	struct SMTConfig;
	impl Config for SMTConfig {
		type H = SMTCRH;
		type LeafH = SMTCRH;

		const HEIGHT: u8 = 3;
	}

	type SMTNode = NodeVar<Fq, SMTConfig, SMTCRHGadget, SMTCRHGadget>;
	type SMT = SparseMerkleTree<SMTConfig>;

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
