use super::{Config, Node, Path};
use crate::Vec;
use ark_ff::PrimeField;
use ark_r1cs_std::{
	alloc::AllocVar, eq::EqGadget, prelude::*, select::CondSelectGadget, ToBytesGadget,
};
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::{borrow::Borrow, rc::Rc};
use webb_crypto_primitives::CRHGadget;

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
pub struct PathVar<F, P, HG, LHG>
where
	F: PrimeField,
	P: Config,
	HG: CRHGadget<P::H, F>,
	LHG: CRHGadget<P::LeafH, F>,
{
	path: Vec<(NodeVar<F, P, HG, LHG>, NodeVar<F, P, HG, LHG>)>,
	inner_params: Rc<HG::ParametersVar>,
	leaf_params: Rc<LHG::ParametersVar>,
}

impl<F, P, HG, LHG> PathVar<F, P, HG, LHG>
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

		root.is_eq(&previous_hash)
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

impl<F, P, HG, LHG> AllocVar<Path<P>, F> for PathVar<F, P, HG, LHG>
where
	F: PrimeField,
	P: Config,
	HG: CRHGadget<P::H, F>,
	LHG: CRHGadget<P::LeafH, F>,
{
	fn new_variable<T: Borrow<Path<P>>>(
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
			path,
			inner_params: Rc::new(inner_params_var),
			leaf_params: Rc::new(leaf_params_var),
		})
	}
}

#[cfg(test)]
mod test {
	use super::{NodeVar, PathVar};
	use crate::{
		ark_std::UniformRand,
		merkle_tree::{Config, SparseMerkleTree},
		test_data::{get_mds_3, get_rounds_3},
	};
	use ark_ed_on_bn254::Fq;
	use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, R1CSVar};
	use ark_relations::r1cs::ConstraintSystem;
	use ark_std::{rc::Rc, test_rng};
	use webb_crypto_primitives::crh::poseidon::{
		constraints::CRHGadget as PoseidonCRHGadget, sbox::PoseidonSbox, PoseidonParameters,
		Rounds, CRH as PoseidonCRH,
	};

	type FieldVar = FpVar<Fq>;

	#[derive(Default, Clone)]
	struct PoseidonRounds3;

	impl Rounds for PoseidonRounds3 {
		const FULL_ROUNDS: usize = 8;
		const PARTIAL_ROUNDS: usize = 57;
		const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
		const WIDTH: usize = 3;
	}

	type SMTCRH = PoseidonCRH<Fq, PoseidonRounds3>;
	type SMTCRHGadget = PoseidonCRHGadget<Fq, PoseidonRounds3>;

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
		let rounds3 = get_rounds_3::<Fq>();
		let mds3 = get_mds_3::<Fq>();
		let params3 = PoseidonParameters::<Fq>::new(rounds3, mds3);
		let inner_params = Rc::new(params3);
		let leaf_params = inner_params.clone();

		let cs = ConstraintSystem::<Fq>::new_ref();

		let leaves = vec![Fq::rand(rng), Fq::rand(rng), Fq::rand(rng)];
		let smt = SMT::new_sequential(inner_params, leaf_params, &leaves).unwrap();
		let root = smt.root();
		let path = smt.generate_membership_proof(0);

		let path_var = PathVar::new_witness(cs.clone(), || Ok(path)).unwrap();
		let root_var = SMTNode::new_witness(cs.clone(), || Ok(root)).unwrap();
		let leaf_var = FieldVar::new_witness(cs.clone(), || Ok(leaves[0])).unwrap();

		let res = path_var.check_membership(&root_var, &leaf_var).unwrap();
		assert!(res.value().unwrap());
	}
}
