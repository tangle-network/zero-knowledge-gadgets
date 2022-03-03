//! Anchor is the fixed deposit/withdraw pool.
//! It allows for users to deposit tokens on one chain and withdraw in another
//! one without a link from the deposit to the withdrawal.

//! We wil take inputs and do a merkle tree reconstruction for each node in the
//! path and check if the reconstructed root is inside the current root set.
//!
//! This is the Groth16 setup implementation of Anchor
use ark_ff::fields::PrimeField;
use ark_r1cs_std::{eq::EqGadget, fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::vec::Vec;
use arkworks_gadgets::{
	merkle_tree::{simple_merkle::Path, simple_merkle_constraints::PathVar},
	poseidon::field_hasher_constraints::FieldHasherGadget,
	set::constraints::SetGadget,
};

/// Defines a AnchorCircuit struct that hold all the information thats needed to
/// verify the following statements:
/// * Alice knows a witness tuple (secret, nullifier, merklePath)
/// and a commitment Hash(chain_id, nullifier, secret) stored in one of the
/// Anchor merkle trees,
/// * The Anchor contract hasn't seen this nullifier_hash before.
///
/// Needs to implement ConstraintSynthesizer and a
/// constructor to generate proper constraints
#[derive(Clone)]
pub struct AnchorCircuit<F: PrimeField, HG: FieldHasherGadget<F>, const N: usize, const M: usize> {
	// Represents the hash of recepient + relayer + fee + refunds + commitment
	arbitrary_input: F,
	secret: F,
	nullifier: F,
	// source chain_id
	chain_id: F,
	// Merkle root set to use on one-of-many proof
	root_set: [F; M],
	// Merkle path to transaction
	path: Path<F, HG::Native, N>,
	nullifier_hash: F,
	// 3 input poseidon hasher
	hasher3: HG::Native,
	// 4 input poseidon hasher
	hasher4: HG::Native,
}

/// Constructor for a AnchorCiruit
impl<F, HG, const N: usize, const M: usize> AnchorCircuit<F, HG, N, M>
where
	F: PrimeField,
	HG: FieldHasherGadget<F>,
{
	#[allow(clippy::too_many_arguments)]
	pub fn new(
		arbitrary_input: F,
		secret: F,
		nullifier: F,
		chain_id: F,
		root_set: [F; M],
		path: Path<F, HG::Native, N>,
		nullifier_hash: F,
		hasher3: HG::Native,
		hasher4: HG::Native,
	) -> Self {
		Self {
			arbitrary_input,
			secret,
			nullifier,
			chain_id,
			root_set,
			path,
			nullifier_hash,
			hasher3,
			hasher4,
		}
	}
}

/// Implements R1CS constraint generation for AnchorCircuit
/// TODO add link to basic.rs for example implementation of
/// ConstraintSynthesizer
impl<F, HG, const N: usize, const M: usize> ConstraintSynthesizer<F> for AnchorCircuit<F, HG, N, M>
where
	F: PrimeField,
	HG: FieldHasherGadget<F>,
{
	fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
		let arbitrary_input = self.arbitrary_input;
		let secret = self.secret;
		let nullifier = self.nullifier;
		let chain_id = self.chain_id;
		let root_set = self.root_set;
		let path = self.path;
		let nullifier_hash = self.nullifier_hash;

		// Generating vars
		// Public inputs
		let chain_id_var = FpVar::<F>::new_input(cs.clone(), || Ok(chain_id))?;
		let nullifier_hash_var = FpVar::<F>::new_input(cs.clone(), || Ok(nullifier_hash))?;
		let roots_var = Vec::<FpVar<F>>::new_input(cs.clone(), || Ok(root_set))?;
		let arbitrary_input_var = FpVar::<F>::new_input(cs.clone(), || Ok(arbitrary_input))?;

		// Hashers
		let hasher3_gadget: HG =
			FieldHasherGadget::<F>::from_native(&mut cs.clone(), self.hasher3)?;
		let hasher4_gadget: HG =
			FieldHasherGadget::<F>::from_native(&mut cs.clone(), self.hasher4)?;

		// Private inputs
		let secret_var = FpVar::<F>::new_witness(cs.clone(), || Ok(secret))?;
		let nullifier_var = FpVar::<F>::new_witness(cs.clone(), || Ok(nullifier))?;
		let path_var = PathVar::<F, HG, N>::new_witness(cs.clone(), || Ok(path))?;

		// Creating the leaf and checking the membership inside the tree
		let anchor_leaf =
			hasher4_gadget.hash(&[chain_id_var, nullifier_var.clone(), secret_var])?;
		let anchor_nullifier = hasher3_gadget.hash_two(&nullifier_var, &nullifier_var)?;
		let root_var = path_var.root_hash(&anchor_leaf, &hasher3_gadget)?;
		// Check if target root is in set
		let set_gadget = SetGadget::new(roots_var);
		let is_set_member = set_gadget.check_membership(&root_var)?;
		// Constraining arbitrary inputs
		let _ = &arbitrary_input_var * &arbitrary_input_var;

		// Enforcing constraints
		is_set_member.enforce_equal(&Boolean::TRUE)?;
		anchor_nullifier.enforce_equal(&nullifier_hash_var)?;

		Ok(())
	}
}
