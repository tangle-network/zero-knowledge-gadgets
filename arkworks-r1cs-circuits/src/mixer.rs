// This file is part of Webb.

// Copyright (C) 2021 Webb Technologies Inc.
// SPDX-License-Identifier: Apache-2.0

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

//! The Mixer is a fixed sized deposit/withdraw shielded pool.
//! This is the simplest circuit in arkworks-circuits.
//! It implements a on-chain mixer contract that allows for users to deposit
//! tokens using one wallet and withdraw using another one. This system uses
//! zero-knowledge proofs so no private information about the user gets leaked.
//!
//! Will take inputs and do a merkle tree reconstruction for each node in the
//! path to check if the reconstructed root matches current merkle root.
//!
//! This is the Groth16 setup implementation of the Mixer
use ark_ff::fields::PrimeField;
use ark_r1cs_std::{eq::EqGadget, fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use arkworks_native_gadgets::merkle_tree::Path;
use arkworks_r1cs_gadgets::{merkle_tree::PathVar, poseidon::FieldHasherGadget};

/// Defines a `MixerCircuit` struct that hold all the information thats needed
/// to verify the following statement:

/// * Alice knows a witness tuple `(secret, nullifier, merklePath)` and a
///   commitment `Hash(secret, nullifier)` that is stored in the merkle tree.
///
/// Needs to implement `ConstraintSynthesizer` and a
/// constructor to generate proper constraints
#[derive(Clone)]
pub struct MixerCircuit<F: PrimeField, HG: FieldHasherGadget<F>, const N: usize> {
	// Represents the hash of recepient + relayer + fee + refunds + commitment
	arbitrary_input: F,
	// Secret
	secret: F,
	// Nullifier to prevent double spending
	nullifier: F,
	// Merkle path to transaction
	path: Path<F, HG::Native, N>,
	// Merkle root with transaction in it
	root: F,
	// Nullifier hash to prevent double spending
	nullifier_hash: F,
	// Hasher to be used inside the circuit
	hasher: HG::Native,
}

/// Constructor for MixerCircuit
impl<F, HG, const N: usize> MixerCircuit<F, HG, N>
where
	F: PrimeField,
	HG: FieldHasherGadget<F>,
{
	pub fn new(
		arbitrary_input: F,
		secret: F,
		nullifier: F,
		path: Path<F, HG::Native, N>,
		root: F,
		nullifier_hash: F,
		hasher: HG::Native,
	) -> Self {
		Self {
			arbitrary_input,
			secret,
			nullifier,
			path,
			root,
			nullifier_hash,
			hasher,
		}
	}
}
/// Implementation of the `ConstraintSynthesizer` trait for the `MixerCircuit`
/// <https://github.com/arkworks-rs/snark/blob/master/relations/src/r1cs/constraint_system.rs>
///
/// This is the main function that is called by the `R1CS` library to generate
/// the constraints for the `AnchorCircuit`.
impl<F, HG, const N: usize> ConstraintSynthesizer<F> for MixerCircuit<F, HG, N>
where
	F: PrimeField,
	HG: FieldHasherGadget<F>,
{
	fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
		let arbitrary_input = self.arbitrary_input;
		let secret = self.secret;
		let nullifier = self.nullifier;
		let path = self.path;
		let root = self.root;
		let nullifier_hash = self.nullifier_hash;

		// Generating vars
		// Public inputs
		let nullifier_hash_var = FpVar::<F>::new_input(cs.clone(), || Ok(nullifier_hash))?;
		let root_var = FpVar::<F>::new_input(cs.clone(), || Ok(root))?;
		let arbitrary_input_var = FpVar::<F>::new_input(cs.clone(), || Ok(arbitrary_input))?;

		// Hashers
		let hasher: HG = FieldHasherGadget::<F>::from_native(&mut cs.clone(), self.hasher)?;

		// Private inputs
		let secret_var = FpVar::<F>::new_witness(cs.clone(), || Ok(secret))?;
		let nullifier_var = FpVar::<F>::new_witness(cs.clone(), || Ok(nullifier))?;
		let path_var = PathVar::<F, HG, N>::new_witness(cs.clone(), || Ok(path))?;

		// Creating the leaf and checking the membership inside the tree
		let mixer_leaf_hash: FpVar<F> = hasher.hash_two(&secret_var, &nullifier_var)?;
		let mixer_nullifier_hash = hasher.hash_two(&nullifier_var, &nullifier_var)?;

		let is_member = path_var.check_membership(&root_var, &mixer_leaf_hash, &hasher)?;
		// Constraining arbitrary inputs
		let _ = &arbitrary_input_var * &arbitrary_input_var;

		// Enforcing constraints
		is_member.enforce_equal(&Boolean::TRUE)?;
		mixer_nullifier_hash.enforce_equal(&nullifier_hash_var)?;

		Ok(())
	}
}
