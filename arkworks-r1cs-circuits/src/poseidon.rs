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

//! Poseidon hasher circuit to prove Hash(a, b) == c
//!
//! This is the Groth16 setup implementation of Poseidon
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use arkworks_r1cs_gadgets::poseidon::FieldHasherGadget;

#[derive(Copy)]
struct PoseidonCircuit<F: PrimeField, HG: FieldHasherGadget<F>> {
	pub a: F,
	pub b: F,
	pub c: F,
	hasher: HG::Native,
}

/// Constructor for PoseidonCircuit
#[allow(dead_code)]
impl<F: PrimeField, HG: FieldHasherGadget<F>> PoseidonCircuit<F, HG> {
	pub fn new(a: F, b: F, c: F, hasher: HG::Native) -> Self {
		Self { a, b, c, hasher }
	}
}

impl<F: PrimeField, HG: FieldHasherGadget<F>> Clone for PoseidonCircuit<F, HG> {
	fn clone(&self) -> Self {
		PoseidonCircuit {
			a: self.a,
			b: self.b,
			c: self.c,
			hasher: self.hasher.clone(),
		}
	}
}

/// Implementation of the `ConstraintSynthesizer` trait for the
/// `PoseidonCircuit` https://github.com/arkworks-rs/snark/blob/master/relations/src/r1cs/constraint_system.rs
///
/// This is the main function that is called by the `R1CS` library to generate
/// the constraints for the `PoseidonCircuit`.
impl<F: PrimeField, HG: FieldHasherGadget<F>> ConstraintSynthesizer<F> for PoseidonCircuit<F, HG> {
	fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
		let a = FpVar::new_witness(cs.clone(), || Ok(self.a))?;
		let b = FpVar::new_witness(cs.clone(), || Ok(self.b))?;
		let res_target = FpVar::<F>::new_input(cs.clone(), || Ok(&self.c))?;
		let hasher_gadget: HG = FieldHasherGadget::<F>::from_native(&mut cs.clone(), self.hasher)?;

		let res_var = hasher_gadget.hash(&[a, b])?;

		res_var.enforce_equal(&res_target)?;

		Ok(())
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use ark_bls12_381::{Bls12_381, Fr as BlsFr};
	use ark_crypto_primitives::SNARK;
	use ark_groth16::Groth16;
	use ark_marlin::Marlin;
	use ark_poly::univariate::DensePolynomial;
	use ark_poly_commit::marlin_pc::MarlinKZG10;
	use ark_std::UniformRand;
	use arkworks_native_gadgets::poseidon::{
		sbox::PoseidonSbox, FieldHasher, Poseidon, PoseidonParameters,
	};
	use arkworks_r1cs_gadgets::poseidon::PoseidonGadget;
	use arkworks_utils::{
		bytes_matrix_to_f, bytes_vec_to_f, poseidon_params::setup_poseidon_params, Curve,
	};
	use blake2::Blake2s;
	type PoseidonC = PoseidonCircuit<BlsFr, PoseidonGadget<BlsFr>>;

	pub fn setup_params<F: PrimeField>(curve: Curve, exp: i8, width: u8) -> PoseidonParameters<F> {
		let pos_data = setup_poseidon_params(curve, exp, width).unwrap();

		let mds_f = bytes_matrix_to_f(&pos_data.mds);
		let rounds_f = bytes_vec_to_f(&pos_data.rounds);

		let pos = PoseidonParameters {
			mds_matrix: mds_f,
			round_keys: rounds_f,
			full_rounds: pos_data.full_rounds,
			partial_rounds: pos_data.partial_rounds,
			sbox: PoseidonSbox(pos_data.exp),
			width: pos_data.width,
		};

		pos
	}

	#[test]
	fn should_verify_poseidon_circuit() {
		let rng = &mut ark_std::test_rng();
		let curve = Curve::Bls381;

		let a = BlsFr::rand(rng);
		let b = BlsFr::rand(rng);
		let parameters = setup_params(curve, 5, 3);
		let hasher = Poseidon::<BlsFr>::new(parameters);

		let c = hasher.hash(&[a, b]).unwrap();
		let nc = 3000;
		let nv = 2;
		let circuit = PoseidonC::new(a, b, c, hasher);

		type KZG10 = MarlinKZG10<Bls12_381, DensePolynomial<BlsFr>>;
		type MarlinSetup = Marlin<BlsFr, KZG10, Blake2s>;

		let srs = MarlinSetup::universal_setup(nc, nv, nv, rng).unwrap();
		let (pk, vk) = MarlinSetup::index(&srs, circuit.clone()).unwrap();
		let proof = MarlinSetup::prove(&pk, circuit, rng).unwrap();

		let res = MarlinSetup::verify(&vk, &vec![c], &proof, rng).unwrap();
		assert!(res);
	}

	#[test]
	fn should_verify_poseidon_circuit_groth16() {
		let rng = &mut ark_std::test_rng();
		let curve = Curve::Bls381;

		let a = BlsFr::rand(rng);
		let b = BlsFr::rand(rng);
		let parameters = setup_params(curve, 5, 3);
		let hasher = Poseidon::<BlsFr>::new(parameters);
		let c = hasher.hash(&[a, b]).unwrap();
		let circuit = PoseidonC::new(a, b, c, hasher);

		type GrothSetup = Groth16<Bls12_381>;

		let (pk, vk) = GrothSetup::circuit_specific_setup(circuit.clone(), rng).unwrap();
		let proof = GrothSetup::prove(&pk, circuit, rng).unwrap();

		let res = GrothSetup::verify(&vk, &vec![c], &proof).unwrap();
		assert!(res);
	}
}
