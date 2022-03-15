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

//! A Plonk gadget for the Poseidon hash function.
//! 
//! The Poseidon hash function is a cryptographic hash function which takes a vector
//! of elements of a prime field and outputs a single element of the same prime field.
//! For more information on the Poseidon hash function, see [the documentation for 
//! our native Poseidon implementation](Poseidon), or 
//! [the original Poseidon paper](https://eprint.iacr.org/2019/458.pdf).
//! 
//! [Plonk](https://eprint.iacr.org/2019/953.pdf) is a protocol for generating zk-SNARKs.  
//! A *gadget* translates a function's native implementation into a form that can be used 
//! by a *circuit*, which is ultimately used to create a zero-knowledge proof. For more 
//! information on gadgets and circuits, see 
//! [the README for the arkworks-gadgets repository](https://github.com/webb-tools/arkworks-gadgets#readme).
//! 
//! ## Usage
//! 
//! ```rust
//! fn should_verify_plonk_poseidon_x5_3() {
//!		let curve = Curve::Bn254;
//!
//!		// Get poseidon parameters for this curve:
//!		let util_params = setup_params(curve, 5, 3);
//!		let params = PoseidonParameters {
//!			round_keys: util_params.clone().round_keys,
//!			mds_matrix: util_params.clone().mds_matrix,
//!			full_rounds: util_params.clone().full_rounds,
//!			partial_rounds: util_params.clone().partial_rounds,
//!			sbox: PoseidonSbox(5),
//!			width: util_params.clone().width,
//!		};
//!		let poseidon_hasher = PoseidonHasher::new(params);
//!
//!		// Choose hash fn inputs and compute hash:
//!		let left = Fq::one();
//!		let right = Fq::one().double();
//!		let expected = poseidon_hasher.hash_two(&left, &right).unwrap();
//!
//!		// Create the circuit
//!		let mut test_circuit = TestCircuit::<Bn254Fr, JubjubParameters, PoseidonGadget> {
//!			left,
//!			right,
//!			expected,
//!			hasher: poseidon_hasher,
//!		};
//!
//!		let rng = &mut test_rng();
//!		let u_params: UniversalParams<Bn254> =
//!			SonicKZG10::<Bn254, DensePolynomial<Bn254Fr>>::setup(1 << 13, None, rng).unwrap();
//!
//!		let (pk, vd) = test_circuit
//!			.compile::<SonicKZG10<Bn254, DensePolynomial<Bn254Fr>>>(&u_params)
//!			.unwrap();
//!
//!		// PROVER
//!		let proof = test_circuit
//!			.gen_proof(&u_params, pk, b"Poseidon Test")
//!			.unwrap();
//!
//!		// VERIFIER
//!		let public_inputs: Vec<Bn254Fr> = vec![];
//!
//!		let VerifierData { key, pi_pos } = vd;
//!
//!		circuit::verify_proof::<_, JubjubParameters, _>(
//!			&u_params,
//!			key,
//!			&proof,
//!			&public_inputs,
//!			&pi_pos,
//!			b"Poseidon Test",
//!		)
//!		.unwrap();
//!	}
//! ```

use ark_ec::models::TEModelParameters;
use ark_ff::PrimeField;
use ark_std::{fmt::Debug, vec, vec::Vec};
use arkworks_native_gadgets::poseidon::{sbox::PoseidonSbox, FieldHasher, Poseidon};
use plonk_core::{constraint_system::StandardComposer, error::Error, prelude::Variable};

pub mod sbox;
use sbox::SboxConstraints;

#[derive(Debug, Default)]
pub struct PoseidonParametersVar {
	/// Round constants
	pub round_keys: Vec<Variable>,
	/// MDS matrix to apply in the mix layer.
	pub mds_matrix: Vec<Vec<Variable>>,
	/// Number of full rounds
	pub full_rounds: u8,
	/// Number of partial rounds
	pub partial_rounds: u8,
	/// Length of the input, in field elements, plus one zero element.
	pub width: u8,
	/// S-box to apply in the sub words layer.
	pub sbox: PoseidonSbox,
}

#[derive(Debug, Default)]
pub struct PoseidonGadget {
	pub params: PoseidonParametersVar,
}

pub trait FieldHasherGadget<F: PrimeField, P: TEModelParameters<BaseField = F>> {
	type Native: Debug + Clone + FieldHasher<F>;

	// For easy conversion from native version
	fn from_native(composer: &mut StandardComposer<F, P>, native: Self::Native) -> Self;
	fn hash(
		&self,
		composer: &mut StandardComposer<F, P>,
		inputs: &[Variable],
	) -> Result<Variable, Error>;
	fn hash_two(
		&self,
		composer: &mut StandardComposer<F, P>,
		left: &Variable,
		right: &Variable,
	) -> Result<Variable, Error>;
}

impl<F: PrimeField, P: TEModelParameters<BaseField = F>> FieldHasherGadget<F, P>
	for PoseidonGadget
{
	type Native = Poseidon<F>;

	/// Converts the native poseidon hash function to a Plonk gadget.
	fn from_native(composer: &mut StandardComposer<F, P>, native: Self::Native) -> Self {
		// Add native parameters to composer and store variables:
		let mut round_keys_var = vec![];
		for key in native.params.round_keys {
			round_keys_var.push(composer.add_witness_to_circuit_description(key));
		}
		let mut mds_matrix_var = vec![];
		for row in native.params.mds_matrix {
			let mut temp = vec![];
			for element in row {
				temp.push(composer.add_witness_to_circuit_description(element));
			}
			mds_matrix_var.push(temp);
		}

		let params_var = PoseidonParametersVar {
			round_keys: round_keys_var,
			mds_matrix: mds_matrix_var,
			full_rounds: native.params.full_rounds,
			partial_rounds: native.params.partial_rounds,
			width: native.params.width,
			sbox: native.params.sbox,
		};
		PoseidonGadget { params: params_var }
	}

	fn hash(
		&self,
		composer: &mut StandardComposer<F, P>,
		inputs: &[Variable],
	) -> Result<Variable, Error> {
		// Casting params to usize
		let width = self.params.width as usize;
		let partial_rounds = self.params.partial_rounds as usize;
		let full_rounds = self.params.full_rounds as usize;

		// TODO: This is not the appropriate error, should add new error
		if inputs.len() > width - 1 {
			return Err(Error::PointMalformed);
		}
		let mut state = vec![composer.zero_var()];
		for f in inputs {
			state.push(*f);
		}
		// Pads the input vector with zeroes if necessary.
		while state.len() < width {
			state.push(composer.zero_var());
		}

		// COMPUTE HASH
		let nr = full_rounds + partial_rounds;
		for r in 0..nr {
			// Adds round constants.
			state.iter_mut().enumerate().for_each(|(i, a)| {
				let c_temp = self.params.round_keys[(r * width + i)];
				*a = composer
					.arithmetic_gate(|gate| gate.witness(*a, c_temp, None).add(F::one(), F::one()));
			});

			let half_rounds = full_rounds / 2;
			// Applies the S-box to *all* entries of the state vector, for all full rounds.
			if r < half_rounds || r >= half_rounds + partial_rounds {
				state.iter_mut().try_for_each(|a| {
					self.params
						.sbox
						.synthesize_sbox(a, composer)
						.map(|f| *a = f)
				})?;
			} else {
				// Applies the S-box to the *first* entry of the state vector, for all partial rounds.
				state[0] = self.params.sbox.synthesize_sbox(&state[0], composer)?;
			}

			// Multiplies the state vector by the MDS matrix.
			state = state
				.iter()
				.enumerate()
				.map(|(i, _)| {
					state
						.iter()
						.enumerate()
						.fold(composer.zero_var(), |acc, (j, a)| {
							let m = &self.params.mds_matrix[i][j];

							let mul_result = composer
								.arithmetic_gate(|gate| gate.witness(*a, *m, None).mul(F::one()));

							let add_result = composer.arithmetic_gate(|gate| {
								gate.witness(acc, mul_result, None).add(F::one(), F::one())
							});

							add_result
						})
				})
				.collect();
		}

		let computed_hash = state.get(0).cloned().ok_or(Error::CircuitInputsNotFound)?;
		Ok(computed_hash)
	}

	fn hash_two(
		&self,
		composer: &mut StandardComposer<F, P>,
		left: &Variable,
		right: &Variable,
	) -> Result<Variable, Error> {
		self.hash(composer, &[*left, *right])
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use ark_bn254::{Bn254, Fr as Bn254Fr};
	use ark_ed_on_bn254::{EdwardsParameters as JubjubParameters, Fq};
	use ark_ff::Field;
	use ark_poly::polynomial::univariate::DensePolynomial;
	use ark_poly_commit::{kzg10::UniversalParams, sonic_pc::SonicKZG10, PolynomialCommitment};
	use ark_std::{test_rng, One};
	use arkworks_native_gadgets::poseidon::{sbox::PoseidonSbox, FieldHasher, PoseidonParameters};
	use arkworks_utils::{
		bytes_matrix_to_f, bytes_vec_to_f, poseidon_params::setup_poseidon_params, Curve,
	};
	use plonk_core::prelude::*;
	use plonk_hashing::poseidon::poseidon_ref::{NativeSpecRef, PoseidonRef};

	type PoseidonHasher = arkworks_native_gadgets::poseidon::Poseidon<Fq>;

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

	// Use it in a circuit
	struct TestCircuit<
		F: PrimeField,
		P: TEModelParameters<BaseField = F>,
		HG: FieldHasherGadget<F, P>,
	> {
		left: F,
		right: F,
		expected: F,
		hasher: HG::Native,
	}

	impl<F: PrimeField, P: TEModelParameters<BaseField = F>, HG: FieldHasherGadget<F, P>>
		Circuit<F, P> for TestCircuit<F, P, HG>
	{
		const CIRCUIT_ID: [u8; 32] = [0xff; 32];

		fn gadget(&mut self, composer: &mut StandardComposer<F, P>) -> Result<(), Error> {
			let hasher_gadget = HG::from_native(composer, self.hasher.clone());

			let left_var = composer.add_input(self.left);
			let right_var = composer.add_input(self.right);
			let expected_var = composer.add_input(self.expected);

			let outcome = hasher_gadget.hash_two(composer, &left_var, &right_var)?;
			composer.assert_equal(outcome, expected_var);
			Ok(())
		}

		fn padded_circuit_size(&self) -> usize {
			1 << 12
		}
	}
	#[test]
	fn should_verify_plonk_poseidon_x5_3() {
		let curve = Curve::Bn254;

		// Get poseidon parameters for this curve:
		let util_params = setup_params(curve, 5, 3);
		let params = PoseidonParameters {
			round_keys: util_params.clone().round_keys,
			mds_matrix: util_params.clone().mds_matrix,
			full_rounds: util_params.clone().full_rounds,
			partial_rounds: util_params.clone().partial_rounds,
			sbox: PoseidonSbox(5),
			width: util_params.clone().width,
		};
		let poseidon_hasher = PoseidonHasher::new(params);

		// Choose hash fn inputs and compute hash:
		let left = Fq::one();
		let right = Fq::one().double();
		let expected = poseidon_hasher.hash_two(&left, &right).unwrap();

		// Create the circuit
		let mut test_circuit = TestCircuit::<Bn254Fr, JubjubParameters, PoseidonGadget> {
			left,
			right,
			expected,
			hasher: poseidon_hasher,
		};

		let rng = &mut test_rng();
		let u_params: UniversalParams<Bn254> =
			SonicKZG10::<Bn254, DensePolynomial<Bn254Fr>>::setup(1 << 13, None, rng).unwrap();

		let (pk, vd) = test_circuit
			.compile::<SonicKZG10<Bn254, DensePolynomial<Bn254Fr>>>(&u_params)
			.unwrap();

		// PROVER
		let proof = test_circuit
			.gen_proof(&u_params, pk, b"Poseidon Test")
			.unwrap();

		// VERIFIER
		let public_inputs: Vec<Bn254Fr> = vec![];

		let VerifierData { key, pi_pos } = vd;

		circuit::verify_proof::<_, JubjubParameters, _>(
			&u_params,
			key,
			&proof,
			&public_inputs,
			&pi_pos,
			b"Poseidon Test",
		)
		.unwrap();
	}

	#[test]
	fn should_verify_against_zk_garage_non_optimized_poseidon() {
		let curve = Curve::Bn254;

		// Get poseidon parameters for this curve:
		let util_params = setup_params(curve, 5, 3);
		let params = PoseidonParameters {
			round_keys: util_params.clone().round_keys,
			mds_matrix: util_params.clone().mds_matrix,
			full_rounds: util_params.clone().full_rounds,
			partial_rounds: util_params.clone().partial_rounds,
			sbox: PoseidonSbox(5),
			width: util_params.clone().width,
		};
		let poseidon_hasher = PoseidonHasher::new(params);

		// Choose hash fn inputs and compute hash:
		let left = Fq::from(100);
		let right = Fq::from(100).double();
		let expected = poseidon_hasher.hash_two(&left, &right).unwrap();

		// ZK-Garage Poseidon implementation using non-optimized PoseidonRef
		use plonk_hashing::poseidon::{
			matrix::Matrix,
			mds::{factor_to_sparse_matrixes, MdsMatrices},
		};
		// Private method for now..
		// use plonk_hashing::poseidon::preprocessing::compress_round_constants;
		use plonk_hashing::poseidon::constants::PoseidonConstants;
		const ARITY: usize = 2;
		const WIDTH: usize = ARITY + 1;
		// Fill in Webb's Poseidon constants by hand
		let round_constants = util_params.round_keys.clone();
		// It is essential to transpose the matrix! Webb uses left matrix mult, this
		// implementation uses right !!!
		let mds_matrix = Matrix::from(util_params.mds_matrix).transpose();
		let domain_tag = Bn254Fr::from(0u32); // circom used 0 as the domain tag
		let full_rounds = 8usize;
		let half_full_rounds = 4usize;
		let partial_rounds = 57usize;
		let mds_matrices = MdsMatrices {
			m: mds_matrix.clone(),
			m_inv: Matrix::from(vec![]),
			m_hat: Matrix::from(vec![]),
			m_hat_inv: Matrix::from(vec![]),
			m_prime: Matrix::from(vec![]),
			m_double_prime: Matrix::from(vec![]),
		};
		// let compressed_round_constants = compress_round_constants(WIDTH, full_rounds,
		// partial_rounds, &round_constants, &mds_matrices);
		let (pre_sparse_matrix, sparse_matrixes) =
			factor_to_sparse_matrixes(mds_matrix, partial_rounds);

		// let constants = PoseidonConstants::generate::<WIDTH>();
		let constants = PoseidonConstants {
			mds_matrices,
			round_constants,
			domain_tag,
			full_rounds,
			half_full_rounds,
			partial_rounds,
			pre_sparse_matrix,
			sparse_matrixes,
			compressed_round_constants: vec![],
		};

		let inputs = [Bn254Fr::from(100u32), Bn254Fr::from(200u32)];

		let mut poseidon =
			PoseidonRef::<(), NativeSpecRef<Bn254Fr>, WIDTH>::new(&mut (), constants);

		inputs.iter().for_each(|x| {
			poseidon.input(*x).unwrap();
		});

		// let res: Vec<Fq> = parse_vec(vec![
		// 	"0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a",
		// ]);

		poseidon.output_hash(&mut ());
		let digest_actual = poseidon.elements;

		// Remember they are returning element 1 for some reason
		println!("expected {:?}, got {:?}", expected, digest_actual[0]);
		assert_eq!(expected, digest_actual[0]);
	}
}
