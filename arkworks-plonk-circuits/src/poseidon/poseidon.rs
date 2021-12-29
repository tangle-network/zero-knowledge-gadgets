// use std::arch::aarch64::ST; // What was this?
use ark_std::fmt::Debug;

// use ark_crypto_primitives::crh::poseidon::Poseidon;
use ark_ec::{models::TEModelParameters, PairingEngine};
use ark_ff::PrimeField;
use ark_plonk::{
	circuit::Circuit, constraint_system::StandardComposer, error::Error, prelude::Variable,
};
use ark_std::{marker::PhantomData, vec::Vec, One, Zero};
use arkworks_gadgets::poseidon::field_hasher::Poseidon;

use crate::poseidon::sbox::{PoseidonSbox, SboxConstraints};

#[derive(Debug, Default)]
pub struct PoseidonParametersVar {
	/// The round key constants
	pub round_keys: Vec<Variable>,
	/// The MDS matrix to apply in the mix layer.
	pub mds_matrix: Vec<Vec<Variable>>,
	/// Number of full SBox rounds
	pub full_rounds: u8,
	/// Number of partial rounds
	pub partial_rounds: u8,
	/// The size of the permutation, in field elements.
	pub width: u8,
	/// The S-box to apply in the sub words layer.
	pub sbox: PoseidonSbox,
}

#[derive(Debug, Default)]
struct PoseidonGadget<E: PairingEngine, P: TEModelParameters<BaseField = E::Fr>> {
	pub params: PoseidonParametersVar,
	pub _engine: PhantomData<E>,
	pub _marker: PhantomData<P>,
}

trait FieldHasherGadget<F: PrimeField, E: PairingEngine, P: TEModelParameters<BaseField = E::Fr>> {
	type Native: Clone; //should I derive Debug somewhere upstream?
					// For easy conversion from native version
	fn from_native(composer: &mut StandardComposer<E, P>, native: Self::Native) -> Self;
	fn hash(
		&self,
		composer: &mut StandardComposer<E, P>,
		inputs: &[Variable],
	) -> Result<Variable, Error>;
	fn hash_two(
		&self,
		composer: &mut StandardComposer<E, P>,
		left: &Variable,
		right: &Variable,
	) -> Result<Variable, Error>;
}

impl<E: PairingEngine, P: TEModelParameters<BaseField = E::Fr>> FieldHasherGadget<E::Fr, E, P>
	for PoseidonGadget<E, P>
{
	type Native = Poseidon<E::Fr>;

	fn from_native(composer: &mut StandardComposer<E, P>, native: Self::Native) -> Self {
		// Add native parameters to composer and store variables:
		let mut round_keys_var = vec![];
		for key in native.params.round_keys {
			round_keys_var.push(composer.add_input(key));
		}
		let mut mds_matrix_var = vec![];
		for row in native.params.mds_matrix {
			let mut temp = vec![];
			for element in row {
				temp.push(composer.add_input(element));
			}
			mds_matrix_var.push(temp);
		}

		let sbox_gadget = PoseidonSbox::Exponentiation(native.params.sbox.0 as usize);

		let params_var = PoseidonParametersVar {
			round_keys: round_keys_var,
			mds_matrix: mds_matrix_var,
			full_rounds: native.params.full_rounds,
			partial_rounds: native.params.partial_rounds,
			width: native.params.width,
			sbox: sbox_gadget,
		};
		PoseidonGadget {
			params: params_var,
			_engine: PhantomData,
			_marker: PhantomData,
		}
	}

	fn hash(
		&self,
		composer: &mut StandardComposer<E, P>,
		inputs: &[Variable],
	) -> Result<Variable, Error> {
		// Casting params to usize
		let width = self.params.width as usize;
		let partial_rounds = self.params.partial_rounds as usize;
		let full_rounds = self.params.full_rounds as usize;

		if inputs.len() > width - 1 {
			return Err(Error::PointMalformed);
		}
		let mut state = vec![composer.zero_var()];
		for f in inputs {
			state.push(*f);
		}
		while state.len() < width {
			state.push(composer.zero_var());
		}

		// COMPUTE HASH
		let nr = full_rounds + partial_rounds;
		for r in 0..nr {
			state.iter_mut().enumerate().for_each(|(i, a)| {
				let c_temp = self.params.round_keys[(r * width + i)];
				*a = composer.arithmetic_gate(|gate| {
					gate.witness(*a, c_temp, None)
						.add(E::Fr::one(), E::Fr::one())
				});
			});

			let half_rounds = full_rounds / 2;
			if r < half_rounds || r >= half_rounds + partial_rounds {
				state.iter_mut().try_for_each(|a| {
					self.params
						.sbox
						.synthesize_sbox(a, composer)
						.map(|f| *a = f)
				})?;
			} else {
				state[0] = self.params.sbox.synthesize_sbox(&state[0], composer)?;
			}

			state = state
				.iter()
				.enumerate()
				.map(|(i, _)| {
					state
						.iter()
						.enumerate()
						.fold(composer.zero_var(), |acc, (j, a)| {
							let m = &self.params.mds_matrix[i][j];

							let mul_result = composer.arithmetic_gate(|gate| {
								gate.witness(*a, *m, None).mul(E::Fr::one())
							});

							let add_result = composer.arithmetic_gate(|gate| {
								gate.witness(acc, mul_result, None)
									.add(E::Fr::one(), E::Fr::one())
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
		composer: &mut StandardComposer<E, P>,
		left: &Variable,
		right: &Variable,
	) -> Result<Variable, Error> {
		self.hash(composer, &[*left, *right])
	}
}

// Practice using it in a circuit
struct TestCircuit<
	E: PairingEngine,
	P: TEModelParameters<BaseField = E::Fr>,
	HG: FieldHasherGadget<E::Fr, E, P>,
> {
	left: E::Fr,
	right: E::Fr,
	expected: E::Fr,
	hasher: HG::Native,
}

impl<
		E: PairingEngine,
		P: TEModelParameters<BaseField = E::Fr>,
		HG: FieldHasherGadget<E::Fr, E, P>,
	> Circuit<E, P> for TestCircuit<E, P, HG>
{
	const CIRCUIT_ID: [u8; 32] = [0xff; 32];

	fn gadget(&mut self, composer: &mut StandardComposer<E, P>) -> Result<(), Error> {
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

#[cfg(test)]
mod tests {
	use super::*;
	use ark_bn254::{Bn254, Fr as Bn254Fr};
	use ark_ed_on_bn254::{EdwardsParameters as JubjubParameters, Fq};
	use ark_ff::{BigInteger, Field};
	use ark_plonk::{
		circuit::{self, FeIntoPubInput},
		prelude::*,
		proof_system::{Prover, Verifier},
	};
	use ark_poly::polynomial::univariate::DensePolynomial;
	use ark_poly_commit::{
		kzg10::{self, Powers, UniversalParams, KZG10},
		sonic_pc::SonicKZG10,
		PolynomialCommitment,
	};
	use ark_std::{test_rng, One};
	use arkworks_gadgets::poseidon::field_hasher::FieldHasher;
	use arkworks_utils::{
		poseidon::{sbox::PoseidonSbox as UtilsPoseidonSbox, PoseidonParameters},
		utils::common::setup_params_x5_3,
	};

	type PoseidonHasher = arkworks_gadgets::poseidon::field_hasher::Poseidon<Fq>;
	type PoseidonHasherGadget = PoseidonGadget<Bn254, JubjubParameters>;

	#[test]
	fn should_verify_plonk_poseidon_x5_3() {
		let curve = arkworks_utils::utils::common::Curve::Bn254;

		// Get poseidon parameters for this curve:
		let util_params = setup_params_x5_3(curve);
		let params = PoseidonParameters {
			round_keys: util_params.clone().round_keys,
			mds_matrix: util_params.clone().mds_matrix,
			full_rounds: util_params.clone().full_rounds,
			partial_rounds: util_params.clone().partial_rounds,
			sbox: UtilsPoseidonSbox(5),
			width: util_params.clone().width,
		};
		let poseidon_hasher = PoseidonHasher::new(params);

		// Choose hash fn inputs and compute hash:
		let left = Fq::one();
		let right = Fq::one().double();
		let expected = poseidon_hasher.hash_two(&left, &right).unwrap();

		// Create the circuit
		let mut test_circuit = TestCircuit::<Bn254, JubjubParameters, PoseidonHasherGadget> {
			left,
			right,
			expected,
			hasher: poseidon_hasher,
		};

		let rng = &mut test_rng();
		let u_params: UniversalParams<Bn254> =
			KZG10::<Bn254, DensePolynomial<Bn254Fr>>::setup(1 << 12, false, rng).unwrap();

		let (pk, vd) = test_circuit.compile(&u_params).unwrap();

		// PROVER
		let proof = {
			// Get poseidon parameters for this curve:
			let util_params = setup_params_x5_3(curve);
			let params = PoseidonParameters {
				round_keys: util_params.clone().round_keys,
				mds_matrix: util_params.clone().mds_matrix,
				full_rounds: util_params.clone().full_rounds,
				partial_rounds: util_params.clone().partial_rounds,
				sbox: UtilsPoseidonSbox(5),
				width: util_params.clone().width,
			};
			let poseidon_hasher = PoseidonHasher::new(params);

			// Choose hash fn inputs and compute hash:
			let left = Fq::one();
			let right = Fq::one().double();
			let expected = poseidon_hasher.hash_two(&left, &right).unwrap();

			// Create the circuit
			let mut test_circuit = TestCircuit::<Bn254, JubjubParameters, PoseidonHasherGadget> {
				left,
				right,
				expected,
				hasher: poseidon_hasher,
			};
			test_circuit
				.gen_proof(&u_params, pk, b"Poseidon Test")
				.unwrap()
		};

		// VERIFIER
		let public_inputs: Vec<PublicInputValue<JubjubParameters>> = vec![expected.into_pi()];

		let VerifierData { key, pi_pos } = vd;

		circuit::verify_proof(
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
	fn should_verify_plonk_poseidon_x5_3_gadget_tester() {
		let curve = arkworks_utils::utils::common::Curve::Bn254;

		// Get poseidon parameters for this curve:
		let util_params = setup_params_x5_3(curve);
		let params = PoseidonParameters {
			round_keys: util_params.clone().round_keys,
			mds_matrix: util_params.clone().mds_matrix,
			full_rounds: util_params.clone().full_rounds,
			partial_rounds: util_params.clone().partial_rounds,
			sbox: UtilsPoseidonSbox(5),
			width: util_params.clone().width,
		};
		let poseidon_hasher = PoseidonHasher::new(params);

		// Choose hash fn inputs and compute hash:
		let left = Fq::one();
		let right = Fq::one().double().double();
		let expected = poseidon_hasher.hash_two(&left, &right).unwrap();

		// Create the circuit
		let mut test_circuit = TestCircuit::<Bn254, JubjubParameters, PoseidonHasherGadget> {
			left,
			right,
			expected,
			hasher: poseidon_hasher,
		};

		let res = gadget_tester(&mut test_circuit, 3000);
		assert!(res.is_ok(), "{:?}", res.err().unwrap());
	}

	/// Takes a generic gadget function with no auxillary input and
	/// tests whether it passes an end-to-end test
	pub(crate) fn gadget_tester<
		E: PairingEngine,
		P: TEModelParameters<BaseField = E::Fr>,
		C: Circuit<E, P>,
	>(
		circuit: &mut C,
		n: usize,
	) -> Result<(), Error> {
		let rng = &mut test_rng();
		// Common View
		let universal_params = KZG10::<E, DensePolynomial<E::Fr>>::setup(2 * n, false, rng)?;
		// Provers View
		let (proof, public_inputs) = {
			// Create a prover struct
			let mut prover = Prover::new(b"demo");

			// Additionally key the transcript
			prover.key_transcript(b"key", b"additional seed information");

			// Add gadgets
			circuit.gadget(&mut prover.mut_cs())?;

			// Commit Key
			let (ck, _) = SonicKZG10::<E, DensePolynomial<E::Fr>>::trim(
				&universal_params,
				prover.circuit_size().next_power_of_two(),
				0,
				None,
			)
			.unwrap();
			let powers = Powers {
				powers_of_g: ck.powers_of_g.into(),
				powers_of_gamma_g: ck.powers_of_gamma_g.into(),
			};
			// Preprocess circuit
			prover.preprocess(&powers)?;

			// Once the prove method is called, the public inputs are cleared
			// So pre-fetch these before calling Prove
			let public_inputs = prover.mut_cs().construct_dense_pi_vec();
			//? let lookup_table = prover.mut_cs().lookup_table.clone();

			// Compute Proof
			(prover.prove(&powers)?, public_inputs)
		};
		// Verifiers view
		//
		// Create a Verifier object
		let mut verifier = Verifier::new(b"demo");

		// Additionally key the transcript
		verifier.key_transcript(b"key", b"additional seed information");

		// Add gadgets
		circuit.gadget(&mut verifier.mut_cs())?;

		// Compute Commit and Verifier Key
		let (sonic_ck, sonic_vk) = SonicKZG10::<E, DensePolynomial<E::Fr>>::trim(
			&universal_params,
			verifier.circuit_size().next_power_of_two(),
			0,
			None,
		)
		.unwrap();
		let powers = Powers {
			powers_of_g: sonic_ck.powers_of_g.into(),
			powers_of_gamma_g: sonic_ck.powers_of_gamma_g.into(),
		};

		let vk = kzg10::VerifierKey {
			g: sonic_vk.g,
			gamma_g: sonic_vk.gamma_g,
			h: sonic_vk.h,
			beta_h: sonic_vk.beta_h,
			prepared_h: sonic_vk.prepared_h,
			prepared_beta_h: sonic_vk.prepared_beta_h,
		};

		// Preprocess circuit
		verifier.preprocess(&powers)?;

		// Verify proof
		Ok(verifier.verify(&proof, &vk, &public_inputs)?)
	}
}
