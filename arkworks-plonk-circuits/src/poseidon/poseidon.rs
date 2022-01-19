use ark_ec::{models::TEModelParameters, PairingEngine};
use ark_ff::PrimeField;
use ark_std::{fmt::Debug, vec, vec::Vec, One};
use arkworks_gadgets::poseidon::field_hasher::{FieldHasher, Poseidon};
use plonk::{constraint_system::StandardComposer, error::Error, prelude::Variable};

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

	fn from_native(composer: &mut StandardComposer<F, P>, native: Self::Native) -> Self {
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
		while state.len() < width {
			state.push(composer.zero_var());
		}

		// COMPUTE HASH
		let nr = full_rounds + partial_rounds;
		for r in 0..nr {
			state.iter_mut().enumerate().for_each(|(i, a)| {
				let c_temp = self.params.round_keys[(r * width + i)];
				*a = composer
					.arithmetic_gate(|gate| gate.witness(*a, c_temp, None).add(F::one(), F::one()));
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
	use arkworks_gadgets::poseidon::field_hasher::FieldHasher;
	use arkworks_utils::{
		poseidon::{sbox::PoseidonSbox as UtilsPoseidonSbox, PoseidonParameters},
		utils::common::setup_params_x5_3,
	};
	use plonk::prelude::*;

	type PoseidonHasher = arkworks_gadgets::poseidon::field_hasher::Poseidon<Fq>;

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
		let public_inputs: Vec<PublicInputValue<Bn254Fr>> = vec![];

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
}
