use ark_ec::{models::TEModelParameters, PairingEngine};
use ark_ff::PrimeField;
use ark_plonk::{
	circuit::{self, Circuit},
	constraint_system::StandardComposer,
	error::Error,
	prelude::{Variable, *},
};
use ark_std::{marker::PhantomData, vec::Vec};
use num_traits::{One, Zero};

use crate::poseidon::sbox::{PoseidonSbox, SboxConstraints};

#[derive(Debug, Default)]
pub struct PoseidonParameters<F: PrimeField> {
	/// The round key constants
	pub round_keys: Vec<F>,
	/// The MDS matrix to apply in the mix layer.
	pub mds_matrix: Vec<Vec<F>>,
	/// Number of full SBox rounds
	pub full_rounds: u8,
	/// Number of partial rounds
	pub partial_rounds: u8,
	/// The size of the permutation, in field elements.
	pub width: u8,
	/// The S-box to apply in the sub words layer.
	pub sbox: PoseidonSbox,
}

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
struct PoseidonCircuit<E: PairingEngine> {
	pub a: E::Fr,
	pub b: E::Fr,
	pub c: E::Fr,
	pub params: PoseidonParameters<E::Fr>,
}

impl<E: PairingEngine, P: TEModelParameters<BaseField = E::Fr>> Circuit<E, P>
	for PoseidonCircuit<E>
{
	const CIRCUIT_ID: [u8; 32] = [0xff; 32];

	fn gadget(&mut self, composer: &mut StandardComposer<E, P>) -> Result<(), Error> {
		// ADD INPUTS
		let a = composer.add_input(self.a);
		let b = composer.add_input(self.b);

		let mut round_key_vars = vec![];
		for i in 0..self.params.round_keys.len() {
			let round_key = composer.add_input(self.params.round_keys[i]);
			round_key_vars.push(round_key);
		}

		let mut mds_matrix_vars = vec![];
		for i in 0..self.params.mds_matrix.len() {
			let mut mds_row_vars = vec![];
			for j in 0..self.params.mds_matrix[i].len() {
				let mds_entry = composer.add_input(self.params.mds_matrix[i][j]);
				mds_row_vars.push(mds_entry);
			}
			mds_matrix_vars.push(mds_row_vars);
		}

		let params = PoseidonParametersVar {
			round_keys: round_key_vars,
			mds_matrix: mds_matrix_vars,
			full_rounds: self.params.full_rounds,
			partial_rounds: self.params.partial_rounds,
			width: self.params.width,
			sbox: self.params.sbox,
		};

		// COMPUTE HASH
		let mut state = vec![a, b];
		let nr = params.full_rounds + params.partial_rounds;
		for r in 0..nr {
			state.iter_mut().enumerate().for_each(|(i, mut a)| {
				let c_temp = params.round_keys[(r as usize * params.width as usize + i)];
				// a = a + c_temp
				a = &mut composer.add(
					(E::Fr::one(), *a),
					(E::Fr::one(), c_temp),
					E::Fr::zero(),
					None,
				);
			});

			let half_rounds = params.full_rounds / 2;
			if r < half_rounds || r >= half_rounds + params.partial_rounds {
				state
					.iter_mut()
					.try_for_each(|a| params.sbox.synthesize_sbox(a, composer).map(|f| *a = f))?;
			} else {
				state[0] = params.sbox.synthesize_sbox(&state[0], composer)?;
			}

			state = state
				.iter()
				.enumerate()
				.map(|(i, _)| {
					state
						.iter()
						.enumerate()
						.fold(composer.zero_var(), |acc, (j, a)| {
							let m = &params.mds_matrix[i][j];

							let mul_result = composer.mul(E::Fr::one(), *a, *m, E::Fr::one(), None);

							let add_result = composer.add(
								(E::Fr::one(), acc),
								(E::Fr::one(), mul_result),
								E::Fr::zero(),
								None,
							);

							add_result
						})
				})
				.collect();
		}

		Ok(())
	}

	fn padded_circuit_size(&self) -> usize {
		1 << 11
	}
}

mod tests {
	//copied from ark-plonk
	use super::*;
	use ark_bn254::{Bn254, Fr as Bn254Fr};
	use ark_crypto_primitives::{CRHGadget, CRH};
	use ark_ec::{twisted_edwards_extended::GroupAffine, AffineCurve};
	use ark_plonk::constraint_system::StandardComposer;
	use ark_poly::polynomial::univariate::DensePolynomial;
	use ark_poly_commit::kzg10::KZG10;
	use num_traits::{One, Zero};
	use rand_core::OsRng;

	use arkworks_utils::utils::common::setup_params_x5_3;

	#[test]
	fn should_not_verify_plonk_poseidon() {
		let curve = arkworks_utils::utils::common::Curve::Bn254;

		let util_params = setup_params_x5_3(curve);
		let params = PoseidonParameters {
			round_keys: util_params.round_keys,
			mds_matrix: util_params.mds_matrix,
			full_rounds: util_params.full_rounds,
			partial_rounds: util_params.partial_rounds,
			sbox: PoseidonSbox::Exponentiation(5),
			width: util_params.width,
		};

		//this step seems to be needed to tell the subsequent step what the curve E is
		type PoseidonTestCircuit = PoseidonCircuit<Bn254>;

		let test_circuit = PoseidonTestCircuit {
			a: Bn254Fr::zero(),
			b: Bn254Fr::zero(),
			c: Bn254Fr::zero(),
			params,
		};

		let u_params =
			KZG10::<Bls12_381, DensePolynomial<Bn254Fr>>::setup(1 << 12, false, &mut OsRng)?; //removed a ? from output
																				  //is this step necessary? passing &u_params to compile below doesnt work
		let u_params_ref = &u_params;

		let (prover_key, verifier_data) = test_circuit.compile(u_params_ref)?;
	}
}
