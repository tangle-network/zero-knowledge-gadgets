use crate::Vec;
use ark_ec::{models::TEModelParameters, PairingEngine};
use ark_ff::PrimeField;
use ark_plonk::circuit::{self, Circuit};
use ark_std::marker::PhantomData;

use ark_plonk::{constraint_system::StandardComposer, error::Error, prelude::Variable};
use num_traits::{One, Zero};

use crate::plonk::poseidon::sbox::{PoseidonSbox, SboxConstraints};

#[derive(Debug, Default)]
pub struct PoseidonParameters<F: PrimeField> {
	/// The round key constants
	pub round_keys: Vec<F>,
	/// The MDS matrix to apply in the mix layer.
	pub mds_matrix: Vec<Vec<F>>,
}

pub struct PoseidonParametersVar {
	/// The round key constants
	pub round_keys: Vec<Variable>,
	/// The MDS matrix to apply in the mix layer.
	pub mds_matrix: Vec<Vec<Variable>>,
}

#[derive(Debug, Default)]
struct PoseidonCircuit<E: PairingEngine, R: Rounds> {
	pub a: E::Fr,
	pub b: E::Fr,
	pub c: E::Fr,
	pub params: PoseidonParameters<E::Fr>,
	pub rounds: PhantomData<R>,
}

pub trait Rounds: Default + Clone {
	/// The size of the permutation, in field elements.
	const WIDTH: usize;
	/// Number of full SBox rounds
	const FULL_ROUNDS: usize;
	/// Number of partial rounds
	const PARTIAL_ROUNDS: usize;
	/// The S-box to apply in the sub words layer.
	const SBOX: PoseidonSbox;
}

//will get rid of H,HG and implement poseidonhash directly in fnc
impl<E: PairingEngine, P: TEModelParameters<BaseField = E::Fr>, R: Rounds> Circuit<E, P>
	for PoseidonCircuit<E, R>
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
		};

		// COMPUTE HASH
		let mut state = vec![a, b];
		let nr = R::FULL_ROUNDS + R::PARTIAL_ROUNDS;
		for r in 0..nr {
			state.iter_mut().enumerate().for_each(|(i, mut a)| {
				let c_temp = params.round_keys[(r * R::WIDTH + i)];
				// a = a + c_temp
				a = &mut composer.add(
					(E::Fr::one(), *a),
					(E::Fr::one(), c_temp),
					E::Fr::zero(),
					None,
				);
			});

			let half_rounds = R::FULL_ROUNDS / 2;
			if r < half_rounds || r >= half_rounds + R::PARTIAL_ROUNDS {
				state
					.iter_mut()
					.try_for_each(|a| R::SBOX.synthesize_sbox(a, composer).map(|f| *a = f))?;
			} else {
				state[0] = R::SBOX.synthesize_sbox(&state[0], composer)?;
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
