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


mod tests {
	//copied from ark-plonk
	use super::*;
	use ark_crypto_primitives::{CRH, CRHGadget};
	use ark_plonk::constraint_system::StandardComposer;
	use ark_bls12_381::{Bls12_381, Fr as BlsFr};
	use ark_ec::twisted_edwards_extended::GroupAffine;
	use ark_ec::AffineCurve;
	use ark_poly_commit::kzg10::KZG10;
	use ark_poly::polynomial::univariate::DensePolynomial;
	use num_traits::{One,Zero};
	use rand_core::OsRng; 
	
	//copied from arkworks-gadgets
	// use crate::{

	// 	utils::get_mds_poseidon_bls381_x5_3,
	// };
	use crate::utils::{get_mds_poseidon_bls381_x5_3, get_rounds_poseidon_bls381_x5_3};

	//to satisfy trait bounds below
	#[derive(Default,Clone)]

	//this seems to be a struct to hold details 
	struct PoseidonRounds1;

	//then you put in some actual numbers
	impl Rounds for PoseidonRounds1 {
		const FULL_ROUNDS: usize = 8;
		const PARTIAL_ROUNDS: usize = 57;
		const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
		const WIDTH: usize = 3;
	}

	#[test]
	fn should_not_verify_plonk_poseidon() {
		let params = PoseidonParameters{
			round_keys: get_rounds_poseidon_bls381_x5_3::<BlsFr>(),
			mds_matrix: get_mds_poseidon_bls381_x5_3::<BlsFr>(),
		};

		//this step seems to be needed to tell the subsequent step what the curve E is
		type PoseidonTestCircuit = PoseidonCircuit<Bls12_381, PoseidonRounds1>;

		let test_circuit = PoseidonTestCircuit{
			a: BlsFr::zero(),
			b: BlsFr::zero(),
			c: BlsFr::zero(),
			params: params,
			rounds: PhantomData,
		};

		let u_params = KZG10::<Bls12_381, DensePolynomial<BlsFr>>::setup(
			1 << 12 ,
			false,
			&mut OsRng,
		)?; //removed a ? from output
		//is this step necessary? passing &u_params to compile below doesnt work
		let u_params_ref = &u_params;

		let (prover_key, verifier_data) = test_circuit.compile( u_params_ref )?;

	}

	
	
}