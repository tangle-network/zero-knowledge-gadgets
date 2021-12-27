// use std::arch::aarch64::ST; // What was this?
use ark_std::fmt::Debug;

// use ark_crypto_primitives::crh::poseidon::Poseidon;
use arkworks_gadgets::poseidon::field_hasher::Poseidon;
use ark_ec::{models::TEModelParameters, PairingEngine};
use ark_ff::PrimeField;
use ark_plonk::{
	circuit::Circuit, constraint_system::StandardComposer, error::Error, prelude::Variable,
};
use ark_std::{marker::PhantomData, vec::Vec, One, Zero};

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
	fn hash(&self, composer: &mut StandardComposer<E, P>, inputs: &[Variable]) -> Result<Variable, Error>;
	fn hash_two(&self, composer: &mut StandardComposer<E, P>, left: &Variable, right: &Variable) -> Result<Variable, Error>;
}

impl<E: PairingEngine, P: TEModelParameters<BaseField = E::Fr>> FieldHasherGadget<E::Fr, E, P> for PoseidonGadget<E, P> {
	type Native = Poseidon<E::Fr>;

	fn from_native(composer: &mut StandardComposer<E, P>, native: Self::Native) -> Self {
		// Add native parameters to composer and store variables:
		let mut round_keys_var = vec![];
		for key in native.params.round_keys {
			round_keys_var.push(composer.add_input(key));
		}
		let mut mds_matrix_var = vec![vec![]];
		for row in native.params.mds_matrix {
			let mut temp = vec![];
			for element in row {
				temp.push(composer.add_input(element));
			}
			mds_matrix_var.push(temp);
		}
		let sbox_gadget = PoseidonSbox::Exponentiation(native.params.sbox.0 as usize);

		let params_var = PoseidonParametersVar{
			round_keys: round_keys_var,
			mds_matrix: mds_matrix_var,
			full_rounds: native.params.full_rounds,
			partial_rounds: native.params.partial_rounds,
			width: native.params.width,
			sbox: sbox_gadget,
		};
		PoseidonGadget{
			params: params_var,
			_engine: PhantomData,
			_marker: PhantomData,
		}
	}

	fn hash(&self, composer: &mut StandardComposer<E, P>, inputs: &[Variable]) -> Result<Variable, Error> {
		// Casting params to usize
		let width = self.params.width as usize;
		
		if inputs.len() > width - 1 {
			return Err(Error::PointMalformed); //that's the wrong error, just a placeholder
			//how can I allow myself to return a PoseidonError error here?
		}
		let mut state = vec![composer.zero_var()];
		for f in inputs {
			state.push(*f);
		}
		while state.len() < width {
			state.push(composer.zero_var());
		}

		// COMPUTE HASH
		let nr = self.params.full_rounds + self.params.partial_rounds;
		for r in 0..nr {
			state.iter_mut().enumerate().for_each(|(i, a)| {
				let c_temp = self.params.round_keys[(r as usize * self.params.width as usize + i)];
				*a = composer.arithmetic_gate(|gate| {
					gate.witness(*a, c_temp, None)
						.add(E::Fr::one(), E::Fr::one())
				});
			});

			let half_rounds = self.params.full_rounds / 2;
			if r < half_rounds || r >= half_rounds + self.params.partial_rounds {
				state
					.iter_mut()
					.try_for_each(|a| self.params.sbox.synthesize_sbox(a, composer).map(|f| *a = f))?;
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
								.arithmetic_gate(|gate| gate.witness(*a, *m, None).mul(E::Fr::one()));

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

	fn hash_two(&self, composer: &mut StandardComposer<E, P>, left: &Variable, right: &Variable) -> Result<Variable, Error> {
		self.hash(composer, &[*left, *right])
	}
	
}

