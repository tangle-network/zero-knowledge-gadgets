use ark_ff::PrimeField;
use ark_std::vec::Vec;

use crate::poseidon::sbox::{PoseidonSbox, PoseidonError};

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

struct Poseidon<F: PrimeField> {
	params: PoseidonParameters<F>,
}

impl<F: PrimeField> Poseidon<F> {
	fn new(params: PoseidonParameters<F>) -> Self {
		Poseidon{ params }
	}
}

trait FieldHasher<F: PrimeField> {
	fn hash(&self, inputs: &Vec<F>) -> Result<F, PoseidonError>;
	fn hash_two(&self, left: &F, right: &F) -> Result<F, PoseidonError>;
}

impl<F: PrimeField> FieldHasher<F> for Poseidon<F> {
	fn hash(&self, inputs: &Vec<F>) -> Result<F, PoseidonError> {
		let mut state = vec![F::zero()];
		for f in inputs {
			state.push(*f);
		}
		let result = permute( &self.params, state)?;

		Ok(result.get(0).cloned().ok_or(PoseidonError::InvalidInputs)?)
	}
	
	fn hash_two(&self, left: &F, right: &F) -> Result<F, PoseidonError> {
		let state = vec![F::zero(), *left, *right];
		let result = permute( &self.params, state)?;

		Ok(result.get(0).cloned().ok_or(PoseidonError::InvalidInputs)?)
	}
}

pub fn permute<F: PrimeField>(params: &PoseidonParameters<F>, mut state: Vec<F>)
	-> Result<Vec<F>, PoseidonError> {
		let nr = (params.full_rounds + params.partial_rounds) as usize;
		for r in 0..nr {
			state.iter_mut().enumerate().for_each(|(i, a)| {
				let c = params.round_keys[(r * (params.width as usize) + i)];
				a.add_assign(c);
			});

			let half_rounds = (params.full_rounds as usize) / 2;
			if r < half_rounds || r >= half_rounds + (params.partial_rounds as usize) {
				state
					.iter_mut()
					.try_for_each(|a| params.sbox.apply_sbox_on_field_element(*a).map(|f| *a = f))?;
			} else {
				state[0] = params.sbox.apply_sbox_on_field_element(state[0])?;
			}

			state = state
				.iter()
				.enumerate()
				.map(|(i, _)| {
					state.iter().enumerate().fold(F::zero(), |acc, (j, a)| {
						let m = params.mds_matrix[i][j];
						acc.add(m.mul(*a))
					})
				})
				.collect();
		}
		Ok(state)
	}