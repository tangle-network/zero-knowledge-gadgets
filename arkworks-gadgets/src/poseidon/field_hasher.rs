use ark_ff::PrimeField;
use ark_std::vec::Vec;

use arkworks_utils::poseidon::{PoseidonError, PoseidonParameters};


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
					.try_for_each(|a| params.sbox.apply_sbox(*a).map(|f| *a = f))?;
			} else {
				state[0] = params.sbox.apply_sbox(state[0])?;
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