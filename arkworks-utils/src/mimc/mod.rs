use ark_ff::fields::PrimeField;
use ark_std::{error::Error as ArkError, rand::Rng, vec::Vec};

pub mod ed_on_bn254_mimc;
pub use ed_on_bn254_mimc::*;

#[derive(Debug)]
pub enum MiMCError {
	InvalidInputs,
}

impl core::fmt::Display for MiMCError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		use MiMCError::*;
		let msg = match self {
			InvalidInputs => "invalid inputs".to_string(),
		};
		write!(f, "{}", msg)
	}
}

impl ArkError for MiMCError {}

pub trait Rounds: Default + Clone {
	/// The size of the input vector
	const WIDTH: usize;
	/// Number of mimc rounds
	const ROUNDS: usize;
}

/// The Poseidon permutation.
#[derive(Default, Clone)]
pub struct MiMCParameters<F> {
	pub k: F,
	pub rounds: usize,
	pub num_inputs: usize,
	pub num_outputs: usize,
	pub round_keys: Vec<F>,
}

impl<F: PrimeField> MiMCParameters<F> {
	pub fn new(
		k: F,
		rounds: usize,
		num_inputs: usize,
		num_outputs: usize,
		round_keys: Vec<F>,
	) -> Self {
		Self {
			k,
			rounds,
			num_inputs,
			num_outputs,
			round_keys,
		}
	}

	pub fn generate<R: Rng>(rng: &mut R) -> Self {
		Self {
			round_keys: Self::create_round_keys(rng),
			rounds: 220,
			k: F::zero(),
			num_inputs: 2,
			num_outputs: 1,
		}
	}

	pub fn create_round_keys<R: Rng>(_rng: &mut R) -> Vec<F> {
		todo!();
	}
}
