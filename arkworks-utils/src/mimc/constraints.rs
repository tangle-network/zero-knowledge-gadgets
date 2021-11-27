use super::MiMCParameters;
use ark_ff::PrimeField;
use ark_r1cs_std::{
	alloc::AllocVar,
	fields::{fp::FpVar, FieldVar},
	prelude::*,
};
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::vec::Vec;
use core::borrow::Borrow;

#[derive(Clone)]
pub struct MiMCParametersVar<F: PrimeField> {
	pub k: FpVar<F>,
	pub rounds: usize,
	pub num_inputs: usize,
	pub num_outputs: usize,
	pub round_keys: Vec<FpVar<F>>,
}

impl<F: PrimeField> Default for MiMCParametersVar<F> {
	fn default() -> Self {
		Self {
			k: FpVar::<F>::zero(),
			rounds: usize::default(),
			num_inputs: usize::default(),
			num_outputs: usize::default(),
			round_keys: Vec::default(),
		}
	}
}

impl<F: PrimeField> AllocVar<MiMCParameters<F>, F> for MiMCParametersVar<F> {
	fn new_variable<T: Borrow<MiMCParameters<F>>>(
		_cs: impl Into<Namespace<F>>,
		f: impl FnOnce() -> Result<T, SynthesisError>,
		_mode: AllocationMode,
	) -> Result<Self, SynthesisError> {
		let params = f()?.borrow().clone();

		let mut round_keys_var = Vec::new();
		for rk in params.round_keys {
			round_keys_var.push(FpVar::Constant(rk));
		}

		Ok(Self {
			round_keys: round_keys_var,
			k: FpVar::Constant(params.k),
			rounds: params.rounds,
			num_inputs: params.num_inputs,
			num_outputs: params.num_outputs,
		})
	}
}