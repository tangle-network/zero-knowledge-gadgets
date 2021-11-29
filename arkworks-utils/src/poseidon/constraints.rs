use super::PoseidonParameters;
use crate::poseidon::PoseidonSbox;

use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::vec::Vec;
use core::borrow::Borrow;

#[derive(Default, Clone)]
pub struct PoseidonParametersVar<F: PrimeField> {
	/// The round key constants
	pub round_keys: Vec<FpVar<F>>,
	/// The MDS matrix to apply in the mix layer.
	pub mds_matrix: Vec<Vec<FpVar<F>>>,
	/// Number of full SBox rounds
	pub full_rounds: u8,
	/// Number of partial rounds
	pub partial_rounds: u8,
	/// The size of the permutation, in field elements.
	pub width: u8,
	/// The S-box to apply in the sub words layer.
	pub sbox: PoseidonSbox,
}

impl<F: PrimeField> AllocVar<PoseidonParameters<F>, F> for PoseidonParametersVar<F> {
	fn new_variable<T: Borrow<PoseidonParameters<F>>>(
		_cs: impl Into<Namespace<F>>,
		f: impl FnOnce() -> Result<T, SynthesisError>,
		_mode: AllocationMode,
	) -> Result<Self, SynthesisError> {
		let params = f()?.borrow().clone();
		let mut round_keys_var = Vec::new();
		for rk in params.round_keys {
			round_keys_var.push(FpVar::Constant(rk));
		}
		let mut mds_var = Vec::new();
		for row in params.mds_matrix {
			let mut row_var = Vec::new();
			for mk in row {
				row_var.push(FpVar::Constant(mk));
			}
			mds_var.push(row_var);
		}
		let full_rounds = params.full_rounds;
		let partial_rounds = params.partial_rounds;
		let width = params.width;
		let sbox = params.sbox;

		Ok(Self {
			round_keys: round_keys_var,
			mds_matrix: mds_var,
			full_rounds,
			partial_rounds,
			width,
			sbox,
		})
	}
}
