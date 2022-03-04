use ark_ff::PrimeField;
use ark_r1cs_std::{
	alloc::AllocVar,
	fields::{fp::FpVar, FieldVar},
	prelude::*,
};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::{fmt::Debug, vec::Vec};
use arkworks_native_gadgets::poseidon::{
	sbox::PoseidonSbox, FieldHasher, Poseidon, PoseidonParameters,
};

use core::{
	borrow::Borrow,
	ops::{Add, AddAssign, Mul},
};

pub mod sbox;
use sbox::SboxConstraints;

pub trait FieldHasherGadget<F: PrimeField>
where
	Self: Sized,
{
	type Native: Debug + Clone + FieldHasher<F>;

	// For easy conversion from native version
	fn from_native(
		cs: &mut ConstraintSystemRef<F>,
		native: Self::Native,
	) -> Result<Self, SynthesisError>;
	fn hash(&self, inputs: &[FpVar<F>]) -> Result<FpVar<F>, SynthesisError>;
	fn hash_two(&self, left: &FpVar<F>, right: &FpVar<F>) -> Result<FpVar<F>, SynthesisError>;
}

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
		cs: impl Into<Namespace<F>>,
		f: impl FnOnce() -> Result<T, SynthesisError>,
		mode: AllocationMode,
	) -> Result<Self, SynthesisError> {
		let params = f()?.borrow().clone();
		let mut round_keys_var = Vec::new();
		let ns = cs.into();
		let cs = ns.cs();
		for rk in params.round_keys {
			round_keys_var.push(FpVar::<F>::new_variable(cs.clone(), || Ok(rk), mode)?);
		}
		let mut mds_var = Vec::new();
		for row in params.mds_matrix {
			let mut row_var = Vec::new();
			for mk in row {
				row_var.push(FpVar::<F>::new_variable(cs.clone(), || Ok(mk), mode)?);
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

#[derive(Default, Clone)]
pub struct PoseidonGadget<F: PrimeField> {
	pub params: PoseidonParametersVar<F>,
}

impl<F: PrimeField> PoseidonGadget<F> {
	pub fn permute(&self, mut state: Vec<FpVar<F>>) -> Result<Vec<FpVar<F>>, SynthesisError> {
		let params = &self.params;
		let nr = (params.full_rounds + params.partial_rounds) as usize;
		for r in 0..nr {
			state.iter_mut().enumerate().for_each(|(i, a)| {
				let c = &params.round_keys[(r * (params.width as usize) + i)];
				a.add_assign(c);
			});

			let half_rounds = (params.full_rounds as usize) / 2;
			if r < half_rounds || r >= half_rounds + (params.partial_rounds as usize) {
				state
					.iter_mut()
					.try_for_each(|a| params.sbox.synthesize_sbox(a).map(|f| *a = f))?;
			} else {
				state[0] = params.sbox.synthesize_sbox(&state[0])?;
			}

			state = state
				.iter()
				.enumerate()
				.map(|(i, _)| {
					state
						.iter()
						.enumerate()
						.fold(FpVar::<F>::zero(), |acc, (j, a)| {
							let m = &params.mds_matrix[i][j];
							acc.add(m.mul(a))
						})
				})
				.collect();
		}
		Ok(state)
	}
}

impl<F: PrimeField> FieldHasherGadget<F> for PoseidonGadget<F> {
	type Native = Poseidon<F>;

	fn from_native(
		cs: &mut ConstraintSystemRef<F>,
		native: Self::Native,
	) -> Result<Self, SynthesisError> {
		let params = PoseidonParametersVar::new_variable(
			cs.clone(),
			|| Ok(native.params),
			AllocationMode::Constant,
		)?;
		Ok(Self { params })
	}

	fn hash(&self, inputs: &[FpVar<F>]) -> Result<FpVar<F>, SynthesisError> {
		let parameters = &self.params;
		if inputs.len() >= parameters.width.into() {
			panic!(
				"incorrect input length {:?} for width {:?} -- input bits {:?}",
				inputs.len(),
				parameters.width,
				inputs.len()
			);
		}

		let mut buffer = vec![FpVar::zero(); parameters.width as usize];
		buffer
			.iter_mut()
			.skip(1)
			.zip(inputs)
			.for_each(|(a, b)| *a = b.clone());
		let result = self.permute(buffer);
		result.map(|x| x.get(0).cloned().ok_or(SynthesisError::AssignmentMissing))?
	}

	fn hash_two(&self, left: &FpVar<F>, right: &FpVar<F>) -> Result<FpVar<F>, SynthesisError> {
		self.hash(&[left.clone(), right.clone()])
	}
}
