use crate::poseidon::CRH;
use ark_crypto_primitives::crh::constraints::{CRHGadget as CRHGadgetTrait, TwoToOneCRHGadget};
use ark_ff::PrimeField;
use ark_r1cs_std::{
	alloc::AllocVar,
	fields::{fp::FpVar, FieldVar},
	prelude::*,
	uint8::UInt8,
};
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::{marker::PhantomData, vec::Vec};
use arkworks_utils::poseidon::{
	sbox::{constraints::SboxConstraints, PoseidonSbox},
	PoseidonParameters,
};
use core::{
	borrow::Borrow,
	ops::{Add, AddAssign, Mul},
};

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

pub struct CRHGadget<F: PrimeField>(PhantomData<F>);

impl<F: PrimeField> CRHGadget<F> {
	pub fn permute(
		params: &PoseidonParametersVar<F>,
		mut state: Vec<FpVar<F>>,
	) -> Result<Vec<FpVar<F>>, SynthesisError> {
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

impl<F: PrimeField> CRHGadgetTrait<CRH<F>, F> for CRHGadget<F> {
	type OutputVar = FpVar<F>;
	type ParametersVar = PoseidonParametersVar<F>;

	fn evaluate(
		parameters: &Self::ParametersVar,
		input: &[UInt8<F>],
	) -> Result<Self::OutputVar, SynthesisError> {
		let f_var_inputs = arkworks_utils::utils::to_field_var_elements(input)?;
		if f_var_inputs.len() >= parameters.width.into() {
			panic!(
				"incorrect input length {:?} for width {:?} -- input bits {:?}",
				f_var_inputs.len(),
				parameters.width,
				input.len()
			);
		}

		let mut buffer = vec![FpVar::zero()];
		for f in f_var_inputs {
			buffer.push(f);
		}
		let result = Self::permute(parameters, buffer);

		result.map(|x| x.get(0).cloned().ok_or(SynthesisError::AssignmentMissing))?
	}
}

impl<F: PrimeField> TwoToOneCRHGadget<CRH<F>, F> for CRHGadget<F> {
	type OutputVar = FpVar<F>;
	type ParametersVar = PoseidonParametersVar<F>;

	fn evaluate(
		parameters: &Self::ParametersVar,
		left_input: &[UInt8<F>],
		right_input: &[UInt8<F>],
	) -> Result<Self::OutputVar, SynthesisError> {
		// assume equality of left and right length
		assert_eq!(left_input.len(), right_input.len());
		let chained_input: Vec<_> = left_input
			.to_vec()
			.into_iter()
			.chain(right_input.to_vec().into_iter())
			.collect();
		<Self as CRHGadgetTrait<_, _>>::evaluate(parameters, &chained_input)
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use ark_crypto_primitives::crh::CRH as CRHTrait;
	use ark_ed_on_bn254::Fq;
	use ark_ff::to_bytes;
	use ark_r1cs_std::{
		alloc::{AllocVar, AllocationMode},
		R1CSVar,
	};
	use ark_relations::r1cs::ConstraintSystem;
	use arkworks_utils::utils::common::setup_params_x5_3;

	type PoseidonCRH3 = CRH<Fq>;
	type PoseidonCRH3Gadget = CRHGadget<Fq>;

	#[test]
	fn circom_poseidon_native_equality() {
		let cs = ConstraintSystem::<Fq>::new_ref();

		let curve = arkworks_utils::utils::common::Curve::Bn254;

		let params = setup_params_x5_3(curve);

		let params_var = PoseidonParametersVar::new_variable(
			cs.clone(),
			|| Ok(&params),
			AllocationMode::Constant,
		)
		.unwrap();

		let aligned_inp = to_bytes![Fq::from(1u128), Fq::from(2u128)].unwrap();
		let aligned_inp_var =
			Vec::<UInt8<Fq>>::new_input(cs.clone(), || Ok(aligned_inp.clone())).unwrap();

		let res = PoseidonCRH3::evaluate(&params, &aligned_inp).unwrap();
		let res_var =
			<PoseidonCRH3Gadget as CRHGadgetTrait<_, _>>::evaluate(&params_var, &aligned_inp_var)
				.unwrap();
		assert_eq!(res, res_var.value().unwrap());

		// Test Poseidon on an input of 6 bytes. This will require padding, since the
		// inputs are not aligned to the expected input chunk size of 32.
		let unaligned_inp: Vec<u8> = vec![1, 2, 3, 4, 5, 6];
		let unaligned_inp_var =
			Vec::<UInt8<Fq>>::new_input(cs, || Ok(unaligned_inp.clone())).unwrap();

		let res = PoseidonCRH3::evaluate(&params, &unaligned_inp).unwrap();
		let res_var =
			<PoseidonCRH3Gadget as CRHGadgetTrait<_, _>>::evaluate(&params_var, &unaligned_inp_var)
				.unwrap();
		assert_eq!(res, res_var.value().unwrap());
	}
}
