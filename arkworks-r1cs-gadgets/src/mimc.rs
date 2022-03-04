use super::to_field_var_elements;
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
use arkworks_native_gadgets::mimc::{MiMCParameters, Rounds, CRH};
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

pub struct CRHGadget<F: PrimeField, P: Rounds> {
	field: PhantomData<F>,
	params: PhantomData<P>,
}

impl<F: PrimeField, P: Rounds> CRHGadget<F, P> {
	fn mimc(
		parameters: &MiMCParametersVar<F>,
		state: Vec<FpVar<F>>,
	) -> Result<Vec<FpVar<F>>, SynthesisError> {
		assert!(state.len() == parameters.num_inputs);
		let mut l_out: FpVar<F> = FpVar::<F>::zero();
		let mut r_out: FpVar<F> = FpVar::<F>::zero();

		for (i, s) in state.iter().enumerate() {
			let l: FpVar<F>;
			let r: FpVar<F>;
			if i == 0 {
				l = s.clone();
				r = FpVar::<F>::zero();
			} else {
				l = l_out.clone() + s.clone();
				r = r_out.clone();
			}

			let res = Self::feistel(parameters, l, r)?;
			l_out = res[0].clone();
			r_out = res[1].clone();
		}

		let mut outs = vec![l_out.clone()];
		for _ in 0..parameters.num_outputs {
			let res = Self::feistel(parameters, l_out.clone(), r_out.clone())?;
			l_out = res[0].clone();
			r_out = res[1].clone();
			outs.push(l_out.clone());
		}

		Ok(outs)
	}

	fn feistel(
		parameters: &MiMCParametersVar<F>,
		left: FpVar<F>,
		right: FpVar<F>,
	) -> Result<[FpVar<F>; 2], SynthesisError> {
		let mut x_l = left;
		let mut x_r = right;
		let mut c: FpVar<F>;
		let mut t: FpVar<F>;
		let mut t2: FpVar<F>;
		let mut t4: FpVar<F>;
		for i in 0..parameters.rounds {
			c = if i == 0 || i == parameters.rounds - 1 {
				FpVar::<F>::zero()
			} else {
				parameters.round_keys[i - 1].clone()
			};
			t = if i == 0 {
				parameters.k.clone() + x_l.clone()
			} else {
				parameters.k.clone() + x_l.clone() + c
			};

			t2 = t.clone() * t.clone();
			t4 = t2.clone() * t2.clone();

			let temp_x_l = x_l.clone();
			let temp_x_r = x_r.clone();

			if i < parameters.rounds - 1 {
				x_l = if i == 0 { temp_x_r } else { temp_x_r + t4 * t };

				x_r = temp_x_l;
			} else {
				x_r = temp_x_r + t4 * t;
				x_l = temp_x_l;
			}
		}

		Ok([x_l, x_r])
	}
}

// https://github.com/arkworks-rs/r1cs-std/blob/master/src/bits/uint8.rs#L343
impl<F: PrimeField, P: Rounds> CRHGadgetTrait<CRH<F, P>, F> for CRHGadget<F, P> {
	type OutputVar = FpVar<F>;
	type ParametersVar = MiMCParametersVar<F>;

	fn evaluate(
		parameters: &Self::ParametersVar,
		input: &[UInt8<F>],
	) -> Result<Self::OutputVar, SynthesisError> {
		let f_var_inputs: Vec<FpVar<F>> = to_field_var_elements(input)?;
		if f_var_inputs.len() > P::WIDTH as usize {
			panic!(
				"incorrect input length {:?} for width {:?}",
				f_var_inputs.len(),
				P::WIDTH,
			);
		}

		let mut buffer = vec![FpVar::zero(); P::WIDTH as usize];
		buffer
			.iter_mut()
			.zip(f_var_inputs)
			.for_each(|(b, l_b)| *b = l_b);

		let result = Self::mimc(parameters, buffer);
		result.map(|x| x.get(0).cloned().ok_or(SynthesisError::AssignmentMissing))?
	}
}

impl<F: PrimeField, P: Rounds> TwoToOneCRHGadget<CRH<F, P>, F> for CRHGadget<F, P> {
	type OutputVar = FpVar<F>;
	type ParametersVar = MiMCParametersVar<F>;

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

#[cfg(test)]
mod test {
	#![allow(non_camel_case_types)]

	use super::*;
	use ark_crypto_primitives::crh::CRH as CRHTrait;
	use ark_ed_on_bn254::Fq;
	use ark_ff::{to_bytes, Zero};
	use ark_relations::r1cs::ConstraintSystem;
	use arkworks_utils::{bytes_vec_to_f, mimc_params::setup_mimc_params, Curve};

	#[derive(Default, Clone)]
	struct MiMCRounds220_2;

	impl Rounds for MiMCRounds220_2 {
		const ROUNDS: u16 = 220;
		const WIDTH: u8 = 2;
	}

	type MiMC220_2 = CRH<Fq, MiMCRounds220_2>;
	type MiMC220Gadget_2 = CRHGadget<Fq, MiMCRounds220_2>;

	#[derive(Default, Clone)]
	struct MiMCRounds220_3;

	impl Rounds for MiMCRounds220_3 {
		const ROUNDS: u16 = 220;
		const WIDTH: u8 = 3;
	}

	type MiMC220_3 = CRH<Fq, MiMCRounds220_3>;
	type MiMC220Gadget_3 = CRHGadget<Fq, MiMCRounds220_3>;

	pub fn setup_mimc<F: PrimeField>(curve: Curve, rounds: u16, width: u8) -> MiMCParameters<F> {
		let mimc_data = setup_mimc_params(curve, rounds, width).unwrap();
		let constants_f = bytes_vec_to_f(&mimc_data.constants);

		let mimc_p = MiMCParameters {
			k: F::zero(),
			num_inputs: mimc_data.width as usize,
			num_outputs: mimc_data.width as usize,
			rounds: mimc_data.rounds as usize,
			round_keys: constants_f,
		};

		mimc_p
	}

	#[test]
	fn test_mimc_native_equality() {
		let curve = Curve::Bn254;
		let cs = ConstraintSystem::<Fq>::new_ref();

		let params = setup_mimc(curve, MiMCRounds220_3::ROUNDS, MiMCRounds220_3::WIDTH);

		let params_var =
			MiMCParametersVar::new_variable(cs.clone(), || Ok(&params), AllocationMode::Constant)
				.unwrap();

		// Test MiMC on an input of 3 field elements.
		let aligned_inp = to_bytes![Fq::zero(), Fq::from(1u128), Fq::from(2u128)].unwrap();
		let aligned_inp_var =
			Vec::<UInt8<Fq>>::new_input(cs.clone(), || Ok(aligned_inp.clone())).unwrap();

		let res = MiMC220_3::evaluate(&params, &aligned_inp).unwrap();
		let res_var = <MiMC220Gadget_3 as CRHGadgetTrait<_, _>>::evaluate(
			&params_var.clone(),
			&aligned_inp_var,
		)
		.unwrap();
		assert_eq!(res, res_var.value().unwrap());
	}
}
