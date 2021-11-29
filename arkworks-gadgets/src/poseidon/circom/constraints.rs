use crate::poseidon::{circom::CircomCRH, constraints::PoseidonParametersVar};
use ark_crypto_primitives::crh::constraints::{CRHGadget as CRHGadgetTrait, TwoToOneCRHGadget};
use ark_ff::PrimeField;
use ark_r1cs_std::{
	fields::{fp::FpVar, FieldVar},
	uint8::UInt8,
};
use ark_relations::r1cs::SynthesisError;
use ark_std::{marker::PhantomData, vec::Vec};
use arkworks_utils::poseidon::sbox::constraints::SboxConstraints;
use core::ops::{Add, AddAssign, Mul};

pub struct CircomCRHGadget<F: PrimeField>(PhantomData<F>);

impl<F: PrimeField> CircomCRHGadget<F> {
	fn permute(
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

impl<F: PrimeField> CRHGadgetTrait<CircomCRH<F>, F> for CircomCRHGadget<F> {
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
		let result = Self::permute(&parameters, buffer);

		result.map(|x| x.get(0).cloned().ok_or(SynthesisError::AssignmentMissing))?
	}
}

impl<F: PrimeField> TwoToOneCRHGadget<CircomCRH<F>, F> for CircomCRHGadget<F> {
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
	use arkworks_utils::utils::common::setup_circom_params_x5_3;

	type PoseidonCircomCRH3 = CircomCRH<Fq>;
	type PoseidonCircomCRH3Gadget = CircomCRHGadget<Fq>;

	#[test]
	fn circom_poseidon_native_equality() {
		let cs = ConstraintSystem::<Fq>::new_ref();

		let curve = arkworks_utils::utils::common::Curve::Bn254;

		let params = setup_circom_params_x5_3(curve);

		let params_var = PoseidonParametersVar::new_variable(
			cs.clone(),
			|| Ok(&params),
			AllocationMode::Constant,
		)
		.unwrap();

		let aligned_inp = to_bytes![Fq::from(1u128), Fq::from(2u128)].unwrap();
		let aligned_inp_var =
			Vec::<UInt8<Fq>>::new_input(cs.clone(), || Ok(aligned_inp.clone())).unwrap();

		let res = PoseidonCircomCRH3::evaluate(&params, &aligned_inp).unwrap();
		let res_var = <PoseidonCircomCRH3Gadget as CRHGadgetTrait<_, _>>::evaluate(
			&params_var,
			&aligned_inp_var,
		)
		.unwrap();
		assert_eq!(res, res_var.value().unwrap());

		// Test Poseidon on an input of 6 bytes. This will require padding, since the
		// inputs are not aligned to the expected input chunk size of 32.
		let unaligned_inp: Vec<u8> = vec![1, 2, 3, 4, 5, 6];
		let unaligned_inp_var =
			Vec::<UInt8<Fq>>::new_input(cs, || Ok(unaligned_inp.clone())).unwrap();

		let res = PoseidonCircomCRH3::evaluate(&params, &unaligned_inp).unwrap();
		let res_var = <PoseidonCircomCRH3Gadget as CRHGadgetTrait<_, _>>::evaluate(
			&params_var,
			&unaligned_inp_var,
		)
		.unwrap();
		assert_eq!(res, res_var.value().unwrap());
	}
}
