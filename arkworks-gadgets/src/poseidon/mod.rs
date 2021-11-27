use arkworks_utils::{poseidon::{PoseidonError, PoseidonParameters}, utils::{from_field_elements, to_field_elements}};
use ark_crypto_primitives::{crh::TwoToOneCRH, Error, CRH as CRHTrait};
use ark_ff::{fields::PrimeField};
use ark_std::{marker::PhantomData, rand::Rng, vec::Vec};

pub mod circom;

#[cfg(feature = "r1cs")]
pub mod constraints;

pub struct CRH<F: PrimeField> {
	field: PhantomData<F>,
}

impl<F: PrimeField> CRH<F> {
	fn permute(params: &PoseidonParameters<F>, mut state: Vec<F>) -> Result<Vec<F>, PoseidonError> {
		let width = params.width as usize;

		let mut round_keys_offset = 0;

		// full Sbox rounds
		for _ in 0..(params.full_rounds / 2) {
			// Sbox layer
			for i in 0..width {
				state[i] += params.round_keys[round_keys_offset];
				state[i] = params.sbox.apply_sbox(state[i])?;
				round_keys_offset += 1;
			}
			// linear layer
			state = Self::apply_linear_layer(&state, &params.mds_matrix);
		}

		// middle partial Sbox rounds
		for _ in 0..params.partial_rounds {
			for i in 0..width {
				state[i] += params.round_keys[round_keys_offset];
				round_keys_offset += 1;
			}
			// partial Sbox layer, apply Sbox to only 1 element of the state.
			// Here the last one is chosen but the choice is arbitrary.
			state[0] = params.sbox.apply_sbox(state[0])?;
			// linear layer
			state = Self::apply_linear_layer(&state, &params.mds_matrix);
		}

		// last full Sbox rounds
		for _ in 0..(params.full_rounds / 2) {
			// Sbox layer
			for i in 0..width {
				state[i] += params.round_keys[round_keys_offset];
				state[i] = params.sbox.apply_sbox(state[i])?;
				round_keys_offset += 1;
			}
			// linear layer
			state = Self::apply_linear_layer(&state, &params.mds_matrix);
		}

		// Finally the current_state becomes the output
		Ok(state)
	}

	fn apply_linear_layer(state: &Vec<F>, mds: &Vec<Vec<F>>) -> Vec<F> {
		let mut new_state: Vec<F> = Vec::new();
		for i in 0..state.len() {
			let mut sc = F::zero();
			for j in 0..state.len() {
				let mij = mds[i][j];
				sc += mij * state[j];
			}
			new_state.push(sc);
		}
		new_state
	}
}

impl<F: PrimeField> CRHTrait for CRH<F> {
	type Output = F;
	type Parameters = PoseidonParameters<F>;

	const INPUT_SIZE_BITS: usize = 0;

	// F::BigInt::NUM_LIMBS * 8 * PoseidonParameters::width * 8;

	// Not sure what's the purpose of this function of we are going to pass
	// parameters
	fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error> {
		Ok(Self::Parameters::generate(rng))
	}

	fn evaluate(parameters: &Self::Parameters, input: &[u8]) -> Result<Self::Output, Error> {
		let eval_time = start_timer!(|| "PoseidonCRH::Eval");

		let f_inputs: Vec<F> = to_field_elements(input)?;

		let width = parameters.width as usize;

		if f_inputs.len() > width {
			panic!(
				"incorrect input length {:?} for width {:?} -- input bits {:?}",
				f_inputs.len(),
				parameters.width,
				input.len()
			);
		}

		let mut buffer = vec![F::zero(); width];
		buffer.iter_mut().zip(f_inputs).for_each(|(p, v)| *p = v);

		let result = Self::permute(&parameters, buffer)?;

		end_timer!(eval_time);

		Ok(result.get(0).cloned().ok_or(PoseidonError::InvalidInputs)?)
	}
}

impl<F: PrimeField> TwoToOneCRH for CRH<F> {
	type Output = F;
	type Parameters = PoseidonParameters<F>;

	const LEFT_INPUT_SIZE_BITS: usize = Self::INPUT_SIZE_BITS / 2;
	const RIGHT_INPUT_SIZE_BITS: usize = Self::INPUT_SIZE_BITS / 2;

	fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error> {
		<Self as CRHTrait>::setup(rng)
	}

	/// A simple implementation of TwoToOneCRH by asserting left and right input
	/// has same length and chain them together.
	fn evaluate(
		parameters: &Self::Parameters,
		left_input: &[u8],
		right_input: &[u8],
	) -> Result<Self::Output, Error> {
		assert_eq!(left_input.len(), right_input.len());
		assert!(left_input.len() * 8 <= Self::LEFT_INPUT_SIZE_BITS);
		let chained: Vec<_> = left_input
			.iter()
			.chain(right_input.iter())
			.copied()
			.collect();

		<Self as CRHTrait>::evaluate(parameters, &chained)
	}
}

#[cfg(all(test, feature = "poseidon_bn254_x5_5", feature = "poseidon_bn254_x5_3",))]
mod test {
	use super::*;
	use ark_ed_on_bn254::Fq;
	use ark_ff::{to_bytes, Zero};

	use crate::{
		setup::common::{setup_params_x5_3, setup_params_x5_5},
	};

	use arkworks_utils::utils::{bn254_x5_3::get_poseidon_bn254_x5_3, common::Curve, get_results_poseidon_bn254_x5_3, get_results_poseidon_bn254_x5_5};

	type PoseidonCRH = CRH<Fq>;

	#[test]
	fn test_parameter_to_and_from_bytes() {
		let params = get_poseidon_bn254_x5_3::<Fq>();

		let bytes = params.to_bytes();
		let new_params: PoseidonParameters<Fq> = PoseidonParameters::from_bytes(&bytes).unwrap();
		assert_eq!(bytes, new_params.to_bytes());

		let input = to_bytes![Fq::zero(), Fq::zero()].unwrap();
		let hash1 = <PoseidonCRH as CRHTrait>::evaluate(&params, &input).unwrap();
		let hash2 = <PoseidonCRH as CRHTrait>::evaluate(&new_params, &input).unwrap();
		assert_eq!(hash1, hash2);
	}

	#[test]
	fn test_width_3_bn_254() {
		let curve = Curve::Bn254;

		let params = setup_params_x5_3(curve);

		let res = get_results_poseidon_bn254_x5_3::<Fq>();

		let inp = to_bytes![Fq::zero(), Fq::from(1u128), Fq::from(2u128)].unwrap();

		let poseidon_res = <PoseidonCRH as CRHTrait>::evaluate(&params, &inp).unwrap();
		assert_eq!(res[0], poseidon_res);
	}

	#[test]
	fn test_width_5_bn_254() {
		let curve = Curve::Bn254;

		let params = setup_params_x5_5(curve);

		let res = get_results_poseidon_bn254_x5_5::<Fq>();

		let inp = to_bytes![
			Fq::zero(),
			Fq::from(1u128),
			Fq::from(2u128),
			Fq::from(3u128),
			Fq::from(4u128)
		]
		.unwrap();

		let poseidon_res = <PoseidonCRH as CRHTrait>::evaluate(&params, &inp).unwrap();
		assert_eq!(res[0], poseidon_res);
	}
}
