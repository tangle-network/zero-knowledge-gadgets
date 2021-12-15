use crate::ark_std::string::ToString;
use ark_crypto_primitives::{crh::TwoToOneCRH, Error, CRH as CRHTrait};
use ark_ff::{fields::PrimeField, BigInteger};
use ark_std::{error::Error as ArkError, marker::PhantomData, rand::Rng, vec::Vec};
use arkworks_utils::{mimc::MiMCParameters, utils::to_field_elements};
#[cfg(feature = "r1cs")]
pub mod constraints;

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

pub struct CRH<F: PrimeField, P: Rounds> {
	field: PhantomData<F>,
	rounds: PhantomData<P>,
}

impl<F: PrimeField, P: Rounds> CRH<F, P> {
	fn mimc(params: &MiMCParameters<F>, state: Vec<F>) -> Result<Vec<F>, MiMCError> {
		assert!(state.len() == params.num_inputs);
		let mut l_out: F = F::zero();
		let mut r_out: F = F::zero();
		for (i, s) in state.iter().enumerate() {
			let l: F;
			let r: F;
			if i == 0 {
				l = *s;
				r = F::zero();
			} else {
				l = l_out + s;
				r = r_out;
			}

			let res = Self::feistel(params, l, r)?;
			l_out = res[0];
			r_out = res[1];
		}

		let mut outs = vec![l_out];
		for _ in 0..params.num_outputs {
			let res = Self::feistel(params, l_out, r_out)?;
			l_out = res[0];
			r_out = res[1];
			outs.push(l_out);
		}

		Ok(outs)
	}

	fn feistel(params: &MiMCParameters<F>, left: F, right: F) -> Result<[F; 2], MiMCError> {
		let mut x_l = left;
		let mut x_r = right;
		let mut c: F;
		let mut t: F;
		let mut t2: F;
		let mut t4: F;
		for i in 0..params.rounds {
			c = if i == 0 || i == params.rounds - 1 {
				F::zero()
			} else {
				params.round_keys[i - 1]
			};
			t = if i == 0 {
				params.k + x_l
			} else {
				params.k + x_l + c
			};

			t2 = t * t;
			t4 = t2 * t2;

			let temp_x_l = x_l;
			let temp_x_r = x_r;

			if i < params.rounds - 1 {
				x_l = if i == 0 {
					temp_x_r
				} else {
					temp_x_r + (t4 * t)
				};

				x_r = temp_x_l;
			} else {
				x_r = temp_x_r + (t4 * t);
				x_l = temp_x_l;
			}
		}

		Ok([x_l, x_r])
	}
}

impl<F: PrimeField, P: Rounds> CRHTrait for CRH<F, P> {
	type Output = F;
	type Parameters = MiMCParameters<F>;

	const INPUT_SIZE_BITS: usize = F::BigInt::NUM_LIMBS * 8 * P::WIDTH * 8;

	// Not sure what's the purpose of this function of we are going to pass
	// parameters
	fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error> {
		Ok(Self::Parameters::generate(rng))
	}

	fn evaluate(parameters: &Self::Parameters, input: &[u8]) -> Result<Self::Output, Error> {
		let eval_time = start_timer!(|| "PoseidonCRH::Eval");

		let f_inputs: Vec<F> = to_field_elements(input)?;

		if f_inputs.len() > P::WIDTH {
			panic!(
				"incorrect input length {:?} for width {:?} -- input bits {:?}",
				f_inputs.len(),
				P::WIDTH,
				input.len()
			);
		}

		let mut buffer = vec![F::zero(); P::WIDTH];
		buffer.iter_mut().zip(f_inputs).for_each(|(p, v)| *p = v);
		let result = Self::mimc(parameters, buffer)?;
		end_timer!(eval_time);
		Ok(result.get(0).cloned().ok_or(MiMCError::InvalidInputs)?)
	}
}

impl<F: PrimeField, P: Rounds> TwoToOneCRH for CRH<F, P> {
	type Output = F;
	type Parameters = MiMCParameters<F>;

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

#[cfg(test)]
mod test {
	use super::*;
	use ark_ed_on_bn254::Fq;
	use ark_ff::{to_bytes, Zero};

	#[derive(Default, Clone)]
	struct MiMCRounds220;

	impl Rounds for MiMCRounds220 {
		const ROUNDS: usize = 220;
		const WIDTH: usize = 3;
	}

	type MiMC220 = CRH<Fq, MiMCRounds220>;

	#[test]
	fn test_hash() {
		let params = MiMCParameters::<Fq>::new(
			Fq::zero(),
			MiMCRounds220::ROUNDS,
			MiMCRounds220::WIDTH,
			MiMCRounds220::WIDTH,
			arkworks_utils::utils::get_rounds_mimc_220(),
		);

		let inp = to_bytes![Fq::zero(), Fq::from(1u128), Fq::from(2u128)].unwrap();

		let mimc_res = <MiMC220 as CRHTrait>::evaluate(&params, &inp).unwrap();
		println!("{:?}", mimc_res);
	}
}
