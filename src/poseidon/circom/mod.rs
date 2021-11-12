use crate::poseidon::{PoseidonError, PoseidonParameters, Rounds};

use ark_crypto_primitives::{crh::TwoToOneCRH, Error, CRH as CRHTrait};
use ark_ff::{fields::PrimeField, BigInteger};
use ark_std::{marker::PhantomData, rand::Rng, vec::Vec};

#[cfg(feature = "r1cs")]
pub mod constraints;

pub struct CircomCRH<F: PrimeField, P: Rounds>(PhantomData<F>, PhantomData<P>);

impl<F: PrimeField, P: Rounds> CircomCRH<F, P> {
	fn permute(params: &PoseidonParameters<F>, mut state: Vec<F>) -> Result<Vec<F>, PoseidonError> {
		let nr = P::FULL_ROUNDS + P::PARTIAL_ROUNDS;
		for r in 0..nr {
			state.iter_mut().enumerate().for_each(|(i, a)| {
				let c = params.round_keys[(r * P::WIDTH + i)];
				a.add_assign(c);
			});

			let half_rounds = P::FULL_ROUNDS / 2;
			if r < half_rounds || r >= half_rounds + P::PARTIAL_ROUNDS {
				state
					.iter_mut()
					.try_for_each(|a| P::SBOX.apply_sbox(*a).map(|f| *a = f))?;
			} else {
				state[0] = P::SBOX.apply_sbox(state[0])?;
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
}

impl<F: PrimeField, P: Rounds> CRHTrait for CircomCRH<F, P> {
	type Output = F;
	type Parameters = PoseidonParameters<F>;

	const INPUT_SIZE_BITS: usize = F::BigInt::NUM_LIMBS * 8 * P::WIDTH * 8;

	fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
		unreachable!("PoseidonParameters are already precomuted.");
	}

	fn evaluate(parameters: &Self::Parameters, input: &[u8]) -> Result<Self::Output, Error> {
		let eval_time = start_timer!(|| "PoseidonCircomCRH::Eval");
		let f_inputs = crate::utils::to_field_elements(input)?;
		if f_inputs.len() >= P::WIDTH {
			panic!(
				"incorrect input length {:?} for width {:?} -- input bits {:?}",
				f_inputs.len(),
				P::WIDTH,
				input.len()
			);
		}

		let mut buffer = vec![F::zero()];
		for f in f_inputs {
			buffer.push(f);
		}
		let result = Self::permute(&parameters, buffer)?;

		end_timer!(eval_time);

		Ok(result.get(0).cloned().ok_or(PoseidonError::InvalidInputs)?)
	}
}

impl<F: PrimeField, P: Rounds> TwoToOneCRH for CircomCRH<F, P> {
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

#[cfg(all(test, feature = "poseidon_circom_bn254_x5_3"))]
mod test {
	use super::*;
	use crate::{poseidon::PoseidonSbox, utils::{get_mds_poseidon_bn254_x5_2, get_mds_poseidon_bn254_x5_3, get_mds_poseidon_circom_bn254_x5_5, get_rounds_poseidon_bn254_x5_2, get_rounds_poseidon_bn254_x5_3, get_rounds_poseidon_circom_bn254_x5_5}};
	// use ark_bn254::Fq as Bn254Fq;
	use ark_ed_on_bn254::Fq;

	use ark_ff::{BigInteger256, Field};
	use ark_std::{One, Zero};

	use crate::utils::{
		get_mds_poseidon_circom_bn254_x5_3, get_rounds_poseidon_circom_bn254_x5_3, parse_vec,
	};

	#[derive(Default, Clone)]
	struct PoseidonCircomRounds3;

	impl Rounds for PoseidonCircomRounds3 {
		const FULL_ROUNDS: usize = 8;
		const PARTIAL_ROUNDS: usize = 57;
		const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
		const WIDTH: usize = 3;
	}

	#[derive(Default, Clone)]
	struct PoseidonCircomRounds2;

	impl Rounds for PoseidonCircomRounds2 {
		const FULL_ROUNDS: usize = 8;
		const PARTIAL_ROUNDS: usize = 56;
		const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
		const WIDTH: usize = 2;
	}


	type PoseidonCircomCRH3 = CircomCRH<Fq, PoseidonCircomRounds3>;
	type PoseidonCircomCRH2 = CircomCRH<Fq, PoseidonCircomRounds2>;
	#[test]
	fn test_width_3_circom_bn_254() {
		let rounds = get_rounds_poseidon_circom_bn254_x5_3::<Fq>();
		let mds = get_mds_poseidon_circom_bn254_x5_3::<Fq>();
		let params = PoseidonParameters::<Fq>::new(rounds, mds);
		// output from circomlib, and here is the code.
		// ```js
		// const { poseidon } = require('circomlib');
		// console.log(poseidon([1, 2]).toString(16));
		// ```
		let res: Vec<Fq> = parse_vec(vec![
			"0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a",
		]);

		let left_input = Fq::one().into_repr().to_bytes_le();
		let right_input = Fq::one().double().into_repr().to_bytes_le();
		let poseidon_res =
			<PoseidonCircomCRH3 as TwoToOneCRH>::evaluate(&params, &left_input, &right_input)
				.unwrap();
		assert_eq!(res[0], poseidon_res, "{} != {}", res[0], poseidon_res);

		// test two with 32 bytes.
		// these bytes are randomly generated.
		// and tested as the following:
		// ```js
		// const left = "0x" + Buffer.from([
		// 		0x06, 0x9c, 0x63, 0x81, 0xac, 0x0b, 0x96, 0x8e, 0x88, 0x1c,
		// 		0x91, 0x3c, 0x17, 0xd8, 0x36, 0x06, 0x7f, 0xd1, 0x5f, 0x2c,
		// 		0xc7, 0x9f, 0x90, 0x2c, 0x80, 0x70, 0xb3, 0x6d, 0x28, 0x66,
		// 		0x17, 0xdd
		// ]).toString("hex");
		// const right = "0x" + Buffer.from([
		// 		0xc3, 0x3b, 0x60, 0x04, 0x2f, 0x76, 0xc7, 0xfb, 0xd0, 0x5d,
		// 		0xb7, 0x76, 0x23, 0xcb, 0x17, 0xb8, 0x1d, 0x49, 0x41, 0x4b,
		// 		0x82, 0xe5, 0x6a, 0x2e, 0xc0, 0x18, 0xf7, 0xa5, 0x5c, 0x3f,
		// 		0x30, 0x0b
		// ]).toString("hex");
		// console.log({
		// 		hash: "0x" + poseidon([left, right])
		// 						.toString(16)
		// 						.padStart(64, "0")
		// 		});
		// ```
		//
		// Here we should read the data as Big Endian and
		// then we convert it to little endian.
		let aaa: &[u8] = &[
			0x06, 0x9c, 0x63, 0x81, 0xac, 0x0b, 0x96, 0x8e, 0x88, 0x1c, 0x91, 0x3c, 0x17, 0xd8,
			0x36, 0x06, 0x7f, 0xd1, 0x5f, 0x2c, 0xc7, 0x9f, 0x90, 0x2c, 0x80, 0x70, 0xb3, 0x6d,
			0x28, 0x66, 0x17, 0xdd,
		];
		let left_input = Fq::from_be_bytes_mod_order(aaa).into_repr().to_bytes_le();
		let right_input = Fq::from_be_bytes_mod_order(&[
			0xc3, 0x3b, 0x60, 0x04, 0x2f, 0x76, 0xc7, 0xfb, 0xd0, 0x5d, 0xb7, 0x76, 0x23, 0xcb,
			0x17, 0xb8, 0x1d, 0x49, 0x41, 0x4b, 0x82, 0xe5, 0x6a, 0x2e, 0xc0, 0x18, 0xf7, 0xa5,
			0x5c, 0x3f, 0x30, 0x0b,
		])
		.into_repr()
		.to_bytes_le();
		let res: Vec<Fq> = parse_vec(vec![
			"0x0a13ad844d3487ad3dbaf3876760eb971283d48333fa5a9e97e6ee422af9554b",
		]);
		let poseidon_res =
			<PoseidonCircomCRH3 as TwoToOneCRH>::evaluate(&params, &left_input, &right_input)
				.unwrap();
		assert_eq!(res[0], poseidon_res, "{} != {}", res[0], poseidon_res);
	}

	#[derive(Default, Clone)]
	struct PoseidonCircomRounds5;

	impl Rounds for PoseidonCircomRounds5 {
		const FULL_ROUNDS: usize = 8;
		const PARTIAL_ROUNDS: usize = 56;
		const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
		const WIDTH: usize = 5;
	}

	type PoseidonCircomCRH5 = CircomCRH<Fq, PoseidonCircomRounds5>;
	#[test]
	fn test_width_3_zero_input_circom_bn_254() {
		let round_keys = get_rounds_poseidon_bn254_x5_2::<Fq>();
		let mds_matrix = get_mds_poseidon_bn254_x5_2::<Fq>();
		let parameters = PoseidonParameters::<Fq>::new(round_keys, mds_matrix);

		let res: Vec<Fq> = parse_vec(vec![
			"0x07a1f74bf9feda741e1e9099012079df28b504fc7a19a02288435b8e02ae21fa",
		]);

		let res_zero: Vec<Fq> = parse_vec(vec![
			"0x2a09a9fd93c590c26b91effbb2499f07e8f7aa12e2b4940a3aed2411cb65e11c",
		]);

		let res_2zeros: Vec<Fq> = parse_vec(vec![
			"0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864",
		]);
		//let s_input =
		// "b2ac10dccfb5a5712d632464a359668bb513e80e9d145ab5a88381de83af1046"; let input
		// =<[u8;32]>::from_hex(s_input).expect("Decoding failed"); println!("input
		// = {:?}", input); let input_byte: &[u8] =&[
		//	0xb2, 0xac, 0x10, 0xdc, 0xcf, 0xb5, 0xa5, 0x71, 0x2d, 0x63, 0x24, 0x64, 0xa3,
		// 0x59, 	0x66, 0x8b, 0xb5, 0x13, 0xe8, 0x0e, 0x9d, 0x14, 0x5a, 0xb5, 0xa8, 0x83,
		// 0x81, 0xde, 	0x83, 0xaf, 0x10, 0x46,
		//];
		//println!("input_byte = {:?}", input_byte);
		let biginput: Vec<Fq> = parse_vec(vec![
			"0x0000000000000000000000000000000000000000000000000000000000000000",
			"0x0000000000000000000000000000000000000000000000000000000000000000",
		]);
		let mut input = biginput[0].into_repr().to_bytes_le();

		//let mut input2 = biginput[1].into_repr().to_bytes_le();
		//input.append(&mut input2);

		println!("input = {:?}", input);
		println!("input.len() = {:?}", input.len());
		let zero_input = Fq::zero().into_repr().to_bytes_le();
		let poseidon_res = <PoseidonCircomCRH2 as CRHTrait>::evaluate(&parameters, &input).unwrap();
		println!("poseidon_res = {:?}", poseidon_res);
		//println!("expected_res = {:?}", res[0]);
		println!("res_zero     = {:?}", res_zero[0]);
		println!("res_2zeros   = {:?}", res_2zeros[0]);
		assert_eq!(
			res_zero[0], poseidon_res,
			"{} != {}",
			res[0], poseidon_res
		);

		//assert_eq!(res[0], poseidon_res, "{} != {}", res[0], poseidon_res);
		// "0x0000000000000000000000000000000000000000000000000000000000000000"
		// `Private Key =`
		// 0xb2ac10dccfb5a5712d632464a359668bb513e80e9d145ab5a88381de83af1046
		// `Public Key = Poseidon(Private Key) =`
		// 0x07a1f74bf9feda741e1e9099012079df28b504fc7a19a02288435b8e02ae21fa
		//      poseidon_res = Fp256(BigInteger256([17480363595638945920,
		// 1253640362899031899, 6874398346593975678, 1872052294913738484])) zero
		// poseidon_res = Fp256(BigInteger256([12887110008706979002,
		// 2630454327059184150, 15767152811187647922, 1755600115054570625]))
	}
}
