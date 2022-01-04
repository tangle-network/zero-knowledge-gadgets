use ark_ff::PrimeField;
use ark_std::vec::Vec;

use arkworks_utils::poseidon::{PoseidonError, PoseidonParameters};

#[derive(Clone, Debug)]
pub struct Poseidon<F: PrimeField> {
	pub params: PoseidonParameters<F>,
}

impl<F: PrimeField> Poseidon<F> {
	pub fn new(params: PoseidonParameters<F>) -> Self {
		Poseidon { params }
	}
}

pub trait FieldHasher<F: PrimeField> {
	fn hash(&self, inputs: &[F]) -> Result<F, PoseidonError>;
	fn hash_two(&self, left: &F, right: &F) -> Result<F, PoseidonError>;
}

impl<F: PrimeField> FieldHasher<F> for Poseidon<F> {
	fn hash(&self, inputs: &[F]) -> Result<F, PoseidonError> {
		// Casting params to usize
		let width = self.params.width as usize;
		let partial_rounds = self.params.partial_rounds as usize;
		let full_rounds = self.params.full_rounds as usize;

		// Populate a state vector with 0 and then inputs, pad with zeros if necessary
		if inputs.len() > width - 1 {
			return Err(PoseidonError::InvalidInputs);
		}
		let mut state = vec![F::zero()];
		for f in inputs {
			state.push(*f);
		}
		while state.len() < width {
			state.push(F::zero());
		}

		let nr = full_rounds + partial_rounds;
		for r in 0..nr {
			state.iter_mut().enumerate().for_each(|(i, a)| {
				let c = self.params.round_keys[(r * width + i)];
				a.add_assign(c);
			});

			let half_rounds = full_rounds / 2;
			if r < half_rounds || r >= half_rounds + partial_rounds {
				state
					.iter_mut()
					.try_for_each(|a| self.params.sbox.apply_sbox(*a).map(|f| *a = f))?;
			} else {
				state[0] = self.params.sbox.apply_sbox(state[0])?;
			}

			state = state
				.iter()
				.enumerate()
				.map(|(i, _)| {
					state.iter().enumerate().fold(F::zero(), |acc, (j, a)| {
						let m = self.params.mds_matrix[i][j];
						acc.add(m.mul(*a))
					})
				})
				.collect();
		}

		Ok(state[0])
	}

	fn hash_two(&self, left: &F, right: &F) -> Result<F, PoseidonError> {
		self.hash(&[*left, *right])
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use ark_ed_on_bn254::Fq;
	use ark_ff::fields::Field;
	use ark_std::One;
	use arkworks_utils::utils::{
		common::{
			setup_params_x5_2, setup_params_x5_3, setup_params_x5_4, setup_params_x5_5, Curve,
		},
		parse_vec,
	};

	type PoseidonHasher = Poseidon<Fq>;
	#[test]
	fn test_width_3_circom_bn_254() {
		let curve = Curve::Bn254;

		let params = setup_params_x5_3(curve);
		let poseidon = PoseidonHasher::new(params);

		// output from circomlib, and here is the code.
		// ```js
		// const { poseidon } = require('circomlib');
		// console.log(poseidon([1, 2]).toString(16));
		// ```
		let res: Vec<Fq> = parse_vec(vec![
			"0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a",
		]);
		let left_input = Fq::one();
		let right_input = Fq::one().double();
		let poseidon_res = poseidon.hash_two(&left_input, &right_input).unwrap();

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
		let left_input = Fq::from_be_bytes_mod_order(aaa);
		let right_input = Fq::from_be_bytes_mod_order(&[
			0xc3, 0x3b, 0x60, 0x04, 0x2f, 0x76, 0xc7, 0xfb, 0xd0, 0x5d, 0xb7, 0x76, 0x23, 0xcb,
			0x17, 0xb8, 0x1d, 0x49, 0x41, 0x4b, 0x82, 0xe5, 0x6a, 0x2e, 0xc0, 0x18, 0xf7, 0xa5,
			0x5c, 0x3f, 0x30, 0x0b,
		]);
		let res: Vec<Fq> = parse_vec(vec![
			"0x0a13ad844d3487ad3dbaf3876760eb971283d48333fa5a9e97e6ee422af9554b",
		]);
		let poseidon_res = poseidon.hash_two(&left_input, &right_input).unwrap();
		assert_eq!(res[0], poseidon_res, "{} != {}", res[0], poseidon_res);
	}

	#[test]
	fn test_compare_hashes_with_circom_bn_254() {
		let curve = Curve::Bn254;

		let parameters2 = setup_params_x5_2(curve);
		let parameters4 = setup_params_x5_4(curve);
		let parameters5 = setup_params_x5_5(curve);

		let poseidon2 = Poseidon::new(parameters2);
		let poseidon4 = Poseidon::new(parameters4);
		let poseidon5 = Poseidon::new(parameters5);

		let expected_public_key: Vec<Fq> = parse_vec(vec![
			"0x07a1f74bf9feda741e1e9099012079df28b504fc7a19a02288435b8e02ae21fa",
		]);

		let private_key: Vec<Fq> = parse_vec(vec![
			"0xb2ac10dccfb5a5712d632464a359668bb513e80e9d145ab5a88381de83af1046",
		]);
		// let input = private_key[0];

		let computed_public_key = poseidon2.hash(&private_key).unwrap();
		println!("poseidon_res = {:?}", computed_public_key);
		//println!("expected_res = {:?}", res[0]);
		assert_eq!(
			expected_public_key[0], computed_public_key,
			"{} != {}",
			expected_public_key[0], computed_public_key
		);

		let chain_id: Vec<Fq> = parse_vec(vec![
			"0x0000000000000000000000000000000000000000000000000000000000007a69",
		]);
		let amount: Vec<Fq> = parse_vec(vec![
			"0x0000000000000000000000000000000000000000000000000000000000989680",
		]);
		let blinding: Vec<Fq> = parse_vec(vec![
			"0x00a668ba0dcb34960aca597f433d0d3289c753046afa26d97e1613148c05f2c0",
		]);

		let expected_leaf: Vec<Fq> = parse_vec(vec![
			"0x15206d966a7fb3e3fbbb7f4d7b623ca1c7c9b5c6e6d0a3348df428189441a1e4",
		]);
		let mut input = vec![chain_id[0]];
		input.push(amount[0]);
		input.push(expected_public_key[0]);
		input.push(blinding[0]);
		let computed_leaf = poseidon5.hash(&input).unwrap();

		assert_eq!(
			expected_leaf[0], computed_leaf,
			"{} != {}",
			expected_leaf[0], computed_leaf
		);

		let path_index: Vec<Fq> = parse_vec(vec![
			"0x0000000000000000000000000000000000000000000000000000000000000000",
		]);
		let expected_nullifier: Vec<Fq> = parse_vec(vec![
			"0x21423c7374ce5b3574f04f92243449359ae3865bb8e34cb2b7b5e4187ba01fca",
		]);
		let mut input = vec![expected_leaf[0]];
		input.push(path_index[0]);
		input.push(private_key[0]);

		let computed_nullifier = poseidon4.hash(&input).unwrap();

		assert_eq!(
			expected_nullifier[0], computed_nullifier,
			"{} != {}",
			expected_nullifier[0], computed_nullifier
		);
	}
}
