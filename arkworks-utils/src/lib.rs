#![cfg_attr(not(feature = "std"), no_std)]

#[macro_use]
extern crate ark_std;

use ark_ff::PrimeField;
pub use ark_std::vec::Vec;
pub use hex::FromHexError;

pub mod mimc_params;
pub mod poseidon_params;

type Bytes = Vec<u8>;

#[derive(Copy, Clone)]
pub enum Curve {
	Bls381,
	Bn254,
}

pub fn decode_hex(s: &str) -> Result<Bytes, FromHexError> {
	let mut bytes = ark_std::vec![0u8; s.len() / 2];
	let s = &s[2..];
	hex::decode_to_slice(s, &mut bytes as &mut [u8]);
	Ok(bytes.into())
}

pub fn parse_vec(arr: Vec<&str>) -> Result<Vec<Bytes>, FromHexError> {
	let mut res = Vec::new();
	for r in arr.iter() {
		res.push(decode_hex(r)?);
	}
	Ok(res)
}

pub fn parse_matrix(mds_entries: Vec<Vec<&str>>) -> Result<Vec<Vec<Bytes>>, FromHexError> {
	let width = mds_entries.len();
	let mut mds = vec![vec![Vec::new(); width]; width];
	for i in 0..width {
		for j in 0..width {
			mds[i][j] = decode_hex(mds_entries[i][j])?;
		}
	}
	Ok(mds)
}

pub fn bytes_vec_to_f<F: PrimeField>(bytes_vec: &Vec<Vec<u8>>) -> Vec<F> {
	bytes_vec
		.iter()
		.map(|x| F::from_be_bytes_mod_order(x))
		.collect()
}

pub fn bytes_matrix_to_f<F: PrimeField>(bytes_matrix: &Vec<Vec<Vec<u8>>>) -> Vec<Vec<F>> {
	bytes_matrix.iter().map(|x| bytes_vec_to_f(x)).collect()
}
