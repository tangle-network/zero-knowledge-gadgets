#![cfg_attr(not(feature = "std"), no_std)]

use ark_ff::{BigInteger, PrimeField};
use ark_std::{boxed::Box, vec::Vec};

#[macro_use]
pub extern crate ark_std;

pub mod merkle_tree;
pub mod mimc;
pub mod poseidon;

pub type Error = Box<dyn ark_std::error::Error>;

pub mod prelude {
	pub use ark_crypto_primitives;
	pub use ark_ff;
	pub use ark_std;
}

pub fn to_field_elements<F: PrimeField>(bytes: &[u8]) -> Result<Vec<F>, Error> {
	let max_size_bytes = F::BigInt::NUM_LIMBS * 8;

	// Pad the input with zeros
	let padding_len = (max_size_bytes - (bytes.len() % max_size_bytes)) % max_size_bytes;
	// TODO: Pad the last element with the padding
	let padded_input: Vec<u8> = bytes
		.iter()
		.cloned()
		.chain(core::iter::repeat(0u8).take(padding_len))
		.collect();

	let mut chunks: Vec<_> = padded_input.chunks(max_size_bytes).collect();
	chunks[chunks.len() - 1] = core::iter::repeat(0u8).take(max_size_bytes)
		.chain(chunks[chunks.len() - 1].into_iter())
		.collect();

	// TODO: Read as LE but first reverse each chunk
	let res = padded_input
		.chunks(max_size_bytes)
		.map(|v| v.reverse())
		.map(F::read)
		.collect::<Result<Vec<_>, _>>()?;

	Ok(res)
}

pub fn from_field_elements<F: PrimeField>(elts: &[F]) -> Result<Vec<u8>, Error> {
	let res = elts.iter().fold(vec![], |mut acc, prev| {
		acc.extend_from_slice(&prev.into_repr().to_bytes_be());
		acc
	});

	Ok(res)
}
