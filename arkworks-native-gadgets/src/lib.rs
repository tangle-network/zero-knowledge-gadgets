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

// bytes field is assumed to contain concatenated, Big-endian encoded chunks.
pub fn to_field_elements<F: PrimeField>(bytes: &[u8]) -> Result<Vec<F>, Error> {
	let max_size_bytes = F::BigInt::NUM_LIMBS * 8;

	// Pad the input with zeros to prevent crashes in arkworks
	let padding_len = (max_size_bytes - (bytes.len() % max_size_bytes)) % max_size_bytes;
	let padded_input: Vec<u8> = bytes
		.iter()
		.cloned()
		.chain(core::iter::repeat(0u8).take(padding_len))
		.collect();

	// Reverse all chunks so the values are formatted in little-endian.
	// This is necessary because arkworks assumes little-endian.
	let mut reversed_chunks: Vec<u8> = Vec::with_capacity(bytes.len() + padding_len);

	for chunk in padded_input.chunks(max_size_bytes) {
		reversed_chunks.extend(chunk.iter().rev());
	}

	// Read the chunks into arkworks to convert into field elements.
	let res = reversed_chunks.chunks(max_size_bytes).map(F::read).collect::<Result<Vec<_>, _>>()?;
	Ok(res)
}

pub fn from_field_elements<F: PrimeField>(elts: &[F]) -> Result<Vec<u8>, Error> {
	let res = elts.iter().fold(vec![], |mut acc, prev| {
		acc.extend_from_slice(&prev.into_repr().to_bytes_be());
		acc
	});

	Ok(res)
}
