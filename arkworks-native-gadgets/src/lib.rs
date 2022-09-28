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
	// Get chunks of size `max_size_bytes`
	let mut chunks: Vec<Vec<u8>> = bytes.chunks(max_size_bytes).map(|ch| ch.to_vec()).collect();
	let num_chunks = chunks.len();
	// Since we are parsing Big-Endian values, we need to pad the LAST chunk.
	// Because rust is difficult to work with, we first reverse the bytes to
	// Little-endian. and pad the end with zeros.
	let last_chunk_reversed = chunks
		.last()
		.unwrap()
		.into_iter()
		.rev()
		.cloned()
		.collect::<Vec<u8>>();
	// Pad the Little-endian encoded last chunk with zeroes
	let mut last_chunk: Vec<u8> = last_chunk_reversed
		.iter()
		.cloned()
		.chain(core::iter::repeat(0u8).take(padding_len))
		.collect();
	// Reverse the bytes back to Big-Endian
	last_chunk.reverse();
	// Replace the last chunk with the Big-endian padded one
	chunks[num_chunks - 1] = last_chunk;
	// Convert the chunks to Little-endian elements since `F::read` reads
	// Little-endian values
	let new_chunks = chunks
		.iter()
		.map(|v| {
			let mut reversed = v.clone();
			reversed.reverse();
			reversed
		})
		.collect::<Vec<_>>();
	// Convert the chunks to field elements
	let res = new_chunks
		.iter()
		.cloned()
		.map(|v| F::read(&v[..]))
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
