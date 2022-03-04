#![cfg_attr(not(feature = "std"), no_std)]

#[macro_use]
pub extern crate ark_std;

use ark_std::boxed::Box;
pub(crate) use ark_std::vec::Vec;

pub mod merkle_tree;
pub mod mimc;
pub mod poseidon;
pub mod set;

use ark_ff::BigInteger;
use ark_ff::PrimeField;
use ark_relations::r1cs::{SynthesisError};
use ark_r1cs_std::{
	fields::{fp::FpVar},
	prelude::*,
	uint8::UInt8,
};

pub fn to_field_var_elements<F: PrimeField>(
	bytes: &[UInt8<F>],
) -> Result<Vec<FpVar<F>>, SynthesisError> {
	let max_size = F::BigInt::NUM_LIMBS * 8;

	// Pad the input with zeros
	let padding_len = (max_size - (bytes.len() % max_size)) % max_size;
	let padded_input: Vec<UInt8<F>> = bytes
		.iter()
		.cloned()
		.chain(core::iter::repeat(UInt8::constant(0u8)).take(padding_len))
		.collect();

	let res = padded_input
		.chunks(max_size)
		.map(|chunk| Boolean::le_bits_to_fp_var(chunk.to_bits_le()?.as_slice()))
		.collect::<Result<Vec<_>, SynthesisError>>()?;

	Ok(res)
}