use crate::poseidon::sbox::PoseidonSbox;
use ark_crypto_primitives::Error;
use ark_ff::{fields::PrimeField, BigInteger};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*, uint8::UInt8};
use ark_relations::r1cs::SynthesisError;
use ethabi::{encode, Token};
use tiny_keccak::{Hasher, Keccak};

use crate::Vec;
pub mod types;
pub use types::*;

#[cfg(feature = "poseidon_bn254_x17_3")]
pub mod bn254_x17_3;
#[cfg(feature = "poseidon_bn254_x17_5")]
pub mod bn254_x17_5;
#[cfg(feature = "poseidon_bn254_x5_2")]
pub mod bn254_x5_2;
#[cfg(feature = "poseidon_bn254_x5_3")]
pub mod bn254_x5_3;
#[cfg(feature = "poseidon_bn254_x5_3")]
pub mod bn254_x5_3_result;
#[cfg(feature = "poseidon_bn254_x5_4")]
pub mod bn254_x5_4;
#[cfg(feature = "poseidon_bn254_x5_5")]
pub mod bn254_x5_5;
#[cfg(feature = "poseidon_bn254_x5_5")]
pub mod bn254_x5_5_result;

#[cfg(feature = "poseidon_bls381_x17_3")]
pub mod bls381_x17_3;
#[cfg(feature = "poseidon_bls381_x17_5")]
pub mod bls381_x17_5;
#[cfg(feature = "poseidon_bls381_x3_3")]
pub mod bls381_x3_3;
#[cfg(feature = "poseidon_bls381_x3_5")]
pub mod bls381_x3_5;
#[cfg(feature = "poseidon_bls381_x5_3")]
pub mod bls381_x5_3;
#[cfg(feature = "poseidon_bls381_x5_5")]
pub mod bls381_x5_5;
#[cfg(feature = "poseidon_circom_bn254_x5_3")]
pub mod bn254_circom_x5_3;
#[cfg(feature = "poseidon_circom_bn254_x5_5")]
pub mod bn254_circom_x5_5;
#[cfg(feature = "poseidon_bls381_x3_3")]
pub mod bn254_x3_3;
#[cfg(feature = "poseidon_bls381_x3_5")]
pub mod bn254_x3_5;

#[cfg(feature = "mimc_220_ed_on_bn254")]
pub mod mimc;

pub fn to_field_elements<F: PrimeField>(bytes: &[u8]) -> Result<Vec<F>, Error> {
	let max_size_bytes = F::BigInt::NUM_LIMBS * 8;

	// Pad the input with zeros
	let padding_len = (max_size_bytes - (bytes.len() % max_size_bytes)) % max_size_bytes;
	let padded_input: Vec<u8> = bytes
		.iter()
		.cloned()
		.chain(core::iter::repeat(0u8).take(padding_len))
		.collect();

	let res = padded_input
		.chunks(max_size_bytes)
		.map(F::read)
		.collect::<Result<Vec<_>, _>>()?;

	Ok(res)
}

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

pub fn from_field_elements<F: PrimeField>(elts: &[F]) -> Result<Vec<u8>, Error> {
	let res = elts.iter().fold(vec![], |mut acc, prev| {
		acc.extend_from_slice(&prev.into_repr().to_bytes_le());
		acc
	});

	Ok(res)
}

pub fn decode_hex(s: &str) -> Vec<u8> {
	let s = &s[2..];
	let vec: Vec<u8> = (0..s.len())
		.step_by(2)
		.map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
		.collect();

	vec
}

pub fn get_bytes_array_from_hex(hex_str: &str) -> [u8; 32] {
	let bytes = decode_hex(hex_str);
	let mut result: [u8; 32] = [0; 32];
	result.copy_from_slice(&bytes);
	result
}

pub fn parse_vec<F: PrimeField>(arr: Vec<&str>) -> Vec<F> {
	let mut res = Vec::new();
	for r in arr.iter() {
		let c = F::from_be_bytes_mod_order(&get_bytes_array_from_hex(r));
		res.push(c);
	}
	res
}

pub fn parse_matrix<F: PrimeField>(mds_entries: Vec<Vec<&str>>) -> Vec<Vec<F>> {
	let width = mds_entries.len();
	let mut mds: Vec<Vec<F>> = vec![vec![F::zero(); width]; width];
	for i in 0..width {
		for j in 0..width {
			// TODO: Remove unwrap, handle error
			mds[i][j] = F::from_be_bytes_mod_order(&get_bytes_array_from_hex(mds_entries[i][j]));
		}
	}
	mds
}

#[cfg(feature = "poseidon_bn254_x5_5")]
pub fn get_results_poseidon_bn254_x5_5<F: PrimeField>() -> Vec<F> {
	parse_vec(bn254_x5_5_result::RESULT.to_vec())
}

#[cfg(feature = "poseidon_bn254_x5_3")]
pub fn get_results_poseidon_bn254_x5_3<F: PrimeField>() -> Vec<F> {
	parse_vec(bn254_x5_3_result::RESULT.to_vec())
}


#[cfg(feature = "mimc_220_ed_on_bn254")]
pub fn get_rounds_mimc_220<F: PrimeField>() -> Vec<F> {
	parse_vec(crate::utils::mimc::CONSTANTS.to_vec())
}

pub fn check_inputs_arbitrary_ethabi(
	recipient: &Token,
	ext_amount: &Token,
	relayer: &Token,
	fee: &Token,
	encrypted_output1: &Token,
	encrypted_output2: &Token,
) {
	match recipient {
		Token::Address(_address) => {}
		_ => {
			panic!("recipient address is not valid");
		}
	}
	match ext_amount {
		Token::Int(_u256) => {}
		_ => {
			panic!("the ext_amount is not valid");
		}
	}
	match relayer {
		Token::Address(_address) => {}
		_ => {
			panic!("relayer address is not valid");
		}
	}
	match fee {
		Token::Uint(_u256) => {}
		_ => {
			panic!("fee is not valid");
		}
	}
	match encrypted_output1 {
		Token::Bytes(_bytes) => {}
		_ => {
			panic!("encrypted_output1 is not valid");
		}
	}
	match encrypted_output2 {
		Token::Bytes(_bytes) => {}
		_ => {
			panic!("encrypted_output2 is not valid");
		}
	}
}

pub fn vanchor_arbitrary_hash(
	recipient: Token,
	ext_amount: Token,
	relayer: Token,
	fee: Token,
	encrypted_output1: Token,
	encrypted_output2: Token,
) -> Vec<u8> {
	check_inputs_arbitrary_ethabi(
		&recipient,
		&ext_amount,
		&relayer,
		&fee,
		&encrypted_output1,
		&encrypted_output2,
	);
	let tuple = [Token::Tuple(vec![
		recipient,
		ext_amount,
		relayer,
		fee,
		encrypted_output1,
		encrypted_output2,
	])];
	let encoded_input = encode(&tuple);
	let bytes: &[u8] = &encoded_input;
	keccak_256(bytes)
}

pub fn keccak_256(input: &[u8]) -> Vec<u8> {
	let mut hasher = Keccak::v256();
	hasher.update(input);
	let mut res: [u8; 32] = [0; 32];
	hasher.finalize(&mut res);
	res.to_vec()
}
