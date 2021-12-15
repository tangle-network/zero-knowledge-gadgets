use crate::{
	ark_std::string::ToString,
	poseidon::sbox::PoseidonSbox,
	utils::{from_field_elements, to_field_elements},
};
use ark_crypto_primitives::Error;
use ark_ff::{fields::PrimeField, BigInteger};
use ark_serialize::Read;
use ark_std::{error::Error as ArkError, rand::Rng, vec::Vec};

pub mod sbox;

#[derive(Debug)]
pub enum PoseidonError {
	InvalidSboxSize(i8),
	ApplySboxFailed,
	InvalidInputs,
}

impl core::fmt::Display for PoseidonError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		use PoseidonError::*;
		let msg = match self {
			InvalidSboxSize(s) => format!("sbox is not supported: {}", s),
			ApplySboxFailed => "failed to apply sbox".to_string(),
			InvalidInputs => "invalid inputs".to_string(),
		};
		write!(f, "{}", msg)
	}
}

impl ArkError for PoseidonError {}

/// The Poseidon permutation.
#[derive(Default, Clone)]
pub struct PoseidonParameters<F: PrimeField> {
	/// The round key constants
	pub round_keys: Vec<F>,
	/// The MDS matrix to apply in the mix layer.
	pub mds_matrix: Vec<Vec<F>>,
	/// Number of full SBox rounds
	pub full_rounds: u8,
	/// Number of partial rounds
	pub partial_rounds: u8,
	/// The size of the permutation, in field elements.
	pub width: u8,
	/// The S-box to apply in the sub words layer.
	pub sbox: PoseidonSbox,
}

impl<F: PrimeField> PoseidonParameters<F> {
	pub fn new(
		round_keys: Vec<F>,
		mds_matrix: Vec<Vec<F>>,
		full_rounds: u8,
		partial_rounds: u8,
		width: u8,
		sbox: PoseidonSbox,
	) -> Self {
		Self {
			round_keys,
			mds_matrix,
			width,
			full_rounds,
			partial_rounds,
			sbox,
		}
	}

	pub fn generate<R: Rng>(_rng: &mut R) -> Self {
		unimplemented!();
	}

	pub fn create_mds<R: Rng>(_rng: &mut R) -> Vec<Vec<F>> {
		unimplemented!();
	}

	pub fn create_round_keys<R: Rng>(_rng: &mut R) -> Vec<F> {
		unimplemented!();
	}

	pub fn to_bytes(&self) -> Vec<u8> {
		let max_elt_size = F::BigInt::NUM_LIMBS * 8;
		let mut buf: Vec<u8> = vec![];
		// serialize length of round keys and round keys, packing them together
		let round_key_len = self.round_keys.len() * max_elt_size;
		buf.extend(&self.width.to_be_bytes());
		buf.extend(&self.full_rounds.to_be_bytes());
		buf.extend(&self.partial_rounds.to_be_bytes());
		buf.extend(&self.sbox.0.to_be_bytes());

		buf.extend_from_slice(&(round_key_len as u32).to_be_bytes());
		buf.extend_from_slice(&from_field_elements(&self.round_keys).unwrap());
		// serialize all inner matrices and add to buffer, we assume the rest
		// of the buffer is reserved for mds_matrix serialization. Since each
		// inner mds_matrix is equally sized we only add the length once.
		let mut stored = false;
		//TODO: implement this for new properties
		for i in 0..self.mds_matrix.len() {
			if !stored {
				// the number of bytes to read for each inner mds matrix vec
				let inner_vec_len = self.mds_matrix[i].len() * max_elt_size;
				buf.extend_from_slice(&(inner_vec_len as u32).to_be_bytes());
				stored = true;
			}

			buf.extend_from_slice(&from_field_elements(&self.mds_matrix[i]).unwrap());
		}
		buf
	}

	pub fn from_bytes(mut bytes: &[u8]) -> Result<Self, Error> {
		let mut width_u8 = [0u8; 1];
		bytes.read_exact(&mut width_u8)?;
		let width = u8::from_be_bytes(width_u8);

		let mut full_rounds_len = [0u8; 1];
		bytes.read_exact(&mut full_rounds_len)?;
		let full_rounds = u8::from_be_bytes(full_rounds_len);

		let mut partial_rounds_u8 = [0u8; 1];
		bytes.read_exact(&mut partial_rounds_u8)?;
		let partial_rounds = u8::from_be_bytes(partial_rounds_u8);

		let mut exponentiation_u8 = [0u8; 1];
		bytes.read_exact(&mut exponentiation_u8)?;
		let exp = i8::from_be_bytes(exponentiation_u8);

		let mut round_key_len = [0u8; 4];
		bytes.read_exact(&mut round_key_len)?;

		let round_key_len_usize: usize = u32::from_be_bytes(round_key_len) as usize;
		let mut round_keys_buf = vec![0u8; round_key_len_usize];
		bytes.read_exact(&mut round_keys_buf)?;

		let round_keys = to_field_elements::<F>(&round_keys_buf)?;
		let mut mds_matrix_inner_vec_len = [0u8; 4];
		bytes.read_exact(&mut mds_matrix_inner_vec_len)?;

		let inner_vec_len_usize = u32::from_be_bytes(mds_matrix_inner_vec_len) as usize;
		let mut mds_matrix: Vec<Vec<F>> = vec![];
		while !bytes.is_empty() {
			let mut inner_vec_buf = vec![0u8; inner_vec_len_usize];
			bytes.read_exact(&mut inner_vec_buf)?;

			let inner_vec = to_field_elements::<F>(&inner_vec_buf)?;
			mds_matrix.push(inner_vec);
		}

		Ok(Self {
			round_keys,
			mds_matrix,
			width,
			full_rounds,
			partial_rounds,
			sbox: PoseidonSbox(exp),
		})
	}
}

#[cfg(all(test, feature = "poseidon_bn254_x5_5", feature = "poseidon_bn254_x5_3",))]
mod test {
	use super::*;
	use ark_ed_on_bn254::Fq;

	use crate::utils::bn254_x5_3::get_poseidon_bn254_x5_3;

	#[test]
	fn test_parameter_to_and_from_bytes() {
		let params = get_poseidon_bn254_x5_3::<Fq>();

		let bytes = params.to_bytes();
		let new_params: PoseidonParameters<Fq> = PoseidonParameters::from_bytes(&bytes).unwrap();
		assert_eq!(bytes, new_params.to_bytes());
	}
}
