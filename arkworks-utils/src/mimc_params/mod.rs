use super::{Bytes, Curve};
#[cfg(feature = "std")]
pub use hex::FromHexError;

#[cfg(feature = "std")]
use super::parse_vec;

pub use ark_std::vec::Vec;

pub struct MimcData {
	pub constants: Vec<Bytes>,
	pub rounds: u16,
	pub width: u8,
}

impl MimcData {
	pub fn new(constants: Vec<Bytes>, rounds: u16, width: u8) -> Self {
		Self {
			constants,
			rounds,
			width,
		}
	}
}

#[cfg(feature = "std")]
pub fn setup_mimc_params(curve: Curve, rounds: u16, width: u8) -> Result<MimcData, FromHexError> {
	match (curve, rounds, width) {
		#[cfg(feature = "mimc_ed_on_bn254_220")]
		(Curve::Bn254, 220, 3) => {
			#[path = "./ed_on_bn254_220.rs"]
			pub mod ed_on_bn254_220;
			use ed_on_bn254_220::{CONSTANTS, MIMC_ROUNDS, WIDTH};
			get_mimc_data(CONSTANTS, MIMC_ROUNDS, WIDTH)
		}
		_ => unimplemented!(),
	}
}

#[cfg(feature = "std")]
pub fn get_mimc_data(constants: &[&str], rounds: u16, width: u8) -> Result<MimcData, FromHexError> {
	let constants = parse_vec(constants.to_vec())?;
	Ok(MimcData::new(constants, rounds, width))
}
