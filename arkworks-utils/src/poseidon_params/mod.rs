use super::{Bytes, Curve};

#[cfg(feature = "std")]
use super::parse_matrix;

#[cfg(feature = "std")]
use super::parse_vec;

#[cfg(feature = "std")]
pub use hex::FromHexError;

pub use ark_std::vec::Vec;

pub struct PoseidonData {
	pub mds: Vec<Vec<Bytes>>,
	pub rounds: Vec<Bytes>,
	pub full_rounds: u8,
	pub partial_rounds: u8,
	pub width: u8,
	pub exp: i8,
}

impl PoseidonData {
	pub fn new(
		mds: Vec<Vec<Bytes>>,
		rounds: Vec<Bytes>,
		full_rounds: u8,
		partial_rounds: u8,
		width: u8,
		exp: i8,
	) -> Self {
		Self {
			mds,
			rounds,
			full_rounds,
			partial_rounds,
			exp,
			width,
		}
	}
}

#[cfg(feature = "std")]
pub fn setup_poseidon_params(
	curve: Curve,
	exp: i8,
	width: u8,
) -> Result<PoseidonData, FromHexError> {
	// Making params for poseidon in merkle tree
	match (curve, exp, width) {
		#[cfg(feature = "poseidon_bls381_x3_3")]
		(Curve::Bls381, 3, 3) => {
			#[path = "./bls381_x3_3.rs"]
			mod bls381_x3_3;
			use bls381_x3_3::{
				EXPONENTIATION, FULL_ROUNDS, MDS_ENTRIES, PARTIAL_ROUNDS, ROUND_CONSTS, WIDTH,
			};
			get_poseidon_data(
				ROUND_CONSTS,
				MDS_ENTRIES,
				FULL_ROUNDS,
				PARTIAL_ROUNDS,
				WIDTH,
				EXPONENTIATION,
			)
		}
		#[cfg(feature = "poseidon_bn254_x3_3")]
		(Curve::Bn254, 3, 3) => {
			#[path = "./bn254_x3_3.rs"]
			pub mod bn254_x3_3;
			use bn254_x3_3::{
				EXPONENTIATION, FULL_ROUNDS, MDS_ENTRIES, PARTIAL_ROUNDS, ROUND_CONSTS, WIDTH,
			};
			get_poseidon_data(
				ROUND_CONSTS,
				MDS_ENTRIES,
				FULL_ROUNDS,
				PARTIAL_ROUNDS,
				WIDTH,
				EXPONENTIATION,
			)
		}
		#[cfg(feature = "poseidon_bls381_x3_5")]
		(Curve::Bls381, 3, 5) => {
			#[path = "./bls381_x3_5.rs"]
			pub mod bls381_x3_5;
			use bls381_x3_5::{
				EXPONENTIATION, FULL_ROUNDS, MDS_ENTRIES, PARTIAL_ROUNDS, ROUND_CONSTS, WIDTH,
			};
			get_poseidon_data(
				ROUND_CONSTS,
				MDS_ENTRIES,
				FULL_ROUNDS,
				PARTIAL_ROUNDS,
				WIDTH,
				EXPONENTIATION,
			)
		}
		#[cfg(feature = "poseidon_bn254_x3_5")]
		(Curve::Bn254, 3, 5) => {
			#[path = "./bn254_x3_5.rs"]
			pub mod bn254_x3_5;
			use bn254_x3_5::{
				EXPONENTIATION, FULL_ROUNDS, MDS_ENTRIES, PARTIAL_ROUNDS, ROUND_CONSTS, WIDTH,
			};
			get_poseidon_data(
				ROUND_CONSTS,
				MDS_ENTRIES,
				FULL_ROUNDS,
				PARTIAL_ROUNDS,
				WIDTH,
				EXPONENTIATION,
			)
		}
		#[cfg(feature = "poseidon_bls381_x5_3")]
		(Curve::Bls381, 5, 3) => {
			#[path = "./bls381_x5_3.rs"]
			pub mod bls381_x5_3;
			use bls381_x5_3::{
				EXPONENTIATION, FULL_ROUNDS, MDS_ENTRIES, PARTIAL_ROUNDS, ROUND_CONSTS, WIDTH,
			};
			get_poseidon_data(
				ROUND_CONSTS,
				MDS_ENTRIES,
				FULL_ROUNDS,
				PARTIAL_ROUNDS,
				WIDTH,
				EXPONENTIATION,
			)
		}
		#[cfg(feature = "poseidon_bn254_x5_3")]
		(Curve::Bn254, 5, 3) => {
			#[path = "./bn254_x5_3.rs"]
			pub mod bn254_x5_3;
			use bn254_x5_3::{
				EXPONENTIATION, FULL_ROUNDS, MDS_ENTRIES, PARTIAL_ROUNDS, ROUND_CONSTS, WIDTH,
			};
			get_poseidon_data(
				ROUND_CONSTS,
				MDS_ENTRIES,
				FULL_ROUNDS,
				PARTIAL_ROUNDS,
				WIDTH,
				EXPONENTIATION,
			)
		}
		#[cfg(feature = "poseidon_bn254_x5_2")]
		(Curve::Bn254, 5, 2) => {
			#[path = "./bn254_x5_2.rs"]
			pub mod bn254_x5_2;
			use bn254_x5_2::{
				EXPONENTIATION, FULL_ROUNDS, MDS_ENTRIES, PARTIAL_ROUNDS, ROUND_CONSTS, WIDTH,
			};
			get_poseidon_data(
				ROUND_CONSTS,
				MDS_ENTRIES,
				FULL_ROUNDS,
				PARTIAL_ROUNDS,
				WIDTH,
				EXPONENTIATION,
			)
		}
		#[cfg(feature = "poseidon_bn254_x5_4")]
		(Curve::Bn254, 5, 4) => {
			#[path = "./bn254_x5_4.rs"]
			pub mod bn254_x5_4;
			use bn254_x5_4::{
				EXPONENTIATION, FULL_ROUNDS, MDS_ENTRIES, PARTIAL_ROUNDS, ROUND_CONSTS, WIDTH,
			};
			get_poseidon_data(
				ROUND_CONSTS,
				MDS_ENTRIES,
				FULL_ROUNDS,
				PARTIAL_ROUNDS,
				WIDTH,
				EXPONENTIATION,
			)
		}
		#[cfg(feature = "poseidon_bls381_x5_5")]
		(Curve::Bls381, 5, 5) => {
			#[path = "./bls381_x5_5.rs"]
			pub mod bls381_x5_5;
			use bls381_x5_5::{
				EXPONENTIATION, FULL_ROUNDS, MDS_ENTRIES, PARTIAL_ROUNDS, ROUND_CONSTS, WIDTH,
			};
			get_poseidon_data(
				ROUND_CONSTS,
				MDS_ENTRIES,
				FULL_ROUNDS,
				PARTIAL_ROUNDS,
				WIDTH,
				EXPONENTIATION,
			)
		}
		#[cfg(feature = "poseidon_bn254_x5_5")]
		(Curve::Bn254, 5, 5) => {
			#[path = "./bn254_x5_5.rs"]
			pub mod bn254_x5_5;
			use bn254_x5_5::{
				EXPONENTIATION, FULL_ROUNDS, MDS_ENTRIES, PARTIAL_ROUNDS, ROUND_CONSTS, WIDTH,
			};
			get_poseidon_data(
				ROUND_CONSTS,
				MDS_ENTRIES,
				FULL_ROUNDS,
				PARTIAL_ROUNDS,
				WIDTH,
				EXPONENTIATION,
			)
		}
		#[cfg(feature = "poseidon_bls381_x17_3")]
		(Curve::Bls381, 17, 3) => {
			#[path = "./bls381_x17_3.rs"]
			pub mod bls381_x17_3;
			use bls381_x17_3::{
				EXPONENTIATION, FULL_ROUNDS, MDS_ENTRIES, PARTIAL_ROUNDS, ROUND_CONSTS, WIDTH,
			};
			get_poseidon_data(
				ROUND_CONSTS,
				MDS_ENTRIES,
				FULL_ROUNDS,
				PARTIAL_ROUNDS,
				WIDTH,
				EXPONENTIATION,
			)
		}
		#[cfg(feature = "poseidon_bn254_x17_3")]
		(Curve::Bn254, 17, 3) => {
			#[path = "./bn254_x17_3.rs"]
			pub mod bn254_x17_3;
			use bn254_x17_3::{
				EXPONENTIATION, FULL_ROUNDS, MDS_ENTRIES, PARTIAL_ROUNDS, ROUND_CONSTS, WIDTH,
			};
			get_poseidon_data(
				ROUND_CONSTS,
				MDS_ENTRIES,
				FULL_ROUNDS,
				PARTIAL_ROUNDS,
				WIDTH,
				EXPONENTIATION,
			)
		}
		#[cfg(feature = "poseidon_bls381_x17_5")]
		(Curve::Bls381, 17, 5) => {
			#[path = "./bls381_x17_5.rs"]
			pub mod bls381_x17_5;
			use bls381_x17_5::{
				EXPONENTIATION, FULL_ROUNDS, MDS_ENTRIES, PARTIAL_ROUNDS, ROUND_CONSTS, WIDTH,
			};
			get_poseidon_data(
				ROUND_CONSTS,
				MDS_ENTRIES,
				FULL_ROUNDS,
				PARTIAL_ROUNDS,
				WIDTH,
				EXPONENTIATION,
			)
		}
		#[cfg(feature = "poseidon_bn254_x17_5")]
		(Curve::Bn254, 17, 5) => {
			#[path = "./bn254_x17_5.rs"]
			pub mod bn254_x17_5;
			use bn254_x17_5::{
				EXPONENTIATION, FULL_ROUNDS, MDS_ENTRIES, PARTIAL_ROUNDS, ROUND_CONSTS, WIDTH,
			};
			get_poseidon_data(
				ROUND_CONSTS,
				MDS_ENTRIES,
				FULL_ROUNDS,
				PARTIAL_ROUNDS,
				WIDTH,
				EXPONENTIATION,
			)
		}
		_ => unimplemented!(),
	}
}

#[cfg(feature = "std")]
pub fn get_poseidon_result(curve: Curve, exp: i8, width: u8) -> Result<Vec<Bytes>, FromHexError> {
	match (curve, exp, width) {
		#[cfg(feature = "poseidon_bn254_x5_5")]
		(Curve::Bn254, 5, 5) => {
			#[path = "./bn254_x5_5_result.rs"]
			pub mod bn254_x5_5_result;
			parse_vec(bn254_x5_5_result::RESULT.to_vec())
		}
		#[cfg(feature = "poseidon_bn254_x5_3")]
		(Curve::Bn254, 5, 3) => {
			#[path = "./bn254_x5_3_result.rs"]
			pub mod bn254_x5_3_result;
			parse_vec(bn254_x5_3_result::RESULT.to_vec())
		}
		_ => unimplemented!(),
	}
}

#[cfg(feature = "std")]
pub fn get_poseidon_data(
	rounds: &[&str],
	mds: &[&[&str]],
	full_rounds: u8,
	partial_rounds: u8,
	width: u8,
	exp: i8,
) -> Result<PoseidonData, FromHexError> {
	let rounds = parse_vec(rounds.to_vec())?;
	let mds = parse_matrix(mds.iter().map(|x| x.to_vec()).collect::<Vec<_>>())?;
	Ok(PoseidonData::new(
		mds,
		rounds,
		full_rounds,
		partial_rounds,
		width,
		exp,
	))
}
