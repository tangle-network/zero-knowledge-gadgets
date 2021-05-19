#![cfg_attr(not(feature = "std"), no_std)]

#[macro_use]
extern crate ark_std;

pub(crate) use ark_std::vec::Vec;

pub mod arbitrary;
#[cfg(feature = "r1cs")]
pub mod circuit;
pub mod leaf;
pub mod merkle_tree;
pub mod set;
#[cfg(feature = "r1cs")]
pub mod setup;
pub mod test_data;

pub mod prelude {
	pub use ark_bls12_381::Fr as Bls381;
	pub use ark_ff::{fields::PrimeField, to_bytes};
	pub use webb_crypto_primitives;
}
