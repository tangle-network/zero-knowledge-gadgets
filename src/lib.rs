#![cfg_attr(not(feature = "std"), no_std)]

#[macro_use]
pub extern crate ark_std;

use ark_std::boxed::Box;
pub(crate) use ark_std::vec::Vec;

pub mod arbitrary;
#[cfg(feature = "r1cs")]
//pub mod circuit;
pub mod identity;
pub mod keypair;
//pub mod leaf;
pub mod merkle_tree;
pub mod mimc;
pub mod poseidon;
pub mod set;
#[cfg(feature = "r1cs")]
pub mod setup;
pub mod utils;

pub type Error = Box<dyn ark_std::error::Error>;

pub mod prelude {
	pub use ark_bls12_381;
	pub use ark_bn254;
	pub use ark_crypto_primitives;
	pub use ark_ed_on_bls12_381;
	pub use ark_ed_on_bn254;
	pub use ark_ff;
	pub use ark_groth16;
	pub use ark_marlin;
	pub use ark_std;
}
