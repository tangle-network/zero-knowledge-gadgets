use ark_ff::{bytes::ToBytes, fields::PrimeField};
use webb_crypto_primitives::Error;

pub mod membership;

#[cfg(feature = "r1cs")]
pub mod constraints;
#[cfg(feature = "r1cs")]
pub use constraints::*;

pub trait Set<F: PrimeField>: Sized {
	type Private: Clone + Default;

	fn generate_secrets<T: ToBytes>(target: &T, set: &Vec<F>) -> Result<Self::Private, Error>;
	fn check<T: ToBytes>(target: &T, private: &Self::Private) -> Result<bool, Error>;
}
