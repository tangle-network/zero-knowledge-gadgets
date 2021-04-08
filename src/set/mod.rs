use ark_ff::{bytes::ToBytes, fields::PrimeField};
use ark_std::hash::Hash;
use webb_crypto_primitives::Error;

pub mod membership;

#[cfg(feature = "r1cs")]
pub mod constraints;
#[cfg(feature = "r1cs")]
pub use constraints::*;

pub trait Set<F: PrimeField>: Sized {
	type Input: Clone + Default;

	fn generate_inputs<T: ToBytes, I: IntoIterator<Item = F>>(target: &T, set: I) -> Self::Input;
	fn check_membership(inputs: &Self::Input) -> Result<bool, Error>;
}
