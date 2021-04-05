use ark_ff::{bytes::ToBytes, fields::PrimeField};
use ark_std::hash::Hash;
use webb_crypto_primitives::Error;

pub mod membership;

#[cfg(feature = "r1cs")]
pub mod constraints;
#[cfg(feature = "r1cs")]
pub use constraints::*;

pub trait Set<F: PrimeField> {
	type Output: ToBytes + Clone + Eq + core::fmt::Debug + Hash + Default;
	type Input: Clone + Default;

	fn generate_inputs<I: IntoIterator<Item = F>>(target: F, set: I) -> Self::Input;
	fn product(inputs: &Self::Input) -> Result<Self::Output, Error>;
}
