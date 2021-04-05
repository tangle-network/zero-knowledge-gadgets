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
	type Set: IntoIterator<Item = F>;

	fn generate_inputs(target: F, set: &Self::Set) -> Self::Input;
	fn product(inputs: &Self::Input, set: &Self::Set) -> Result<Self::Output, Error>;
}
