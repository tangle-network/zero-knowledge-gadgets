use ark_crypto_primitives::Error;
use ark_ff::bytes::ToBytes;
use ark_std::{hash::Hash, rand::Rng};

pub mod basic;

#[cfg(feature = "r1cs")]
pub mod constraints;
#[cfg(feature = "r1cs")]
pub use constraints::*;

pub trait LeafCreation {
	type Output: ToBytes + Clone + Eq + core::fmt::Debug + Hash + Default;
	type Secrets: Clone + Default;

	fn generate_secrets<R: Rng>(r: &mut R) -> Result<Self::Secrets, Error>;
	fn create(s: &Self::Secrets) -> Result<Self::Output, Error>;
}
