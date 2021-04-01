use ark_ff::bytes::ToBytes;
use ark_std::{hash::Hash, rand::Rng};
use webb_crypto_primitives::{crh::FixedLengthCRH, Error};

pub mod basic;

#[cfg(feature = "r1cs")]
pub mod constraints;
#[cfg(feature = "r1cs")]
pub use constraints::*;

pub trait LeafCreation<H: FixedLengthCRH> {
	type Output: ToBytes + Clone + Eq + core::fmt::Debug + Hash + Default;
	type Secrets: Clone + Default;

	fn generate_secrets<R: Rng>(r: &mut R) -> Result<Self::Secrets, Error>;
	fn create(s: &Self::Secrets, h: &H::Parameters) -> Result<Self::Output, Error>;
}
