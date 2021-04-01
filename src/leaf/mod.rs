use ark_ff::bytes::ToBytes;
use ark_std::{hash::Hash, rand::Rng};
use core::borrow::Borrow;
use webb_crypto_primitives::{crh::FixedLengthCRH, Error};

pub mod basic;
pub mod bridge;

#[cfg(feature = "r1cs")]
pub mod constraints;
#[cfg(feature = "r1cs")]
pub use constraints::*;

pub trait LeafCreation<H: FixedLengthCRH> {
	type Output: ToBytes + Clone + Eq + core::fmt::Debug + Hash + Default;
	type Private: Clone + Default;
	type Public: Clone + Default;

	fn generate_secrets<R: Rng>(r: &mut R) -> Result<Self::Private, Error>;
	fn create(
		s: &Self::Private,
		p: &Self::Public,
		h: &H::Parameters,
	) -> Result<Self::Output, Error>;
}
