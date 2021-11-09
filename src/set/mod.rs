use ark_crypto_primitives::Error;
use ark_ff::{bytes::ToBytes, fields::PrimeField};

pub mod membership;

#[cfg(feature = "r1cs")]
pub mod constraints;
#[cfg(feature = "r1cs")]
pub use constraints::*;

pub trait Set<F: PrimeField, const M: usize>: Sized {
	type Private: Clone + Default;

	fn generate_secrets<T: ToBytes>(target: &T, set: &[F; M]) -> Result<Self::Private, Error>;
	fn check<T: ToBytes>(target: &T, set: &[F; M], private: &Self::Private) -> Result<bool, Error>;
	fn check_is_enabled<T: ToBytes>(
		target: &T,
		set: &[F; M],
		s: &Self::Private,
		enabled: &F,
	) -> Result<bool, Error>;
}
