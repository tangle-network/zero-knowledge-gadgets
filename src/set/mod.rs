use ark_ff::{bytes::ToBytes, fields::PrimeField};
use webb_crypto_primitives::Error;

pub mod membership;

#[cfg(feature = "r1cs")]
pub mod constraints;
#[cfg(feature = "r1cs")]
pub use constraints::*;

pub trait Set<F: PrimeField>: Sized {
	type Public: Clone + Default;
	type Private: Clone + Default;

	fn generate_secrets<T: ToBytes, I: IntoIterator<Item = F>>(target: &T, set: I)
		-> Self::Private;
	fn check_membership(p: &Self::Public, s: &Self::Private) -> Result<bool, Error>;
}
