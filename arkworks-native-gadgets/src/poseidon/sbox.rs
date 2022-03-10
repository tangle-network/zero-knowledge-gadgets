//! The S-box used in the Poseidon hash function.
//!
//! The `PoseidonSbox` struct contains only one signed 8-bit integer.
//! In the notation of
//! [the original Poseidon paper](https://eprint.iacr.org/2019/458.pdf),
//! this is alpha.
//!
//! The value of alpha can be either 3, 5, 17, or -1: the default is 5.
//! Trying to use any other value will result in a `PoseidonError`.
//!
//! The `apply_sbox` method takes an element of a prime field `F`
//! and raises it to the power alpha (in `F`).

/// Importing dependencies
use super::PoseidonError;
use ark_ff::PrimeField;

/// The PoseidonSbox struct contains just a public signed 8-bit integer.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PoseidonSbox(pub i8);

/// The default value for PoseidonSbox is 5.
impl Default for PoseidonSbox {
	fn default() -> Self {
		PoseidonSbox(5)
	}
}

impl PoseidonSbox {
	/// Takes in an element of a prime field and raises it to the power alpha
	/// (`sbox.0`) within that field. The method assumes that alpha is either 3,
	/// 5, 17, or -1. If not, it throws `PoseidonError`.
	pub fn apply_sbox<F: PrimeField>(&self, elem: F) -> Result<F, PoseidonError> {
		let res = match self.0 {
			3 => elem * elem * elem,
			5 => {
				let sqr = elem.square();
				sqr.square().mul(elem)
			}
			17 => {
				let sqr = elem * elem;
				let quad = sqr * sqr;
				let eighth = quad * quad;
				let sixteenth = eighth * eighth;
				sixteenth * elem
			}
			-1 => elem.inverse().ok_or(PoseidonError::ApplySboxFailed)?,

			n => return Err(PoseidonError::InvalidSboxSize(n)),
		};
		Ok(res)
	}
}
