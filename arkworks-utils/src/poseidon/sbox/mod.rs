use super::PoseidonError;
use ark_ff::PrimeField;

#[cfg(feature = "r1cs")]
pub mod constraints;

/// An S-Box that can be used with Poseidon.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PoseidonSbox(pub i8);

impl Default for PoseidonSbox {
	fn default() -> Self {
		PoseidonSbox(5)
	}
}

impl PoseidonSbox {
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
			// default to cubed
			n => return Err(PoseidonError::InvalidSboxSize(n)),
		};
		Ok(res)
	}
}
