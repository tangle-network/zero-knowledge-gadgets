use super::PoseidonError;
use ark_ff::PrimeField;

#[cfg(feature = "r1cs")]
pub mod constraints;

/// An S-Box that can be used with Poseidon.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PoseidonSbox {
	Exponentiation(usize),
	Inverse,
}

impl Default for PoseidonSbox {
    fn default() -> Self { PoseidonSbox::Exponentiation(5) }
}

impl PoseidonSbox {
	pub fn apply_sbox<F: PrimeField>(&self, elem: F) -> Result<F, PoseidonError> {
		match self {
			PoseidonSbox::Exponentiation(val) => {
				let res = match val {
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
					// default to cubed
					n => return Err(PoseidonError::InvalidSboxSize(*n)),
				};
				Ok(res)
			}
			PoseidonSbox::Inverse => elem.inverse().ok_or(PoseidonError::ApplySboxFailed),
		}
	}
}
