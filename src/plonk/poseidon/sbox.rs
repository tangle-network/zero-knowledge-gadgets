use ark_ec::{PairingEngine, TEModelParameters};
use ark_ff::Field;
use ark_plonk::{constraint_system::StandardComposer, error::Error, prelude::Variable};

#[derive(Debug)]
pub enum PoseidonError {
	InvalidSboxSize(usize),
	ApplySboxFailed,
	InvalidInputs,
}

impl core::fmt::Display for PoseidonError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		use PoseidonError::*;
		let msg = match self {
			InvalidSboxSize(s) => format!("sbox is not supported: {}", s),
			ApplySboxFailed => format!("failed to apply sbox"),
			InvalidInputs => format!("invalid inputs"),
		};
		write!(f, "{}", msg)
	}
}

/// An S-Box that can be used with Poseidon.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PoseidonSbox {
	Exponentiation(usize),
	Inverse,
}

impl PoseidonSbox {
	pub fn apply_sbox<E: PairingEngine>(&self, elem: E::Fr) -> Result<E::Fr, PoseidonError> {
		match self {
			PoseidonSbox::Exponentiation(val) => {
				let res = match val {
					3 => elem * elem * elem,
					5 => {
						let sqr = elem.square();
						sqr.square() * elem
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

pub trait SboxConstraints {
	fn synthesize_sbox<E: PairingEngine, P: TEModelParameters<BaseField = E::Fr>>(
		&self,
		input: &Variable,
		composer: &mut StandardComposer<E, P>,
	) -> Result<Variable, Error>;
}

impl SboxConstraints for PoseidonSbox {
	fn synthesize_sbox<E: PairingEngine, P: TEModelParameters<BaseField = E::Fr>>(
		&self,
		input_var: &Variable,
		composer: &mut StandardComposer<E, P>,
	) -> Result<Variable, Error> {
		match self {
			PoseidonSbox::Exponentiation(val) => match val {
				3 => synthesize_exp3_sbox::<E, P>(input_var, composer),
				5 => synthesize_exp5_sbox::<E, P>(input_var, composer),
				17 => synthesize_exp17_sbox::<E, P>(input_var, composer),
				_ => synthesize_exp3_sbox::<E, P>(input_var, composer),
			},
			PoseidonSbox::Inverse => synthesize_inverse_sbox::<E, P>(input_var, composer),
		}
	}
}

// Allocate variables in circuit and enforce constraints when Sbox as cube
fn synthesize_exp3_sbox<E: PairingEngine, P: TEModelParameters<BaseField = E::Fr>>(
	input_var: &Variable,
	composer: &mut StandardComposer<E, P>,
) -> Result<Variable, Error> {
	let sqr = input_var * input_var;
	let cube = input_var * sqr;
	Ok(cube)
}

// Allocate variables in circuit and enforce constraints when Sbox as cube
fn synthesize_exp5_sbox<E: PairingEngine, P: TEModelParameters<BaseField = E::Fr>>(
	input_var: &Variable,
	composer: &mut StandardComposer<E, P>,
) -> Result<Variable, Error> {
	let sqr = input_var * input_var;
	let fourth = &sqr * &sqr;
	let fifth = input_var * fourth;
	Ok(fifth)
}

// Allocate variables in circuit and enforce constraints when Sbox as cube
fn synthesize_exp17_sbox<E: PairingEngine, P: TEModelParameters<BaseField = E::Fr>>(
	input_var: &Variable,
	composer: &mut StandardComposer<E, P>,
) -> Result<Variable, Error> {
	let sqr = input_var * input_var;
	let fourth = &sqr * &sqr;
	let sixteenth = &fourth * &fourth;
	let seventeenth = &sixteenth * input_var;
	Ok(seventeenth)
}

// Allocate variables in circuit and enforce constraints when Sbox as
// inverse
fn synthesize_inverse_sbox<E: PairingEngine, P: TEModelParameters<BaseField = E::Fr>>(
	input_var: &Variable,
	composer: &mut StandardComposer<E, P>,
) -> Result<Variable, Error> {
	input_var.inverse()
}
