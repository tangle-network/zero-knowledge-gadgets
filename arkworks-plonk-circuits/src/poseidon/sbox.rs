use ark_ec::{PairingEngine, TEModelParameters};
use ark_ff::Field;
use ark_plonk::{constraint_system::StandardComposer, error::Error, prelude::Variable};
use ark_std::{One,Zero};

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
}

impl Default for PoseidonSbox {
	fn default() -> Self {
		PoseidonSbox::Exponentiation(0)
	}
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
			_ => return Err(PoseidonError::InvalidSboxSize(0)),
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
			_ => synthesize_exp3_sbox::<E, P>(input_var, composer),
		}
	}
}

// Allocate variables in circuit and enforce constraints when Sbox as cube
fn synthesize_exp3_sbox<E: PairingEngine, P: TEModelParameters<BaseField = E::Fr>>(
	input_var: &Variable,
	composer: &mut StandardComposer<E, P>,
) -> Result<Variable, Error> {
	let sqr = composer.mul(E::Fr::one(), *input_var, *input_var, E::Fr::zero(), None);
	let cube = composer.mul(E::Fr::one(), sqr, *input_var, E::Fr::zero(), None);
	Ok(cube)
}

// Allocate variables in circuit and enforce constraints when Sbox as cube
fn synthesize_exp5_sbox<E: PairingEngine, P: TEModelParameters<BaseField = E::Fr>>(
	input_var: &Variable,
	composer: &mut StandardComposer<E, P>,
) -> Result<Variable, Error> {
	let sqr = composer.mul(E::Fr::one(), *input_var, *input_var, E::Fr::zero(), None);
	let fourth = composer.mul(E::Fr::one(), sqr, sqr, E::Fr::zero(), None);
	let fifth = composer.mul(E::Fr::one(), fourth, *input_var, E::Fr::zero(), None);
	Ok(fifth)
}

// Allocate variables in circuit and enforce constraints when Sbox as cube
fn synthesize_exp17_sbox<E: PairingEngine, P: TEModelParameters<BaseField = E::Fr>>(
	input_var: &Variable,
	composer: &mut StandardComposer<E, P>,
) -> Result<Variable, Error> {
	let sqr = composer.mul(E::Fr::one(), *input_var, *input_var, E::Fr::zero(), None);
	let fourth = composer.mul(E::Fr::one(), sqr, sqr, E::Fr::zero(), None);
	let eigth = composer.mul(E::Fr::one(), fourth, fourth, E::Fr::zero(), None);
	let sixteenth = composer.mul(E::Fr::one(), eigth, eigth, E::Fr::zero(), None);
	let seventeenth = composer.mul(E::Fr::one(), sixteenth, *input_var, E::Fr::zero(), None);
	Ok(seventeenth)
}
