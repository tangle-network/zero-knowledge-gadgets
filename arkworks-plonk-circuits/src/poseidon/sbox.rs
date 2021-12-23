use ark_ec::{PairingEngine, TEModelParameters, AffineCurve};
use ark_ff::Field;
use ark_plonk::{constraint_system::StandardComposer, error::Error, prelude::Variable};
use ark_std::{One, Zero};

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
	let sqr = composer.arithmetic_gate(|gate| {
		gate.witness(*input_var, *input_var, None).mul(E::Fr::one())
	});
	let cube = composer.arithmetic_gate(|gate| {
		gate.witness(sqr, *input_var, None).mul(E::Fr::one())
	});
	Ok(cube)
}

// Allocate variables in circuit and enforce constraints when Sbox as cube
fn synthesize_exp5_sbox<E: PairingEngine, P: TEModelParameters<BaseField = E::Fr>>(
	input_var: &Variable,
	composer: &mut StandardComposer<E, P>,
) -> Result<Variable, Error> {
	let sqr = composer.arithmetic_gate(|gate| {
		gate.witness(*input_var, *input_var, None).mul(E::Fr::one())
	});
	let fourth = composer.arithmetic_gate(|gate| {
		gate.witness(sqr, sqr, None).mul(E::Fr::one())
	});
	let fifth = composer.arithmetic_gate(|gate| {
		gate.witness(fourth, *input_var, None).mul(E::Fr::one())
	});
	Ok(fifth)
}

// Allocate variables in circuit and enforce constraints when Sbox as cube
fn synthesize_exp17_sbox<E: PairingEngine, P: TEModelParameters<BaseField = E::Fr>>(
	input_var: &Variable,
	composer: &mut StandardComposer<E, P>,
) -> Result<Variable, Error> {
	let sqr = composer.arithmetic_gate(|gate| {
		gate.witness(*input_var, *input_var, None).mul(E::Fr::one())
	});
	let fourth = composer.arithmetic_gate(|gate| {
		gate.witness(sqr, sqr, None).mul(E::Fr::one())
	});
	let eigth = composer.arithmetic_gate(|gate| {
		gate.witness(fourth, fourth, None).mul(E::Fr::one())
	});
	let sixteenth = composer.arithmetic_gate(|gate| {
		gate.witness(eigth, eigth, None).mul(E::Fr::one())
	});
	let seventeenth = composer.arithmetic_gate(|gate| {
		gate.witness(sixteenth, *input_var, None).mul(E::Fr::one())
	});
	Ok(seventeenth)
}
