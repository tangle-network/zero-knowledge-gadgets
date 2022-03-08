#![cfg_attr(not(feature = "std"), no_std)]

#[macro_use]
pub extern crate ark_std;

pub mod merkle_tree;
pub mod poseidon;
pub mod set;

use ark_ec::models::TEModelParameters;
use ark_ff::PrimeField;
use ark_std::vec::Vec;
use plonk_core::{constraint_system::StandardComposer, prelude::Variable};

/// Add a variable to a circuit and constrain it to a public input value that
/// is expected to be different in each instance of the circuit.
pub fn add_public_input_variable<F, P>(composer: &mut StandardComposer<F, P>, value: F) -> Variable
where
	F: PrimeField,
	P: TEModelParameters<BaseField = F>,
{
	let variable = composer.add_input(value);
	composer.poly_gate(
		variable,
		variable,
		variable,
		F::zero(),
		-F::one(),
		F::zero(),
		F::zero(),
		F::zero(),
		Some(value),
	);
	variable
}

pub fn add_public_input_variables<F, P>(
	composer: &mut StandardComposer<F, P>,
	items: Vec<F>,
) -> Vec<Variable>
where
	F: PrimeField,
	P: TEModelParameters<BaseField = F>,
{
	let mut vars = Vec::new();
	for item in items {
		vars.push(add_public_input_variable(composer, item));
	}
	vars
}
