use ark_ec::TEModelParameters;
use ark_ff::PrimeField;
use plonk_core::{constraint_system::StandardComposer, error::Error, prelude::Variable};
use arkworks_native_gadgets::poseidon::sbox::PoseidonSbox;

pub trait SboxConstraints {
	fn synthesize_sbox<F: PrimeField, P: TEModelParameters<BaseField = F>>(
		&self,
		input: &Variable,
		composer: &mut StandardComposer<F, P>,
	) -> Result<Variable, Error>;
}

impl SboxConstraints for PoseidonSbox {
	fn synthesize_sbox<F: PrimeField, P: TEModelParameters<BaseField = F>>(
		&self,
		input_var: &Variable,
		composer: &mut StandardComposer<F, P>,
	) -> Result<Variable, Error> {
		match self {
			PoseidonSbox(val) => match val {
				3 => synthesize_exp3_sbox::<F, P>(input_var, composer),
				5 => synthesize_exp5_sbox::<F, P>(input_var, composer),
				17 => synthesize_exp17_sbox::<F, P>(input_var, composer),
				_ => synthesize_exp3_sbox::<F, P>(input_var, composer),
			},
			_ => synthesize_exp3_sbox::<F, P>(input_var, composer),
		}
	}
}

// Allocate variables in circuit and enforce constraints when Sbox as cube
fn synthesize_exp3_sbox<F: PrimeField, P: TEModelParameters<BaseField = F>>(
	input_var: &Variable,
	composer: &mut StandardComposer<F, P>,
) -> Result<Variable, Error> {
	let sqr =
		composer.arithmetic_gate(|gate| gate.witness(*input_var, *input_var, None).mul(F::one()));
	let cube = composer.arithmetic_gate(|gate| gate.witness(sqr, *input_var, None).mul(F::one()));
	Ok(cube)
}

// Allocate variables in circuit and enforce constraints when Sbox as cube
fn synthesize_exp5_sbox<F: PrimeField, P: TEModelParameters<BaseField = F>>(
	input_var: &Variable,
	composer: &mut StandardComposer<F, P>,
) -> Result<Variable, Error> {
	let sqr =
		composer.arithmetic_gate(|gate| gate.witness(*input_var, *input_var, None).mul(F::one()));
	let fourth = composer.arithmetic_gate(|gate| gate.witness(sqr, sqr, None).mul(F::one()));
	let fifth =
		composer.arithmetic_gate(|gate| gate.witness(fourth, *input_var, None).mul(F::one()));
	Ok(fifth)
}

// Allocate variables in circuit and enforce constraints when Sbox as cube
fn synthesize_exp17_sbox<F: PrimeField, P: TEModelParameters<BaseField = F>>(
	input_var: &Variable,
	composer: &mut StandardComposer<F, P>,
) -> Result<Variable, Error> {
	let sqr =
		composer.arithmetic_gate(|gate| gate.witness(*input_var, *input_var, None).mul(F::one()));
	let fourth = composer.arithmetic_gate(|gate| gate.witness(sqr, sqr, None).mul(F::one()));
	let eigth = composer.arithmetic_gate(|gate| gate.witness(fourth, fourth, None).mul(F::one()));
	let sixteenth = composer.arithmetic_gate(|gate| gate.witness(eigth, eigth, None).mul(F::one()));
	let seventeenth =
		composer.arithmetic_gate(|gate| gate.witness(sixteenth, *input_var, None).mul(F::one()));
	Ok(seventeenth)
}
