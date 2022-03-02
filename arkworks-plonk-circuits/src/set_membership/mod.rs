use ark_ec::models::TEModelParameters;
use ark_ff::PrimeField;
use ark_std::vec::Vec;
use plonk_core::{constraint_system::StandardComposer, prelude::Variable};

/// A function whose output is 1 if `member` belongs to `set`
/// and 0 otherwise.  Contraints are added to a StandardComposer
/// and the output is added as a variable to the StandardComposer.
/// The set is assumed to consist of public inputs, such as roots
/// of various Merkle trees.
fn check_set_membership<F, P>(
	composer: &mut StandardComposer<F, P>,
	set: &Vec<F>,
	member: Variable,
) -> Variable
where
	F: PrimeField,
	P: TEModelParameters<BaseField = F>,
{
	// Compute all differences between `member` and set elements
	let mut diffs = Vec::new();
	for x in set.iter() {
		let diff = composer.arithmetic_gate(|gate| {
			gate.witness(member, member, None)
				.add(F::zero(), F::one())
				.pi(-*x)
		});
		diffs.push(diff);
	}

	// Accumulate the product of all differences
	let mut accumulator = composer.add_witness_to_circuit_description(F::one());
	for diff in diffs {
		accumulator =
			composer.arithmetic_gate(|gate| gate.witness(accumulator, diff, None).mul(F::one()));
	}

	composer.is_zero_with_output(accumulator)
}

#[cfg(test)]
pub(crate) mod tests {
	//copied from ark-plonk
	use super::*;
	use ark_ed_on_bn254::{EdwardsParameters as JubjubParameters, Fq};

	#[test]
	fn test_verify_set_membership_functions() {
		let set = vec![Fq::from(1u32), Fq::from(2u32), Fq::from(3u32)];

		let mut composer = StandardComposer::<Fq, JubjubParameters>::new();
		let one = composer.add_input(Fq::from(1u32));
		let member = composer.add_input(Fq::from(2u32));

		let result_private = check_set_membership(&mut composer, &set, member);
		composer.assert_equal(result_private, one);
		composer.check_circuit_satisfied();
	}

	#[test]
	fn test_fail_to_verify_set_membership_functions() {
		let set = vec![Fq::from(1u32), Fq::from(2u32), Fq::from(3u32)];

		let mut composer = StandardComposer::<Fq, JubjubParameters>::new();
		let zero = composer.zero_var();
		let member = composer.add_input(Fq::from(4u32));

		let result_private = check_set_membership(&mut composer, &set, member);
		composer.assert_equal(result_private, zero);
		composer.check_circuit_satisfied();
	}
}
