use ark_ec::models::TEModelParameters;
use ark_ff::PrimeField;
use ark_std::{marker::PhantomData, vec::Vec};
use plonk_core::{constraint_system::StandardComposer, prelude::Variable};

use crate::add_public_input_variables;

pub struct SetGadget<F: PrimeField, P: TEModelParameters<BaseField = F>> {
	items: Vec<Variable>,
	te: PhantomData<P>,
}

impl<F: PrimeField, P: TEModelParameters<BaseField = F>> SetGadget<F, P> {
	pub fn from_native(composer: &mut StandardComposer<F, P>, items: Vec<F>) -> Self {
		let vars = add_public_input_variables(composer, items);

		Self {
			items: vars,
			te: PhantomData,
		}
	}

	/// A function whose output is 1 if `member` belongs to `set`
	/// and 0 otherwise.  Contraints are added to a StandardComposer
	/// and the output is added as a variable to the StandardComposer.
	/// The set is assumed to consist of public inputs, such as roots
	/// of various Merkle trees.
	pub fn check_set_membership(
		&self,
		composer: &mut StandardComposer<F, P>,
		member: Variable,
	) -> Variable {
		// Compute all differences between `member` and set elements
		let mut diffs = Vec::new();
		for x in self.items.iter() {
			let diff = composer
				.arithmetic_gate(|gate| gate.witness(member, *x, None).add(F::one(), -F::one()));
			diffs.push(diff);
		}

		// Accumulate the product of all differences
		let mut accumulator = composer.add_witness_to_circuit_description(F::one());
		for diff in diffs {
			accumulator = composer
				.arithmetic_gate(|gate| gate.witness(accumulator, diff, None).mul(F::one()));
		}

		composer.is_zero_with_output(accumulator)
	}

	/// Similar to the check_set_membership function,
	/// except that it accepts an `is_enabled` argument
	/// that turns the set membership check on/off.
	/// Intended usage is when verifying input UTXOs: the
	/// validity of an input only needs to be verified if
	/// its amount is non-zero, so adding the input amount
	/// as the `is_enabled` argument is a way of turning the
	/// set membership check on only when it is needed.
	pub fn check_set_membership_is_enabled(
		&self,
		composer: &mut StandardComposer<F, P>,
		member: Variable,
		is_enabled: Variable,
	) -> Variable {
		// Compute all differences between `member` and set elements
		let mut diffs = Vec::new();
		for x in self.items.iter() {
			let diff = composer
				.arithmetic_gate(|gate| gate.witness(member, *x, None).add(F::one(), -F::one()));
			diffs.push(diff);
		}

		// Accumulate the product of all differences
		let mut accumulator = composer.add_witness_to_circuit_description(F::one());
		for diff in diffs {
			accumulator = composer
				.arithmetic_gate(|gate| gate.witness(accumulator, diff, None).mul(F::one()));
		}
		// Multiply accumulated product by `is_enabled`
		accumulator = composer
			.arithmetic_gate(|gate| gate.witness(accumulator, is_enabled, None).mul(F::one()));

		composer.is_zero_with_output(accumulator)
	}
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

		let set_gadget = SetGadget::from_native(&mut composer, set);

		let one = composer.add_input(Fq::from(1u32));
		let member = composer.add_input(Fq::from(2u32));

		let result_private = set_gadget.check_set_membership(&mut composer, member);
		composer.assert_equal(result_private, one);
		composer.check_circuit_satisfied();
	}

	#[test]
	fn test_fail_to_verify_set_membership_functions() {
		let set = vec![Fq::from(1u32), Fq::from(2u32), Fq::from(3u32)];
		let mut composer = StandardComposer::<Fq, JubjubParameters>::new();

		let set_gadget = SetGadget::from_native(&mut composer, set);

		let zero = composer.zero_var();
		let member = composer.add_input(Fq::from(4u32));

		let result_private = set_gadget.check_set_membership(&mut composer, member);
		composer.assert_equal(result_private, zero);
		composer.check_circuit_satisfied();
	}

	#[test]
	fn test_verify_set_membership_enabled_functions() {
		let set = vec![Fq::from(1u32), Fq::from(2u32), Fq::from(3u32)];
		let mut composer = StandardComposer::<Fq, JubjubParameters>::new();

		let set_gadget = SetGadget::from_native(&mut composer, set);

		let one = composer.add_input(Fq::from(1u32));
		// This is not a member of the set
		let member = composer.add_input(Fq::from(4u32));
		// We set `is_enabled` to 0, so check should pass
		let is_enabled = composer.add_input(Fq::from(0u32));

		let result_private =
			set_gadget.check_set_membership_is_enabled(&mut composer, member, is_enabled);
		composer.assert_equal(result_private, one);
		composer.check_circuit_satisfied();
	}

	#[test]
	fn test_fail_to_verify_set_membership_enabled_functions() {
		let set = vec![Fq::from(1u32), Fq::from(2u32), Fq::from(3u32)];
		let mut composer = StandardComposer::<Fq, JubjubParameters>::new();

		let set_gadget = SetGadget::from_native(&mut composer, set);

		let zero = composer.zero_var();
		// This is not a member of the set
		let member = composer.add_input(Fq::from(4u32));
		// We set `is_enabled` to 1, so check should fail
		let is_enabled = composer.add_input(Fq::from(1u32));

		let result_private =
			set_gadget.check_set_membership_is_enabled(&mut composer, member, is_enabled);
		composer.assert_equal(result_private, zero);
		composer.check_circuit_satisfied();
	}
}
