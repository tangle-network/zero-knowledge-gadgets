use crate::{
	merkle_tree::PathGadget,
	poseidon::poseidon::{FieldHasherGadget, PoseidonGadget},
};
use ark_ec::models::TEModelParameters;
use ark_ff::PrimeField;
use ark_std::marker::PhantomData;
use arkworks_gadgets::merkle_tree::simple_merkle::Path;
use plonk::{
	circuit::Circuit, constraint_system::StandardComposer, error::Error, prelude::Variable,
};

pub struct MixerCircuit<
	F: PrimeField,
	P: TEModelParameters<BaseField = F>,
	HG: FieldHasherGadget<F, P>,
	const N: usize,
> {
	secret: F,
	nullifier: F,
	nullifier_hash: F,
	path: Path<F, HG::Native, N>,
	root: F,
	arbitrary_data: F,
	hasher: HG::Native,
}

impl<F, P, HG, const N: usize> MixerCircuit<F, P, HG, N>
where
	F: PrimeField,
	P: TEModelParameters<BaseField = F>,
	HG: FieldHasherGadget<F, P>,
{
	pub fn new(
		secret: F,
		nullifier: F,
		nullifier_hash: F,
		path: Path<F, HG::Native, N>,
		root: F,
		arbitrary_data: F,
		hasher: HG::Native,
	) -> Self {
		Self {
			secret,
			nullifier,
			nullifier_hash,
			path,
			root,
			arbitrary_data,
			hasher,
		}
	}
}

impl<F, P, HG, const N: usize> Circuit<F, P> for MixerCircuit<F, P, HG, N>
where
	F: PrimeField,
	P: TEModelParameters<BaseField = F>,
	HG: FieldHasherGadget<F, P>,
{
	const CIRCUIT_ID: [u8; 32] = [0xff; 32];

	fn gadget(&mut self, composer: &mut StandardComposer<F, P>) -> Result<(), Error> {
		// Inputs
		let secret = composer.add_input(self.secret);
		let nullifier = composer.add_input(self.nullifier);
		let path_gadget = PathGadget::<F, P, HG, N>::from_native(composer, self.path.clone());
		let root = add_public_input_variable(composer, self.root);
		let arbitrary_data = add_public_input_variable(composer, self.arbitrary_data);
		// Create the hasher_gadget from native
		let hasher_gadget: HG =
			FieldHasherGadget::<F, P>::from_native(composer, self.hasher.clone());

		// Preimage proof of nullifier
		let res_nullifier = hasher_gadget.hash_two(composer, &nullifier, &nullifier)?;
		// Assert equality to the nullifier hash in publicly visible way
		composer.poly_gate(
			res_nullifier,
			res_nullifier,
			res_nullifier,
			F::zero(),
			-F::one(),
			F::zero(),
			F::zero(),
			F::zero(),
			Some(self.nullifier_hash),
		);

		// Preimage proof of leaf hash
		let res_leaf = hasher_gadget.hash_two(composer, &secret, &nullifier)?;

		// Proof of Merkle tree membership
		let is_member = path_gadget.check_membership(composer, &root, &res_leaf, &hasher_gadget)?;
		let one = composer.add_witness_to_circuit_description(F::one());
		composer.assert_equal(is_member, one);

		// ? What should be done with arbitrary data ?
		Ok(())
	}

	fn padded_circuit_size(&self) -> usize {
		1 << 17
	}
}

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
