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
	hasher: HG,
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
		hasher: HG,
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
		let nullifier_hash = composer.add_input(self.nullifier_hash);
		let path_gadget = PathGadget::<F, P, HG, N>::from_native(composer, self.path.clone());
		let root = composer.add_input(self.root);
		// let arbitrary_data = composer.add_input(self.arbitrary_data);

		// Preimage proof of nullifier
		let res_nullifier = self.hasher.hash_two(composer, &nullifier, &nullifier)?;
		composer.assert_equal(res_nullifier, nullifier_hash);

		// Preimage proof of leaf hash
		let res_leaf = self.hasher.hash_two(composer, &secret, &nullifier)?;

		// Proof of Merkle tree membership
		let is_member = path_gadget.check_membership(composer, &root, &res_leaf, &self.hasher)?;
		let one = composer.add_input(F::one());
		composer.assert_equal(is_member, one);

		// ? What should be done with arbitrary data ?
		Ok(())
	}

	fn padded_circuit_size(&self) -> usize {
		1 << 17
	}
}
