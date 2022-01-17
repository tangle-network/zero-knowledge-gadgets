use std::marker::PhantomData;

use crate::poseidon::poseidon::{FieldHasherGadget, PoseidonParametersVar};
use ark_ec::models::TEModelParameters;
use ark_ff::PrimeField;
use arkworks_gadgets::{
	merkle_tree::simple_merkle::{Path, SparseMerkleTree},
	poseidon::field_hasher::Poseidon,
};
use plonk::{constraint_system::StandardComposer, error::Error, prelude::Variable};

#[derive(Clone)]
pub struct PathVar<
	F: PrimeField,
	P: TEModelParameters<BaseField = F>,
	HG: FieldHasherGadget<F, P>,
	const N: usize,
> {
	path: [(Variable, Variable); N], // Or should we use Vec< ...> ?
	_field: PhantomData<F>,
	_te: PhantomData<P>,
	_hg: PhantomData<HG>,
}

impl<
		F: PrimeField,
		P: TEModelParameters<BaseField = F>,
		HG: FieldHasherGadget<F, P>,
		const N: usize,
	> PathVar<F, P, HG, N>
{
	fn from_native(composer: &mut StandardComposer<F, P>, native: Path<F, HG::Native, N>) -> Self {
		// Initialize the array
		let mut path_vars = [(composer.zero_var(), composer.zero_var()); N];

		for i in 0..N {
			path_vars[i] = (
				composer.add_input(native.path[i].0),
				composer.add_input(native.path[i].1),
			);
		}

		PathVar {
			path: path_vars,
			_field: PhantomData,
			_te: PhantomData,
			_hg: PhantomData,
		}
	}

	// Should this really have output?
	pub fn check_membership(
		&self,
		composer: &mut StandardComposer<F, P>,
		root_hash: &Variable,
		leaf: &Variable,
		hasher: &HG,
	) -> Result<Variable, Error> {
		let computed_root = self.calculate_root(composer, leaf, hash_gadget)?;

		composer.assert_equal(computed_root, *root_hash);

		Ok(composer.is_eq_with_output(computed_root, *root_hash))
	}

	pub fn calculate_root(
		&self,
		composer: &mut StandardComposer<F, P>,
		leaf: &Variable,
		hash_gadget: &HG,
	) -> Result<Variable, Error> {
		// The old version of this in merkle_tree::constraints.rs contains the following
		// check at the beginning: but it seems redundant because this will be checked
		// in the for loop below Am I missing something? Investigate in tests...

		// // Check if leaf is one of the bottom-most siblings
		// let leaf_is_left = composer.is_eq_with_output(leaf_hash, self.path[0].0);
		// composer.assert_equal(
		// 	*leaf,
		// 	composer.conditional_select(leaf_is_left, self.path[0].0, self.path[0].1),
		// );

		// Check levels between leaf level and root
		let mut previous_hash = *leaf;
		for (left_hash, right_hash) in self.path.iter() {
			// Check if previous_hash matches the correct current hash
			let previous_is_left = composer.is_eq_with_output(previous_hash, *left_hash);
			composer.assert_equal(
				previous_hash,
				composer.conditional_select(previous_is_left, *left_hash, *right_hash),
			);

			// Update previous_hash
			previous_hash = hash_gadget.hash_two(composer, left_hash, right_hash)?;
		}

		Ok(previous_hash)
	}
}

#[cfg(test)]
mod test {
	use super::PathVar;
	use crate::poseidon::poseidon::{FieldHasherGadget, PoseidonParametersVar};
	use ark_bls12_381::Fr as BlsFr;
	use ark_ff::PrimeField;
	use ark_std::test_rng;
	use arkworks_gadgets::{
		merkle_tree::simple_merkle::{Path, SparseMerkleTree},
		poseidon::field_hasher::Poseidon,
	};
	use arkworks_utils::utils::common::{setup_params_x5_3, Curve};
	use plonk::{constraint_system::StandardComposer, error::Error, prelude::Variable};

	type PoseidonBLS = Poseidon<BlsFr>;
	type SMTBls = SparseMerkleTree<BlsFr, PoseidonBLS, 3usize>;

	#[test]
	fn should_verify_path() {
		let rng = &mut test_rng();
		let curve = Curve::Bls381;

		let params = setup_params_x5_3(curve);

		let poseidon = PoseidonBLS { params };

		let leaves = [BlsFr::rand(rng), BlsFr::rand(rng), BlsFr::rand(rng)];
		let empty_leaf = [0u8; 32];
		let smt = SMTBls::new_sequential(leaves, &poseidon, &empty_leaf)?;
		let root = smt.root();
		let path = smt.generate_membership_proof(0);

		let mut composer = StandardComposer::new();
		let path_var = PathVar::from_native(&composer, path);
	}
}
