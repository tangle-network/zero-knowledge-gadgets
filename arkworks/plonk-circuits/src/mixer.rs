use ark_ec::models::TEModelParameters;
use ark_ff::PrimeField;
use arkworks_native_gadgets::merkle_tree::Path;
use arkworks_plonk_gadgets::{
	add_public_input_variable, merkle_tree::PathGadget, poseidon::FieldHasherGadget,
};
use plonk_core::{circuit::Circuit, constraint_system::StandardComposer, error::Error};

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
		// Private Inputs
		let secret = composer.add_input(self.secret);
		let nullifier = composer.add_input(self.nullifier);
		let path_gadget = PathGadget::<F, P, HG, N>::from_native(composer, self.path.clone());

		// Public Inputs
		let nullifier_hash = add_public_input_variable(composer, self.nullifier_hash);
		let root = add_public_input_variable(composer, self.root);
		let arbitrary_data = add_public_input_variable(composer, self.arbitrary_data);

		// Create the hasher_gadget from native
		let hasher_gadget: HG =
			FieldHasherGadget::<F, P>::from_native(composer, self.hasher.clone());

		// Preimage proof of nullifier
		let res_nullifier = hasher_gadget.hash_two(composer, &nullifier, &nullifier)?;
		// TODO: (This has 1 more gate than skipping the nullifier_hash variable and
		// putting this straight in to a poly_gate)
		composer.assert_equal(res_nullifier, nullifier_hash);

		// Preimage proof of leaf hash
		let res_leaf = hasher_gadget.hash_two(composer, &secret, &nullifier)?;

		// Proof of Merkle tree membership
		let is_member = path_gadget.check_membership(composer, &root, &res_leaf, &hasher_gadget)?;
		let one = composer.add_witness_to_circuit_description(F::one());
		composer.assert_equal(is_member, one);

		// Safety constraint to prevent tampering with arbitrary_data
		let _arbitrary_data_squared = composer.arithmetic_gate(|gate| {
			gate.witness(arbitrary_data, arbitrary_data, None)
				.mul(F::one())
		});
		Ok(())
	}

	fn padded_circuit_size(&self) -> usize {
		1 << 21
	}
}

#[cfg(test)]
mod test {
	use super::MixerCircuit;
	use crate::utils::{prove_then_verify, ToConstraintFieldHelper};
	use ark_bn254::Bn254;
	use ark_ed_on_bn254::{EdwardsParameters as JubjubParameters, Fq};
	use ark_ff::{Field, PrimeField};
	use ark_std::test_rng;
	use arkworks_native_gadgets::{
		ark_std::UniformRand,
		merkle_tree::SparseMerkleTree,
		poseidon::{sbox::PoseidonSbox, FieldHasher, Poseidon, PoseidonParameters},
	};
	use arkworks_plonk_gadgets::poseidon::PoseidonGadget;
	use arkworks_utils::{
		bytes_matrix_to_f, bytes_vec_to_f, poseidon_params::setup_poseidon_params, Curve,
	};
	use plonk_core::prelude::*;

	type PoseidonBn254 = Poseidon<Fq>;

	pub fn setup_params<F: PrimeField>(curve: Curve, exp: i8, width: u8) -> PoseidonParameters<F> {
		let pos_data = setup_poseidon_params(curve, exp, width).unwrap();

		let mds_f = bytes_matrix_to_f(&pos_data.mds);
		let rounds_f = bytes_vec_to_f(&pos_data.rounds);

		let pos = PoseidonParameters {
			mds_matrix: mds_f,
			round_keys: rounds_f,
			full_rounds: pos_data.full_rounds,
			partial_rounds: pos_data.partial_rounds,
			sbox: PoseidonSbox(pos_data.exp),
			width: pos_data.width,
		};

		pos
	}

	#[test]
	fn should_verify_correct_mixer_plonk() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;

		let params = setup_params(curve, 5, 3);
		let poseidon_native = PoseidonBn254 { params };

		// Randomly generated secrets
		let secret = Fq::rand(rng);
		let nullifier = Fq::rand(rng);

		// Public data
		let arbitrary_data = Fq::rand(rng);
		let nullifier_hash = poseidon_native.hash_two(&nullifier, &nullifier).unwrap();
		let leaf_hash = poseidon_native.hash_two(&secret, &nullifier).unwrap();

		// Create a tree whose leaves are already populated with 2^HEIGHT - 1 random
		// scalars, then add leaf_hash as the final leaf
		const HEIGHT: usize = 6usize;
		let last_index = 1 << (HEIGHT - 1) - 1;
		let mut leaves = [Fq::from(0u8); 1 << (HEIGHT - 1)];
		for i in 0..last_index {
			leaves[i] = Fq::rand(rng);
		}
		leaves[last_index] = leaf_hash;
		let tree = SparseMerkleTree::<Fq, PoseidonBn254, HEIGHT>::new_sequential(
			&leaves,
			&poseidon_native,
			&[0u8; 32],
		)
		.unwrap();
		let root = tree.root();

		// Path
		let path = tree.generate_membership_proof(last_index as u64);

		// Create MixerCircuit
		let mut mixer = MixerCircuit::<Fq, JubjubParameters, PoseidonGadget, HEIGHT>::new(
			secret,
			nullifier,
			nullifier_hash,
			path,
			root,
			arbitrary_data,
			poseidon_native,
		);

		// Prove then verify
		let res = prove_then_verify::<Bn254, JubjubParameters, _>(
			&mut |c| mixer.gadget(c),
			1 << 17,
			None,
		);
		match res {
			Ok(()) => (),
			Err(err) => panic!("Unexpected error: {:?}", err),
		};
	}

	#[test]
	fn should_fail_with_invalid_root_plonk() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;

		let params = setup_params(curve, 5, 3);
		let poseidon_native = PoseidonBn254 { params };

		// Randomly generated secrets
		let secret = Fq::rand(rng);
		let nullifier = Fq::rand(rng);

		// Public data
		let arbitrary_data = Fq::rand(rng);
		let nullifier_hash = poseidon_native.hash_two(&nullifier, &nullifier).unwrap();
		let leaf_hash = poseidon_native.hash_two(&secret, &nullifier).unwrap();

		// Create a tree whose leaves are already populated with 2^HEIGHT - 1 random
		// scalars, then add leaf_hash as the final leaf
		const HEIGHT: usize = 6usize;
		let last_index = 1 << (HEIGHT - 1) - 1;
		let mut leaves = [Fq::from(0u8); 1 << (HEIGHT - 1)];
		for i in 0..last_index {
			leaves[i] = Fq::rand(rng);
		}
		leaves[last_index] = leaf_hash;
		let tree = SparseMerkleTree::<Fq, PoseidonBn254, HEIGHT>::new_sequential(
			&leaves,
			&poseidon_native,
			&[0u8; 32],
		)
		.unwrap();
		let root = tree.root();

		// Path
		let path = tree.generate_membership_proof(last_index as u64);

		// Create MixerCircuit
		let mut mixer = MixerCircuit::<Fq, JubjubParameters, PoseidonGadget, HEIGHT>::new(
			secret,
			nullifier,
			nullifier_hash,
			path,
			root,
			arbitrary_data,
			poseidon_native,
		);

		// Use a different root for the verifier
		let verifier_public_inputs = vec![
			ToConstraintFieldHelper::from(nullifier_hash),
			ToConstraintFieldHelper::from(root.double()),
			ToConstraintFieldHelper::from(arbitrary_data),
		];
		// Prove then verify
		let res = prove_then_verify::<Bn254, JubjubParameters, _>(
			&mut |c| mixer.gadget(c),
			1 << 17,
			Some(verifier_public_inputs),
		);
		match res {
			Err(Error::ProofVerificationError) => (),
			Err(err) => panic!("Unexpected error: {:?}", err),
			Ok(()) => panic!("Proof was successfully verified when error was expected"),
		};
	}

	#[test]
	fn should_fail_with_wrong_secret_plonk() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;

		let params = setup_params(curve, 5, 3);
		let poseidon_native = PoseidonBn254 { params };

		// Randomly generated secrets
		let secret = Fq::rand(rng);
		let nullifier = Fq::rand(rng);

		// Public data
		let arbitrary_data = Fq::rand(rng);
		let nullifier_hash = poseidon_native.hash_two(&nullifier, &nullifier).unwrap();
		let leaf_hash = poseidon_native.hash_two(&secret, &nullifier).unwrap();

		// Create a tree whose leaves are already populated with 2^HEIGHT - 1 random
		// scalars, then add leaf_hash as the final leaf
		const HEIGHT: usize = 6usize;
		let last_index = 1 << (HEIGHT - 1) - 1;
		let mut leaves = [Fq::from(0u8); 1 << (HEIGHT - 1)];
		for i in 0..last_index {
			leaves[i] = Fq::rand(rng);
		}
		leaves[last_index] = leaf_hash;
		let tree = SparseMerkleTree::<Fq, PoseidonBn254, HEIGHT>::new_sequential(
			&leaves,
			&poseidon_native,
			&[0u8; 32],
		)
		.unwrap();
		let root = tree.root();

		// Path
		let path = tree.generate_membership_proof(last_index as u64);

		// An incorrect secret value to use below
		let bad_secret = secret.double();

		// Create MixerCircuit
		let mut mixer = MixerCircuit::<Fq, JubjubParameters, PoseidonGadget, HEIGHT>::new(
			bad_secret,
			nullifier,
			nullifier_hash,
			path,
			root,
			arbitrary_data,
			poseidon_native,
		);

		// Prove then verify
		let res = prove_then_verify::<Bn254, JubjubParameters, _>(
			&mut |c| mixer.gadget(c),
			1 << 17,
			None, // No need to give verifier different public data
		);
		match res {
			Err(Error::ProofVerificationError) => (),
			Err(err) => panic!("Unexpected error: {:?}", err),
			Ok(()) => panic!("Proof was successfully verified when error was expected"),
		};
	}

	#[test]
	fn should_fail_with_wrong_nullifier_plonk() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;

		let params = setup_params(curve, 5, 3);
		let poseidon_native = PoseidonBn254 { params };

		// Randomly generated secrets
		let secret = Fq::rand(rng);
		let nullifier = Fq::rand(rng);

		// Public data
		let arbitrary_data = Fq::rand(rng);
		let nullifier_hash = poseidon_native.hash_two(&nullifier, &nullifier).unwrap();
		let leaf_hash = poseidon_native.hash_two(&secret, &nullifier).unwrap();

		// Create a tree whose leaves are already populated with 2^HEIGHT - 1 random
		// scalars, then add leaf_hash as the final leaf
		const HEIGHT: usize = 6usize;
		let last_index = 1 << (HEIGHT - 1) - 1;
		let mut leaves = [Fq::from(0u8); 1 << (HEIGHT - 1)];
		for i in 0..last_index {
			leaves[i] = Fq::rand(rng);
		}
		leaves[last_index] = leaf_hash;
		let tree = SparseMerkleTree::<Fq, PoseidonBn254, HEIGHT>::new_sequential(
			&leaves,
			&poseidon_native,
			&[0u8; 32],
		)
		.unwrap();
		let root = tree.root();

		// Path
		let path = tree.generate_membership_proof(last_index as u64);

		// Use a bad nullifier value:
		let bad_nullifier = nullifier.double();

		// Create MixerCircuit
		let mut mixer = MixerCircuit::<Fq, JubjubParameters, PoseidonGadget, HEIGHT>::new(
			secret,
			bad_nullifier,
			nullifier_hash,
			path,
			root,
			arbitrary_data,
			poseidon_native,
		);

		// Prove then verify
		let res = prove_then_verify::<Bn254, JubjubParameters, _>(
			&mut |c| mixer.gadget(c),
			1 << 17,
			None, // No need to give verifier different public inputs
		);
		match res {
			Err(Error::ProofVerificationError) => (),
			Err(err) => panic!("Unexpected error: {:?}", err),
			Ok(()) => panic!("Proof was successfully verified when error was expected"),
		};
	}

	#[test]
	fn should_fail_with_wrong_path_plonk() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;

		let params = setup_params(curve, 5, 3);
		let poseidon_native = PoseidonBn254 { params };

		// Randomly generated secrets
		let secret = Fq::rand(rng);
		let nullifier = Fq::rand(rng);

		// Public data
		let arbitrary_data = Fq::rand(rng);
		let nullifier_hash = poseidon_native.hash_two(&nullifier, &nullifier).unwrap();
		let leaf_hash = poseidon_native.hash_two(&secret, &nullifier).unwrap();

		// Create a tree whose leaves are already populated with 2^HEIGHT - 1 random
		// scalars, then add leaf_hash as the final leaf
		const HEIGHT: usize = 6usize;
		let last_index = 1 << (HEIGHT - 1) - 1;
		let mut leaves = [Fq::from(0u8); 1 << (HEIGHT - 1)];
		for i in 0..last_index {
			leaves[i] = Fq::rand(rng);
		}
		leaves[last_index] = leaf_hash;
		let tree = SparseMerkleTree::<Fq, PoseidonBn254, HEIGHT>::new_sequential(
			&leaves,
			&poseidon_native,
			&[0u8; 32],
		)
		.unwrap();
		let root = tree.root();

		// An incorrect path to use below
		let bad_path = tree.generate_membership_proof((last_index as u64) - 1);

		// Create MixerCircuit
		let mut mixer = MixerCircuit::<Fq, JubjubParameters, PoseidonGadget, HEIGHT>::new(
			secret,
			nullifier,
			nullifier_hash,
			bad_path,
			root,
			arbitrary_data,
			poseidon_native,
		);

		// Prove then verify
		let res = prove_then_verify::<Bn254, JubjubParameters, _>(
			&mut |c| mixer.gadget(c),
			1 << 17,
			None, // No need to give verifier different public inputs
		);
		match res {
			Err(Error::ProofVerificationError) => (),
			Err(err) => panic!("Unexpected error: {:?}", err),
			Ok(()) => panic!("Proof was successfully verified when error was expected"),
		};
	}

	#[test]
	fn should_fail_with_wrong_nullifier_hash_plonk() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;

		let params = setup_params(curve, 5, 3);
		let poseidon_native = PoseidonBn254 { params };

		// Randomly generated secrets
		let secret = Fq::rand(rng);
		let nullifier = Fq::rand(rng);

		// Public data
		let arbitrary_data = Fq::rand(rng);
		let nullifier_hash = poseidon_native.hash_two(&nullifier, &nullifier).unwrap();
		let leaf_hash = poseidon_native.hash_two(&secret, &nullifier).unwrap();

		// Create a tree whose leaves are already populated with 2^HEIGHT - 1 random
		// scalars, then add leaf_hash as the final leaf
		const HEIGHT: usize = 6usize;
		let last_index = 1 << (HEIGHT - 1) - 1;
		let mut leaves = [Fq::from(0u8); 1 << (HEIGHT - 1)];
		for i in 0..last_index {
			leaves[i] = Fq::rand(rng);
		}
		leaves[last_index] = leaf_hash;
		let tree = SparseMerkleTree::<Fq, PoseidonBn254, HEIGHT>::new_sequential(
			&leaves,
			&poseidon_native,
			&[0u8; 32],
		)
		.unwrap();
		let root = tree.root();

		// Path
		let path = tree.generate_membership_proof(last_index as u64);

		// Create MixerCircuit
		let mut mixer = MixerCircuit::<Fq, JubjubParameters, PoseidonGadget, HEIGHT>::new(
			secret,
			nullifier,
			nullifier_hash,
			path,
			root,
			arbitrary_data,
			poseidon_native,
		);

		// Give the verifier a different nullifier hash
		let verifier_public_inputs = vec![
			ToConstraintFieldHelper::from(nullifier_hash.double()),
			ToConstraintFieldHelper::from(root),
			ToConstraintFieldHelper::from(arbitrary_data),
		];
		// Prove then verify
		let res = prove_then_verify::<Bn254, JubjubParameters, _>(
			&mut |c| mixer.gadget(c),
			1 << 17,
			Some(verifier_public_inputs),
		);
		match res {
			Err(Error::ProofVerificationError) => (),
			Err(err) => panic!("Unexpected error: {:?}", err),
			Ok(()) => panic!("Proof was successfully verified when error was expected"),
		};
	}

	#[test]
	fn should_fail_with_wrong_arbitrary_data_plonk() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;

		let params = setup_params(curve, 5, 3);
		let poseidon_native = PoseidonBn254 { params };

		// Randomly generated secrets
		let secret = Fq::rand(rng);
		let nullifier = Fq::rand(rng);

		// Public data
		let arbitrary_data = Fq::rand(rng);
		let nullifier_hash = poseidon_native.hash_two(&nullifier, &nullifier).unwrap();
		let leaf_hash = poseidon_native.hash_two(&secret, &nullifier).unwrap();

		// Create a tree whose leaves are already populated with 2^HEIGHT - 1 random
		// scalars, then add leaf_hash as the final leaf
		const HEIGHT: usize = 6usize;
		let last_index = 1 << (HEIGHT - 1) - 1;
		let mut leaves = [Fq::from(0u8); 1 << (HEIGHT - 1)];
		for i in 0..last_index {
			leaves[i] = Fq::rand(rng);
		}
		leaves[last_index] = leaf_hash;
		let tree = SparseMerkleTree::<Fq, PoseidonBn254, HEIGHT>::new_sequential(
			&leaves,
			&poseidon_native,
			&[0u8; 32],
		)
		.unwrap();
		let root = tree.root();

		// Path
		let path = tree.generate_membership_proof(last_index as u64);

		// Create MixerCircuit
		let mut mixer = MixerCircuit::<Fq, JubjubParameters, PoseidonGadget, HEIGHT>::new(
			secret,
			nullifier,
			nullifier_hash,
			path,
			root,
			arbitrary_data,
			poseidon_native,
		);

		// Give the verifier different arbitrary data
		let verifier_public_inputs = vec![
			ToConstraintFieldHelper::from(nullifier_hash),
			ToConstraintFieldHelper::from(root),
			ToConstraintFieldHelper::from(arbitrary_data.double()),
		];
		// Prove then verify
		let res = prove_then_verify::<Bn254, JubjubParameters, _>(
			&mut |c| mixer.gadget(c),
			1 << 17,
			Some(verifier_public_inputs),
		);
		match res {
			Err(Error::ProofVerificationError) => (),
			Err(err) => panic!("Unexpected error: {:?}", err),
			Ok(()) => panic!("Proof was successfully verified when error was expected"),
		};
	}
}
