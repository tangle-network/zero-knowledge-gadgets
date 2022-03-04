use crate::utils::add_public_input_variable;
use ark_ec::models::TEModelParameters;
use ark_ff::PrimeField;
use arkworks_native_gadgets::merkle_tree::Path;
use arkworks_plonk_gadgets::{
	merkle_tree::PathGadget, poseidon::FieldHasherGadget, set::check_set_membership,
};
use plonk_core::{circuit::Circuit, constraint_system::StandardComposer, error::Error};

pub struct AnchorCircuit<
	F: PrimeField,
	P: TEModelParameters<BaseField = F>,
	HG: FieldHasherGadget<F, P>,
	const N: usize,
	const M: usize,
> {
	chain_id: F,
	secret: F,
	nullifier: F,
	nullifier_hash: F,
	path: Path<F, HG::Native, N>,
	roots: [F; M],
	arbitrary_data: F,
	hasher_two: HG::Native,   // Arity 2 hasher
	hasher_three: HG::Native, // Arity 3 hasher
}

impl<F, P, HG, const N: usize, const M: usize> AnchorCircuit<F, P, HG, N, M>
where
	F: PrimeField,
	P: TEModelParameters<BaseField = F>,
	HG: FieldHasherGadget<F, P>,
{
	pub fn new(
		chain_id: F,
		secret: F,
		nullifier: F,
		nullifier_hash: F,
		path: Path<F, HG::Native, N>,
		roots: [F; M],
		arbitrary_data: F,
		hasher_two: HG::Native,
		hasher_three: HG::Native,
	) -> Self {
		Self {
			chain_id,
			secret,
			nullifier,
			nullifier_hash,
			path,
			roots,
			arbitrary_data,
			hasher_two,
			hasher_three,
		}
	}
}

impl<F, P, HG, const N: usize, const M: usize> Circuit<F, P> for AnchorCircuit<F, P, HG, N, M>
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
		let chain_id = add_public_input_variable(composer, self.chain_id);
		let nullifier_hash = add_public_input_variable(composer, self.nullifier_hash);
		let arbitrary_data = add_public_input_variable(composer, self.arbitrary_data);

		// Create the hasher gadgets from native
		let hasher_gadget_two: HG =
			FieldHasherGadget::<F, P>::from_native(composer, self.hasher_two.clone());
		let hasher_gadget_three: HG =
			FieldHasherGadget::<F, P>::from_native(composer, self.hasher_three.clone());

		// Preimage proof of nullifier
		let res_nullifier = hasher_gadget_two.hash_two(composer, &nullifier, &nullifier)?;
		// TODO: (This has 1 more gate than skipping the nullifier_hash variable and
		// putting this straight in to a poly_gate)
		composer.assert_equal(res_nullifier, nullifier_hash);

		// Preimage proof of leaf hash
		// leaf should be hash of [chain_id, secret, nullifier]
		let res_leaf = hasher_gadget_three.hash(composer, &[chain_id, secret, nullifier])?;

		// Proof of Merkle tree set membership
		let calculated_root =
			path_gadget.calculate_root(composer, &res_leaf, &hasher_gadget_two)?;
		let result = check_set_membership(composer, &self.roots.to_vec(), calculated_root);
		let one = composer.add_witness_to_circuit_description(F::one());
		composer.assert_equal(result, one);

		// Safety constraint to prevent tampering with arbitrary_data
		let _arbitrary_data_squared = composer.arithmetic_gate(|gate| {
			gate.witness(arbitrary_data, arbitrary_data, None)
				.mul(F::one())
		});
		Ok(())
	}

	fn padded_circuit_size(&self) -> usize {
		1 << 19
	}
}

#[cfg(test)]
mod test {
	use super::AnchorCircuit;
	use crate::utils::prove_then_verify;
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

	type PoseidonBn254 = Poseidon<Fq>;
	const BRIDGE_SIZE: usize = 2;

	#[test]
	fn should_verify_correct_anchor_plonk() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;

		// These poseidon hashers are named after their WIDTH, not ARITY.
		// So `poseidon_native_three` is for hashing 2 elements together, not 3.
		let params_three = setup_params(curve, 5, 3);
		let params_four = setup_params(curve, 5, 4);
		let poseidon_native_three = PoseidonBn254 {
			params: params_three,
		};
		let poseidon_native_four = PoseidonBn254 {
			params: params_four,
		};

		// Randomly generated secrets
		let secret = Fq::rand(rng);
		let nullifier = Fq::rand(rng);

		// Public data
		let chain_id = Fq::from(1u32);
		let arbitrary_data = Fq::rand(rng);
		let nullifier_hash = poseidon_native_three
			.hash_two(&nullifier, &nullifier)
			.unwrap();
		let leaf_hash = poseidon_native_four
			.hash(&[chain_id, secret, nullifier])
			.unwrap();

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
			&poseidon_native_three,
			&[0u8; 32],
		)
		.unwrap();

		// Path
		let path = tree.generate_membership_proof(last_index as u64);

		let mut roots = [Fq::from(0u8); BRIDGE_SIZE];
		roots[0] = tree.root();

		// Create AnchorCircuit
		let mut anchor =
			AnchorCircuit::<Fq, JubjubParameters, PoseidonGadget, HEIGHT, BRIDGE_SIZE>::new(
				chain_id,
				secret,
				nullifier,
				nullifier_hash,
				path,
				roots,
				arbitrary_data,
				poseidon_native_three,
				poseidon_native_four,
			);

		let res = prove_then_verify::<Bn254, JubjubParameters, _>(
			&mut |c| anchor.gadget(c),
			1 << 15,
			None,
		);
		// Assert that verification was successful
		match res {
			Ok(()) => (),
			Err(err) => panic!("Unexpected error: {:?}", err),
		};
	}

	#[test]
	fn should_fail_with_invalid_secret_plonk() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;

		// These poseidon hashers are named after their WIDTH, not ARITY.
		// So `poseidon_native_three` is for hashing 2 elements together, not 3.
		let params_three = setup_params(curve, 5, 3);
		let params_four = setup_params(curve, 5, 4);
		let poseidon_native_three = PoseidonBn254 {
			params: params_three,
		};
		let poseidon_native_four = PoseidonBn254 {
			params: params_four,
		};

		// Randomly generated secrets
		let secret = Fq::rand(rng);
		let nullifier = Fq::rand(rng);

		// Public data
		let chain_id = Fq::from(1u32);
		let arbitrary_data = Fq::rand(rng);
		let nullifier_hash = poseidon_native_three
			.hash_two(&nullifier, &nullifier)
			.unwrap();
		let leaf_hash = poseidon_native_four
			.hash(&[chain_id, secret, nullifier])
			.unwrap();

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
			&poseidon_native_three,
			&[0u8; 32],
		)
		.unwrap();

		// Path
		let path = tree.generate_membership_proof(last_index as u64);

		let mut roots = [Fq::from(0u8); BRIDGE_SIZE];
		roots[0] = tree.root();

		// Use the wrong secret:
		let bad_secret = secret.double();

		// Create AnchorCircuit
		let mut anchor =
			AnchorCircuit::<Fq, JubjubParameters, PoseidonGadget, HEIGHT, BRIDGE_SIZE>::new(
				chain_id,
				bad_secret,
				nullifier,
				nullifier_hash,
				path,
				roots,
				arbitrary_data,
				poseidon_native_three,
				poseidon_native_four,
			);

		let res = prove_then_verify::<Bn254, JubjubParameters, _>(
			&mut |c| anchor.gadget(c),
			1 << 17,
			None,
		);
		// Assert that verification failed
		match res {
			Err(Error::ProofVerificationError) => (),
			Err(err) => panic!("Unexpected error: {:?}", err),
			Ok(()) => panic!("Proof was successfully verified when error was expected"),
		};
	}

	#[test]
	fn should_fail_with_invalid_nullifier_plonk() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;

		// These poseidon hashers are named after their WIDTH, not ARITY.
		// So `poseidon_native_three` is for hashing 2 elements together, not 3.
		let params_three = setup_params(curve, 5, 3);
		let params_four = setup_params(curve, 5, 4);
		let poseidon_native_three = PoseidonBn254 {
			params: params_three,
		};
		let poseidon_native_four = PoseidonBn254 {
			params: params_four,
		};

		// Randomly generated secrets
		let secret = Fq::rand(rng);
		let nullifier = Fq::rand(rng);

		// Public data
		let chain_id = Fq::from(1u32);
		let arbitrary_data = Fq::rand(rng);
		let nullifier_hash = poseidon_native_three
			.hash_two(&nullifier, &nullifier)
			.unwrap();
		let leaf_hash = poseidon_native_four
			.hash(&[chain_id, secret, nullifier])
			.unwrap();

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
			&poseidon_native_three,
			&[0u8; 32],
		)
		.unwrap();

		// Path
		let path = tree.generate_membership_proof(last_index as u64);

		let mut roots = [Fq::from(0u8); BRIDGE_SIZE];
		roots[0] = tree.root();

		// Use the wrong nullifier:
		let bad_nullifier = nullifier.double();

		// Create AnchorCircuit
		let mut anchor =
			AnchorCircuit::<Fq, JubjubParameters, PoseidonGadget, HEIGHT, BRIDGE_SIZE>::new(
				chain_id,
				secret,
				bad_nullifier,
				nullifier_hash,
				path,
				roots,
				arbitrary_data,
				poseidon_native_three,
				poseidon_native_four,
			);

		let res = prove_then_verify::<Bn254, JubjubParameters, _>(
			&mut |c| anchor.gadget(c),
			1 << 17,
			None,
		);
		// Assert that verification failed
		match res {
			Err(Error::ProofVerificationError) => (),
			Err(err) => panic!("Unexpected error: {:?}", err),
			Ok(()) => panic!("Proof was successfully verified when error was expected"),
		};
	}

	#[test]
	fn should_fail_with_invalid_path_plonk() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;

		// These poseidon hashers are named after their WIDTH, not ARITY.
		// So `poseidon_native_three` is for hashing 2 elements together, not 3.
		let params_three = setup_params(curve, 5, 3);
		let params_four = setup_params(curve, 5, 4);
		let poseidon_native_three = PoseidonBn254 {
			params: params_three,
		};
		let poseidon_native_four = PoseidonBn254 {
			params: params_four,
		};

		// Randomly generated secrets
		let secret = Fq::rand(rng);
		let nullifier = Fq::rand(rng);

		// Public data
		let chain_id = Fq::from(1u32);
		let arbitrary_data = Fq::rand(rng);
		let nullifier_hash = poseidon_native_three
			.hash_two(&nullifier, &nullifier)
			.unwrap();
		let leaf_hash = poseidon_native_four
			.hash(&[chain_id, secret, nullifier])
			.unwrap();

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
			&poseidon_native_three,
			&[0u8; 32],
		)
		.unwrap();

		let mut roots = [Fq::from(0u8); BRIDGE_SIZE];
		roots[0] = tree.root();

		// Use an invalid path
		let bad_path = tree.generate_membership_proof((last_index - 1) as u64);

		// Create AnchorCircuit
		let mut anchor =
			AnchorCircuit::<Fq, JubjubParameters, PoseidonGadget, HEIGHT, BRIDGE_SIZE>::new(
				chain_id,
				secret,
				nullifier,
				nullifier_hash,
				bad_path,
				roots,
				arbitrary_data,
				poseidon_native_three,
				poseidon_native_four,
			);

		let res = prove_then_verify::<Bn254, JubjubParameters, _>(
			&mut |c| anchor.gadget(c),
			1 << 17,
			None,
		);
		// Assert that verification failed
		match res {
			Err(Error::ProofVerificationError) => (),
			Err(err) => panic!("Unexpected error: {:?}", err),
			Ok(()) => panic!("Proof was successfully verified when error was expected"),
		};
	}

	#[test]
	fn should_fail_with_invalid_root_plonk() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;

		// These poseidon hashers are named after their WIDTH, not ARITY.
		// So `poseidon_native_three` is for hashing 2 elements together, not 3.
		let params_three = setup_params(curve, 5, 3);
		let params_four = setup_params(curve, 5, 4);
		let poseidon_native_three = PoseidonBn254 {
			params: params_three,
		};
		let poseidon_native_four = PoseidonBn254 {
			params: params_four,
		};

		// Randomly generated secrets
		let secret = Fq::rand(rng);
		let nullifier = Fq::rand(rng);

		// Public data
		let chain_id = Fq::from(1u32);
		let arbitrary_data = Fq::rand(rng);
		let nullifier_hash = poseidon_native_three
			.hash_two(&nullifier, &nullifier)
			.unwrap();
		let leaf_hash = poseidon_native_four
			.hash(&[chain_id, secret, nullifier])
			.unwrap();

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
			&poseidon_native_three,
			&[0u8; 32],
		)
		.unwrap();

		// Path
		let path = tree.generate_membership_proof(last_index as u64);

		let mut roots = [Fq::from(0u8); BRIDGE_SIZE];
		roots[0] = tree.root();

		// Create AnchorCircuit
		let mut anchor =
			AnchorCircuit::<Fq, JubjubParameters, PoseidonGadget, HEIGHT, BRIDGE_SIZE>::new(
				chain_id,
				secret,
				nullifier,
				nullifier_hash,
				path,
				roots,
				arbitrary_data,
				poseidon_native_three,
				poseidon_native_four,
			);

		// Prover and verifier disagree on public inputs:
		// The order of public inputs is [chain_id, nullifier_hash,
		// arbitrary_data, roots ] (Uncomment the following block to verify that)
		// let mut composer = StandardComposer::<Fq, JubjubParameters>::new();
		// let _ = anchor.gadget(&mut composer);
		// println!("The public input positions are {:?}", composer.pi_positions());
		// let prover_pi = composer.construct_dense_pi_vec();
		// assert_eq!(
		// 	[prover_pi[3], prover_pi[4], prover_pi[5], prover_pi[14355],
		// prover_pi[14356]], 	[chain_id, nullifier_hash, arbitrary_data, roots[0],
		// roots[1]]);
		let verifier_pi = vec![
			chain_id,
			nullifier_hash,
			arbitrary_data,
			roots[0].double(), // Verifier has different root set
			roots[1],
		];
		let res = prove_then_verify::<Bn254, JubjubParameters, _>(
			&mut |c| anchor.gadget(c),
			1 << 17,
			Some(verifier_pi),
		);
		// // Assert that verification failed
		match res {
			Err(Error::ProofVerificationError) => (),
			Err(err) => panic!("Unexpected error: {:?}", err),
			Ok(()) => panic!("Proof was successfully verified when error wasexpected"),
		};
	}

	#[test]
	fn should_fail_with_invalid_nullifier_hash_plonk() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;

		// These poseidon hashers are named after their WIDTH, not ARITY.
		// So `poseidon_native_three` is for hashing 2 elements together, not 3.
		let params_three = setup_params(curve, 5, 3);
		let params_four = setup_params(curve, 5, 4);
		let poseidon_native_three = PoseidonBn254 {
			params: params_three,
		};
		let poseidon_native_four = PoseidonBn254 {
			params: params_four,
		};

		// Randomly generated secrets
		let secret = Fq::rand(rng);
		let nullifier = Fq::rand(rng);

		// Public data
		let chain_id = Fq::from(1u32);
		let arbitrary_data = Fq::rand(rng);
		let nullifier_hash = poseidon_native_three
			.hash_two(&nullifier, &nullifier)
			.unwrap();
		let leaf_hash = poseidon_native_four
			.hash(&[chain_id, secret, nullifier])
			.unwrap();

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
			&poseidon_native_three,
			&[0u8; 32],
		)
		.unwrap();

		// Path
		let path = tree.generate_membership_proof(last_index as u64);

		let mut roots = [Fq::from(0u8); BRIDGE_SIZE];
		roots[0] = tree.root();

		// Create AnchorCircuit
		let mut anchor =
			AnchorCircuit::<Fq, JubjubParameters, PoseidonGadget, HEIGHT, BRIDGE_SIZE>::new(
				chain_id,
				secret,
				nullifier,
				nullifier_hash,
				path,
				roots,
				arbitrary_data,
				poseidon_native_three,
				poseidon_native_four,
			);

		// Prover and verifier disagree on public inputs:
		// The order of public inputs is [chain_id, nullifier_hash,
		// arbitrary_data, roots ]
		let verifier_pi = vec![
			chain_id,
			nullifier_hash.double(), // Verifier has different nullifier hash
			arbitrary_data,
			roots[0],
			roots[1],
		];
		let res = prove_then_verify::<Bn254, JubjubParameters, _>(
			&mut |c| anchor.gadget(c),
			1 << 17,
			Some(verifier_pi),
		);
		// // Assert that verification failed
		match res {
			Err(Error::ProofVerificationError) => (),
			Err(err) => panic!("Unexpected error: {:?}", err),
			Ok(()) => panic!("Proof was successfully verified when error wasexpected"),
		};
	}

	#[test]
	fn should_fail_with_invalid_arbitrary_data_plonk() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;

		// These poseidon hashers are named after their WIDTH, not ARITY.
		// So `poseidon_native_three` is for hashing 2 elements together, not 3.
		let params_three = setup_params(curve, 5, 3);
		let params_four = setup_params(curve, 5, 4);
		let poseidon_native_three = PoseidonBn254 {
			params: params_three,
		};
		let poseidon_native_four = PoseidonBn254 {
			params: params_four,
		};

		// Randomly generated secrets
		let secret = Fq::rand(rng);
		let nullifier = Fq::rand(rng);

		// Public data
		let chain_id = Fq::from(1u32);
		let arbitrary_data = Fq::rand(rng);
		let nullifier_hash = poseidon_native_three
			.hash_two(&nullifier, &nullifier)
			.unwrap();
		let leaf_hash = poseidon_native_four
			.hash(&[chain_id, secret, nullifier])
			.unwrap();

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
			&poseidon_native_three,
			&[0u8; 32],
		)
		.unwrap();

		// Path
		let path = tree.generate_membership_proof(last_index as u64);

		let mut roots = [Fq::from(0u8); BRIDGE_SIZE];
		roots[0] = tree.root();

		// Create AnchorCircuit
		let mut anchor =
			AnchorCircuit::<Fq, JubjubParameters, PoseidonGadget, HEIGHT, BRIDGE_SIZE>::new(
				chain_id,
				secret,
				nullifier,
				nullifier_hash,
				path,
				roots,
				arbitrary_data,
				poseidon_native_three,
				poseidon_native_four,
			);

		// Prover and verifier disagree on public inputs:
		// The order of public inputs is [chain_id, nullifier_hash,
		// arbitrary_data, roots ]
		let verifier_pi = vec![
			chain_id,
			nullifier_hash,
			arbitrary_data.double(), // Verifier has different arbitrary data
			roots[0],
			roots[1],
		];
		let res = prove_then_verify::<Bn254, JubjubParameters, _>(
			&mut |c| anchor.gadget(c),
			1 << 17,
			Some(verifier_pi),
		);
		// // Assert that verification failed
		match res {
			Err(Error::ProofVerificationError) => (),
			Err(err) => panic!("Unexpected error: {:?}", err),
			Ok(()) => panic!("Proof was successfully verified when error wasexpected"),
		};
	}

	#[test]
	fn should_fail_with_invalid_chain_id_plonk() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;

		// These poseidon hashers are named after their WIDTH, not ARITY.
		// So `poseidon_native_three` is for hashing 2 elements together, not 3.
		let params_three = setup_params(curve, 5, 3);
		let params_four = setup_params(curve, 5, 4);
		let poseidon_native_three = PoseidonBn254 {
			params: params_three,
		};
		let poseidon_native_four = PoseidonBn254 {
			params: params_four,
		};

		// Randomly generated secrets
		let secret = Fq::rand(rng);
		let nullifier = Fq::rand(rng);

		// Public data
		let chain_id = Fq::from(1u32);
		let arbitrary_data = Fq::rand(rng);
		let nullifier_hash = poseidon_native_three
			.hash_two(&nullifier, &nullifier)
			.unwrap();
		let leaf_hash = poseidon_native_four
			.hash(&[chain_id, secret, nullifier])
			.unwrap();

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
			&poseidon_native_three,
			&[0u8; 32],
		)
		.unwrap();

		// Path
		let path = tree.generate_membership_proof(last_index as u64);

		let mut roots = [Fq::from(0u8); BRIDGE_SIZE];
		roots[0] = tree.root();

		// Create AnchorCircuit
		let mut anchor =
			AnchorCircuit::<Fq, JubjubParameters, PoseidonGadget, HEIGHT, BRIDGE_SIZE>::new(
				chain_id,
				secret,
				nullifier,
				nullifier_hash,
				path,
				roots,
				arbitrary_data,
				poseidon_native_three,
				poseidon_native_four,
			);

		// Prover and verifier disagree on public inputs:
		// The order of public inputs is [chain_id, nullifier_hash,
		// arbitrary_data, roots ]
		let verifier_pi = vec![
			chain_id.double(), // Verifier has different chain id
			nullifier_hash,
			arbitrary_data,
			roots[0],
			roots[1],
		];
		let res = prove_then_verify::<Bn254, JubjubParameters, _>(
			&mut |c| anchor.gadget(c),
			1 << 17,
			Some(verifier_pi),
		);
		// // Assert that verification failed
		match res {
			Err(Error::ProofVerificationError) => (),
			Err(err) => panic!("Unexpected error: {:?}", err),
			Ok(()) => panic!("Proof was successfully verified when error wasexpected"),
		};
	}
}
