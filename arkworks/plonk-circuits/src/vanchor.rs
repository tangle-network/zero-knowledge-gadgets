// VAnchor is the variable deposit/withdraw/transfer shielded pool
// It supports join split transactions, meaning you can take unspent deposits
// in the pool and join them together, split them, and any combination
// of the two.

// The inputs to the VAnchor are unspent outputs we want to spend (we are
// spending the inputs), and we create outputs which are new, unspent UTXOs. We
// create commitments for each output and these are inserted into merkle trees.

// The VAnchor is also a bridged system. It takes as a public input
// a set of merkle roots that it will use to verify the membership
// of unspent deposits within. The VAnchor prevents double-spending
// through the use of a public input chain identifier `chain_id`.

// We will take inputs and do a merkle tree reconstruction for each input.
// Then we will verify that the reconstructed root from each input's
// membership path is within a set of public merkle roots.

use ark_ec::models::TEModelParameters;
use ark_ff::PrimeField;
use arkworks_native_gadgets::merkle_tree::Path;
use arkworks_plonk_gadgets::{
	add_public_input_variable, add_public_input_variables, merkle_tree::PathGadget,
	poseidon::FieldHasherGadget, set::SetGadget,
};
use plonk_core::{circuit::Circuit, constraint_system::StandardComposer, error::Error};

pub struct VariableAnchorCircuit<
	F: PrimeField,
	P: TEModelParameters<BaseField = F>,
	HG: FieldHasherGadget<F, P>,
	// Tree height
	const N: usize,
	// Size of the root set (bridge length)
	const M: usize,
	// Number of inputs
	const INS: usize,
	// Number of outputs
	const OUTS: usize,
> {
	// sum of input amounts + public amount == sum of output amounts
	public_amount: F,   // Public
	public_chain_id: F, // Public

	// Input transactions
	in_amounts: [F; INS],
	in_blindings: [F; INS],
	in_nullifier_hashes: [F; INS], // Public
	in_private_keys: [F; INS],
	in_paths: [Path<F, HG::Native, N>; INS],
	in_indices: [F; INS],
	in_root_set: [F; M],

	// Output transactions
	out_amounts: [F; OUTS],
	out_blindings: [F; OUTS],
	out_chain_ids: [F; OUTS],
	out_public_keys: [F; OUTS],
	out_commitments: [F; OUTS], // Public

	// Arbitrary data to be added to the transcript
	arbitrary_data: F, // Public

	// All the hashers used in this circuit
	// Used for hashing private_key -- width 2
	public_key_hasher: HG::Native,
	// Used for hashing nodes in the tree -- width 3
	tree_hasher: HG::Native,
	// Used for creating leaf signature and the nullifier hash -- width 4
	signature_hasher: HG::Native,
	// Used for creating leaf -- width 5
	leaf_hasher: HG::Native,
}

impl<F, P, HG, const N: usize, const M: usize, const INS: usize, const OUTS: usize>
	VariableAnchorCircuit<F, P, HG, N, M, INS, OUTS>
where
	F: PrimeField,
	P: TEModelParameters<BaseField = F>,
	HG: FieldHasherGadget<F, P>,
{
	pub fn new(
		public_amount: F,
		public_chain_id: F,
		in_amounts: [F; INS],
		in_blindings: [F; INS],
		in_nullifier_hashes: [F; INS],
		in_private_keys: [F; INS],
		in_paths: [Path<F, HG::Native, N>; INS],
		in_indices: [F; INS],
		in_root_set: [F; M],
		out_amounts: [F; OUTS],
		out_blindings: [F; OUTS],
		out_chain_ids: [F; OUTS],
		out_public_keys: [F; OUTS],
		out_commitments: [F; OUTS],
		arbitrary_data: F,
		public_key_hasher: HG::Native,
		tree_hasher: HG::Native,
		signature_hasher: HG::Native,
		leaf_hasher: HG::Native,
	) -> Self {
		Self {
			public_amount,
			public_chain_id,
			in_amounts,
			in_blindings,
			in_nullifier_hashes,
			in_private_keys,
			in_paths,
			in_indices,
			in_root_set,
			out_amounts,
			out_blindings,
			out_chain_ids,
			out_public_keys,
			out_commitments,
			arbitrary_data,
			public_key_hasher,
			tree_hasher,
			signature_hasher,
			leaf_hasher,
		}
	}
}

impl<F, P, HG, const N: usize, const M: usize, const INS: usize, const OUTS: usize> Circuit<F, P>
	for VariableAnchorCircuit<F, P, HG, N, M, INS, OUTS>
where
	F: PrimeField,
	P: TEModelParameters<BaseField = F>,
	HG: FieldHasherGadget<F, P>,
{
	const CIRCUIT_ID: [u8; 32] = [0xff; 32];

	fn gadget(&mut self, composer: &mut StandardComposer<F, P>) -> Result<(), Error> {
		// Initialize public inputs
		let public_amount = add_public_input_variable(composer, self.public_amount);
		let arbitrary_data = add_public_input_variable(composer, self.arbitrary_data);
		// Allocate nullifier hashes
		let nullifier_hash_vars =
			add_public_input_variables(composer, self.in_nullifier_hashes.to_vec());
		// Allocate output commitments
		let commitment_vars = add_public_input_variables(composer, self.out_commitments.to_vec());
		let public_chain_id = add_public_input_variable(composer, self.public_chain_id);
		let set_gadget = SetGadget::from_native(composer, self.in_root_set.to_vec());

		// Initialize hashers
		let pk_hasher_gadget: HG =
			FieldHasherGadget::<F, P>::from_native(composer, self.public_key_hasher.clone());
		let tree_hasher_gadget: HG =
			FieldHasherGadget::<F, P>::from_native(composer, self.tree_hasher.clone());
		let sig_hasher_gadget: HG =
			FieldHasherGadget::<F, P>::from_native(composer, self.signature_hasher.clone());
		let leaf_hasher_gadget: HG =
			FieldHasherGadget::<F, P>::from_native(composer, self.leaf_hasher.clone());

		// Sum of input amounts + public amount must equal output amounts at the end
		let mut input_sum = public_amount;
		let mut output_sum = composer.zero_var();

		// General strategy
		// 1. Reconstruct the commitments (along the way reconstruct other values)
		// 2. Reconstruct the target merkle root with the input's merkle path
		// 3. Verify that the target merkle root is within the root set
		// 4. Sum the input amounts
		for i in 0..INS {
			// Private inputs for each input UTXO being spent
			let in_private_key_i = composer.add_input(self.in_private_keys[i]);
			let in_amount_i = composer.add_input(self.in_amounts[i]);
			let in_blinding_i = composer.add_input(self.in_blindings[i]);
			let in_index_i = composer.add_input(self.in_indices[i]);
			let path_gadget =
				PathGadget::<F, P, HG, N>::from_native(composer, self.in_paths[i].clone());

			// Computing the public key, which is done just by hashing the private key
			let calc_public_key = pk_hasher_gadget.hash(composer, &[in_private_key_i])?;

			// Computing the leaf
			let calc_leaf = leaf_hasher_gadget.hash(composer, &[
				public_chain_id,
				in_amount_i,
				calc_public_key,
				in_blinding_i,
			])?;

			// Computing the signature: sign(private_key, leaf, input_index)
			let calc_signature =
				sig_hasher_gadget.hash(composer, &[in_private_key_i, calc_leaf, in_index_i])?;

			// Computing the nullifier hash. This is used to prevent spending
			// already spent UTXOs.
			let calc_nullifier =
				sig_hasher_gadget.hash(composer, &[calc_leaf, in_index_i, calc_signature])?;

			// Checking if the passed nullifier hash is the same as the calculated one
			// Optimized version of allocating public nullifier input and constraining
			// to the calculated one.
			composer.assert_equal(calc_nullifier, nullifier_hash_vars[i]);

			// Calculate the root hash
			let calc_root_hash =
				path_gadget.calculate_root(composer, &calc_leaf, &tree_hasher_gadget)?;

			// Check if calculated root hash is in the set
			// Note that if `in_amount_i = 0` then the input is a
			// "dummy" input, so the check is not needed.  The
			// `check_set_membership_is_enabled` function accounts for this.
			let is_member =
				set_gadget.check_set_membership_is_enabled(composer, calc_root_hash, in_amount_i);
			composer.constrain_to_constant(is_member, F::one(), None);

			// Finally add the amount to the sum
			// TODO: Investigate improvements to accumulating sums
			input_sum = composer.arithmetic_gate(|gate| {
				gate.witness(input_sum, in_amount_i, None)
					.add(F::one(), F::one())
			});
		}

		// Check all the nullifiers are unique to prevent double-spending
		// TODO: Investigate checking nullifier uniqueness this check to the application
		// side
		for i in 0..INS {
			for j in (i + 1)..INS {
				let result =
					composer.is_eq_with_output(nullifier_hash_vars[i], nullifier_hash_vars[j]);
				composer.assert_equal(result, composer.zero_var());
			}
		}

		for i in 0..OUTS {
			let out_chain_id_i = composer.add_input(self.out_chain_ids[i]);
			let out_amount_i = composer.add_input(self.out_amounts[i]);
			let out_public_key_i = composer.add_input(self.out_public_keys[i]);
			let out_blinding_i = composer.add_input(self.out_blindings[i]);
			// Calculate the leaf commitment
			let calc_leaf = leaf_hasher_gadget.hash(composer, &[
				out_chain_id_i,
				out_amount_i,
				out_public_key_i,
				out_blinding_i,
			])?;

			// Check if calculated leaf is the same as the passed one
			composer.assert_equal(calc_leaf, commitment_vars[i]);

			// Each amount should not be greater than the limit constant
			// TODO: The field size can be gotten as F::size_in_bits()
			// What is the correct transaction limit?
			// Each amount should be less than (field size)/2 to prevent
			// overflow, which suggests that F::size_in_bits() - 1 would
			// be small enough.  Maybe use F::size_in_bits() - 100 to be safe?
			composer.range_gate(out_amount_i, 254);

			// Add in to the sum
			output_sum = composer.arithmetic_gate(|gate| {
				gate.witness(output_sum, out_amount_i, None)
					.add(F::one(), F::one())
			});
		}

		composer.assert_equal(input_sum, output_sum);

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
	use std::marker::PhantomData;

	use super::VariableAnchorCircuit;
	use crate::utils::prove_then_verify;
	use ark_bn254::Bn254;
	use ark_ed_on_bn254::{EdwardsParameters as JubjubParameters, Fq};
	use ark_ff::{Field, PrimeField};
	use ark_std::{test_rng, UniformRand};
	use arkworks_native_gadgets::{
		merkle_tree::{Path, SparseMerkleTree},
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

	// Helper that outputs the hash functions of each width we need.
	// I have not made this generic over the curve
	fn make_vanchor_hashers() -> [PoseidonBn254; 4] {
		let curve = Curve::Bn254;

		let params2 = setup_params::<Fq>(curve, 5, 2);
		let poseidon_native2 = PoseidonBn254 { params: params2 };
		let params3 = setup_params::<Fq>(curve, 5, 3);
		let poseidon_native3 = PoseidonBn254 { params: params3 };
		let params4 = setup_params::<Fq>(curve, 5, 4);
		let poseidon_native4 = PoseidonBn254 { params: params4 };
		let params5 = setup_params::<Fq>(curve, 5, 5);
		let poseidon_native5 = PoseidonBn254 { params: params5 };

		[
			poseidon_native2,
			poseidon_native3,
			poseidon_native4,
			poseidon_native5,
		]
	}

	// This is the only test of a 16-2 vanchor transaction. All others
	// test 2-2 transactions.

	#[test]
	fn should_verify_correct_16_2_vanchor_plonk() {
		const TREE_HEIGHT: usize = 5;
		const BRIDGE_SIZE: usize = 2;
		const INS: usize = 16;
		const OUTS: usize = 2;

		let rng = &mut test_rng();

		let [poseidon_native2, poseidon_native3, poseidon_native4, poseidon_native5] =
			make_vanchor_hashers();

		// Randomly generated public inputs
		let public_amount = Fq::rand(rng);
		let public_chain_id = Fq::rand(rng);
		let arbitrary_data = Fq::rand(rng);

		// Randomly generated private inputs
		// Initialize arrays
		let mut in_private_keys = [Fq::from(0u64); INS];
		let mut in_blindings = [Fq::from(0u64); INS];
		let mut in_amounts = [Fq::from(0u64); INS];
		let mut in_nullifier_hashes = [Fq::from(0u64); INS];
		let mut in_leaf_hashes = [Fq::from(0u64); INS];
		let mut in_root_set = [Fq::from(0u64); BRIDGE_SIZE];

		// Default path to initialize the `in_paths` array
		let default_path = Path::<Fq, PoseidonBn254, TREE_HEIGHT> {
			path: [(Fq::from(0u64), Fq::from(0u64)); TREE_HEIGHT],
			marker: PhantomData,
		};
		let mut in_paths: [Path<_, _, TREE_HEIGHT>; INS] = [
			default_path.clone(),
			default_path.clone(),
			default_path.clone(),
			default_path.clone(),
			default_path.clone(),
			default_path.clone(),
			default_path.clone(),
			default_path.clone(),
			default_path.clone(),
			default_path.clone(),
			default_path.clone(),
			default_path.clone(),
			default_path.clone(),
			default_path.clone(),
			default_path.clone(),
			default_path,
		];

		// We index the paths from 0 to 15:
		let mut in_indices = [Fq::from(0u32); INS];
		for i in 0..INS {
			in_indices[i] = Fq::from(i as u32);
		}

		// We will let a few of the inputs be non-zero, the rest will be
		// dummy inputs
		in_amounts[0] = Fq::from(1u32);
		in_amounts[1] = Fq::from(2u32);
		in_amounts[3] = Fq::from(3u32);

		// Compute nullifier hash and leaf hash for each input
		for i in 0..INS {
			in_private_keys[i] = Fq::rand(rng);
			in_blindings[i] = Fq::rand(rng);

			// Calculate what the input nullifier hashes would be based on these:
			let public_key = poseidon_native2.hash(&in_private_keys[i..i + 1]).unwrap();
			in_leaf_hashes[i] = poseidon_native5
				.hash(&[public_chain_id, in_amounts[i], public_key, in_blindings[i]])
				.unwrap();
			let signature = poseidon_native4
				.hash(&[in_private_keys[i], in_leaf_hashes[i], in_indices[i]])
				.unwrap();
			in_nullifier_hashes[i] = poseidon_native4
				.hash(&[in_leaf_hashes[i], in_indices[i], signature])
				.unwrap();
		}

		// Now put all input leaves into a merkle tree
		// (we assume here that all came from same chain)
		let default_leaf = [0u8; 32];
		let merkle_tree = SparseMerkleTree::<Fq, PoseidonBn254, TREE_HEIGHT>::new_sequential(
			&in_leaf_hashes,
			&poseidon_native3,
			&default_leaf,
		)
		.unwrap();
		// Store the path of each leaf
		for i in 0..INS {
			in_paths[i] = merkle_tree.generate_membership_proof(i as u64);
		}

		// The root set should contain this merkle tree's root
		in_root_set[0] = merkle_tree.root();

		// Output amounts: (remember input amounts sum to 6 and there is also the public
		// amount)
		let mut out_amounts = [Fq::from(0u64); OUTS];
		out_amounts[0] = Fq::from(2u32) + public_amount;
		out_amounts[1] = Fq::from(4u32);

		// Other output quantities can be randomly generated
		let mut out_private_keys = [Fq::from(0u64); OUTS];
		let mut out_public_keys = [Fq::from(0u64); OUTS];
		let mut out_blindings = [Fq::from(0u64); OUTS];
		let mut out_chain_ids = [Fq::from(0u64); OUTS];
		let mut out_commitments = [Fq::from(0u64); OUTS];
		for i in 0..OUTS {
			out_blindings[i] = Fq::rand(rng);
			out_private_keys[i] = Fq::rand(rng);
			out_chain_ids[i] = Fq::rand(rng);
			out_public_keys[i] = poseidon_native2.hash(&out_private_keys[i..i + 1]).unwrap();
			// Compute the out commitment
			out_commitments[i] = poseidon_native5
				.hash(&[
					out_chain_ids[i],
					out_amounts[i],
					out_public_keys[i],
					out_blindings[i],
				])
				.unwrap();
		}

		// Create the VAnchor circuit
		let mut circuit = VariableAnchorCircuit::<
			Fq,
			JubjubParameters,
			PoseidonGadget,
			TREE_HEIGHT,
			BRIDGE_SIZE,
			INS,
			OUTS,
		>::new(
			public_amount,
			public_chain_id,
			in_amounts,
			in_blindings,
			in_nullifier_hashes,
			in_private_keys,
			in_paths,
			in_indices,
			in_root_set,
			out_amounts,
			out_blindings,
			out_chain_ids,
			out_public_keys,
			out_commitments,
			arbitrary_data,
			poseidon_native2,
			poseidon_native3,
			poseidon_native4,
			poseidon_native5,
		);

		// Verify proof
		let res = prove_then_verify::<Bn254, JubjubParameters, _>(
			&mut |c| circuit.gadget(c),
			1 << 22,
			None, // Use None argument to give verifier the same public input data
		);
		match res {
			Ok(()) => (),
			Err(err) => panic!("Unexpected error: {:?}", err),
		};
	}

	// All subsequent tests are for a 2-2 vanchor transaction
	const TREE_HEIGHT: usize = 3;
	const BRIDGE_SIZE: usize = 3;
	const INS: usize = 2;
	const OUTS: usize = 2;

	#[test]
	fn should_verify_correct_vanchor_plonk() {
		let rng = &mut test_rng();

		let [poseidon_native2, poseidon_native3, poseidon_native4, poseidon_native5] =
			make_vanchor_hashers();

		// Randomly generated public inputs
		let public_amount = Fq::rand(rng);
		let public_chain_id = Fq::rand(rng);
		let arbitrary_data = Fq::rand(rng);

		// Randomly generated private inputs
		// Initialize arrays
		let mut in_private_keys = [Fq::from(0u64); INS];
		let mut in_blindings = [Fq::from(0u64); INS];
		let mut in_amounts = [Fq::from(0u64); INS];
		let mut in_nullifier_hashes = [Fq::from(0u64); INS];
		let mut in_root_set = [Fq::from(0u64); BRIDGE_SIZE];

		// Default path to initialize the `in_paths` array
		let default_path = Path::<Fq, PoseidonBn254, TREE_HEIGHT> {
			path: [(Fq::from(0u64), Fq::from(0u64)); TREE_HEIGHT],
			marker: PhantomData,
		};
		let mut in_paths: [Path<_, _, TREE_HEIGHT>; INS] = [default_path.clone(), default_path];

		// We'll say the index of each input is index:
		let index = 0u64;
		let in_indices = [Fq::from(index); INS];

		// First input will be a dummy input, so its
		// data is left as zeros.  Nullifier hashes must be
		// computed properly, and we need to add a fake merkle
		// tree membership proof since the gadget checks this,
		// but the tree's root does not belong to the root set.
		let public_key = poseidon_native2.hash(&in_private_keys[0..1]).unwrap();
		let leaf = poseidon_native5
			.hash(&[public_chain_id, in_amounts[0], public_key, in_blindings[0]])
			.unwrap();
		let signature = poseidon_native4
			.hash(&[in_private_keys[0], leaf, in_indices[0]])
			.unwrap();
		in_nullifier_hashes[0] = poseidon_native4
			.hash(&[leaf, in_indices[0], signature])
			.unwrap();
		// Simulate a Merkle tree path for this dummy input
		let default_leaf = [0u8; 32];
		let merkle_tree = SparseMerkleTree::<Fq, PoseidonBn254, TREE_HEIGHT>::new_sequential(
			&[leaf],
			&poseidon_native3,
			&default_leaf,
		)
		.unwrap();
		in_paths[0] = merkle_tree.generate_membership_proof(index);

		// The remaining input can be a random number
		in_private_keys[1] = Fq::rand(rng);
		in_blindings[1] = Fq::rand(rng);
		// Multiplying by 1/20 prevents the amounts from summing to more than
		// the size of the field (at least for fewer than 20 inputs)
		in_amounts[1] = Fq::rand(rng) * (Fq::from(20u64).inverse().unwrap());

		// Calculate what the input nullifier hashes would be based on these:
		let public_key = poseidon_native2.hash(&in_private_keys[1..2]).unwrap();
		let leaf = poseidon_native5
			.hash(&[public_chain_id, in_amounts[1], public_key, in_blindings[1]])
			.unwrap();
		let signature = poseidon_native4
			.hash(&[in_private_keys[1], leaf, in_indices[1]])
			.unwrap();
		in_nullifier_hashes[1] = poseidon_native4
			.hash(&[leaf, in_indices[1], signature])
			.unwrap();

		// Simulate a Merkle tree for each input
		let default_leaf = [0u8; 32];
		let merkle_tree = SparseMerkleTree::<Fq, PoseidonBn254, TREE_HEIGHT>::new_sequential(
			&[leaf],
			&poseidon_native3,
			&default_leaf,
		)
		.unwrap();
		in_paths[1] = merkle_tree.generate_membership_proof(index);

		// Add the root of this Merkle tree to the root set.
		in_root_set[0] = merkle_tree.root();

		// Output amounts should sum to inputs plus public amount.
		// In this case the first output is 0 and the remaining output
		// contains the full value of the transaction
		let mut out_amounts = [Fq::from(0u64); OUTS];
		out_amounts[0] = in_amounts[0];
		out_amounts[1] = public_amount + in_amounts[1];

		// Other output quantities can be randomly generated
		let mut out_private_keys = [Fq::from(0u64); OUTS];
		let mut out_public_keys = [Fq::from(0u64); OUTS];
		let mut out_blindings = [Fq::from(0u64); OUTS];
		let mut out_chain_ids = [Fq::from(0u64); OUTS];
		let mut out_commitments = [Fq::from(0u64); OUTS];
		for i in 0..OUTS {
			out_blindings[i] = Fq::rand(rng);
			out_private_keys[i] = Fq::rand(rng);
			out_chain_ids[i] = Fq::rand(rng);
			out_public_keys[i] = poseidon_native2.hash(&out_private_keys[i..i + 1]).unwrap();
			// Compute the out commitment
			out_commitments[i] = poseidon_native5
				.hash(&[
					out_chain_ids[i],
					out_amounts[i],
					out_public_keys[i],
					out_blindings[i],
				])
				.unwrap();
		}

		// Create the VAnchor circuit
		let mut circuit = VariableAnchorCircuit::<
			Fq,
			JubjubParameters,
			PoseidonGadget,
			TREE_HEIGHT,
			BRIDGE_SIZE,
			INS,
			OUTS,
		>::new(
			public_amount,
			public_chain_id,
			in_amounts,
			in_blindings,
			in_nullifier_hashes,
			in_private_keys,
			in_paths,
			in_indices,
			in_root_set,
			out_amounts,
			out_blindings,
			out_chain_ids,
			out_public_keys,
			out_commitments,
			arbitrary_data,
			poseidon_native2,
			poseidon_native3,
			poseidon_native4,
			poseidon_native5,
		);

		// Verify proof
		let res = prove_then_verify::<Bn254, JubjubParameters, _>(
			&mut |c| circuit.gadget(c),
			1 << 17,
			None, // Use None argument to give verifier the same public input data
		);
		match res {
			Ok(()) => (),
			Err(err) => panic!("Unexpected error: {:?}", err),
		};
	}

	#[test]
	fn should_fail_with_invalid_root_plonk() {
		let rng = &mut test_rng();

		let [poseidon_native2, poseidon_native3, poseidon_native4, poseidon_native5] =
			make_vanchor_hashers();

		// Randomly generated public inputs
		let public_amount = Fq::rand(rng);
		let public_chain_id = Fq::rand(rng);
		let arbitrary_data = Fq::rand(rng);

		// Randomly generated private inputs
		// Initialize arrays
		let mut in_private_keys = [Fq::from(0u64); INS];
		let mut in_blindings = [Fq::from(0u64); INS];
		let mut in_amounts = [Fq::from(0u64); INS];
		let mut in_nullifier_hashes = [Fq::from(0u64); INS];
		let mut in_root_set = [Fq::from(0u64); BRIDGE_SIZE];

		// Default path to initialize the `in_paths` array
		let default_path = Path::<Fq, PoseidonBn254, TREE_HEIGHT> {
			path: [(Fq::from(0u64), Fq::from(0u64)); TREE_HEIGHT],
			marker: PhantomData,
		};
		let mut in_paths: [Path<_, _, TREE_HEIGHT>; INS] = [default_path.clone(), default_path];

		// We'll say the index of each input is index:
		let index = 0u64;
		let in_indices = [Fq::from(index); INS];

		// First input will be a dummy input, so its
		// data is left as zeros.  Nullifier hashes must be
		// computed properly, and we need to add a fake merkle
		// tree membership proof since the gadget checks this,
		// but the tree's root does not belong to the root set.
		let public_key = poseidon_native2.hash(&in_private_keys[0..1]).unwrap();
		let leaf = poseidon_native5
			.hash(&[public_chain_id, in_amounts[0], public_key, in_blindings[0]])
			.unwrap();
		let signature = poseidon_native4
			.hash(&[in_private_keys[0], leaf, in_indices[0]])
			.unwrap();
		in_nullifier_hashes[0] = poseidon_native4
			.hash(&[leaf, in_indices[0], signature])
			.unwrap();
		// Simulate a Merkle tree path for this dummy input
		let default_leaf = [0u8; 32];
		let merkle_tree = SparseMerkleTree::<Fq, PoseidonBn254, TREE_HEIGHT>::new_sequential(
			&[leaf],
			&poseidon_native3,
			&default_leaf,
		)
		.unwrap();
		in_paths[0] = merkle_tree.generate_membership_proof(index);

		// The remaining input can be a random number
		in_private_keys[1] = Fq::rand(rng);
		in_blindings[1] = Fq::rand(rng);
		// Multiplying by 1/20 prevents the amounts from summing to more than
		// the size of the field (at least for fewer than 20 inputs)
		in_amounts[1] = Fq::rand(rng) * (Fq::from(20u64).inverse().unwrap());

		// Calculate what the input nullifier hashes would be based on these:
		let public_key = poseidon_native2.hash(&in_private_keys[1..2]).unwrap();
		let leaf = poseidon_native5
			.hash(&[public_chain_id, in_amounts[1], public_key, in_blindings[1]])
			.unwrap();
		let signature = poseidon_native4
			.hash(&[in_private_keys[1], leaf, in_indices[1]])
			.unwrap();
		in_nullifier_hashes[1] = poseidon_native4
			.hash(&[leaf, in_indices[1], signature])
			.unwrap();

		// Simulate a Merkle tree for each input
		let default_leaf = [0u8; 32];
		let merkle_tree = SparseMerkleTree::<Fq, PoseidonBn254, TREE_HEIGHT>::new_sequential(
			&[leaf],
			&poseidon_native3,
			&default_leaf,
		)
		.unwrap();
		in_paths[1] = merkle_tree.generate_membership_proof(index);

		// Add the root of this Merkle tree to the root set.
		in_root_set[0] = merkle_tree.root();

		// Output amounts cannot be randomly generated since they may then exceed input
		// amount.
		let mut out_amounts = [Fq::from(0u64); OUTS];
		out_amounts[0] = in_amounts[0];
		out_amounts[1] = public_amount + in_amounts[1];

		// Other output quantities can be randomly generated
		let mut out_private_keys = [Fq::from(0u64); OUTS];
		let mut out_public_keys = [Fq::from(0u64); OUTS];
		let mut out_blindings = [Fq::from(0u64); OUTS];
		let mut out_chain_ids = [Fq::from(0u64); OUTS];
		let mut out_commitments = [Fq::from(0u64); OUTS];
		for i in 0..OUTS {
			out_blindings[i] = Fq::rand(rng);
			out_private_keys[i] = Fq::rand(rng);
			out_chain_ids[i] = Fq::rand(rng);
			out_public_keys[i] = poseidon_native2.hash(&out_private_keys[i..i + 1]).unwrap();
			// Compute the out commitment
			out_commitments[i] = poseidon_native5
				.hash(&[
					out_chain_ids[i],
					out_amounts[i],
					out_public_keys[i],
					out_blindings[i],
				])
				.unwrap();
		}

		// Create the VAnchor circuit
		let mut circuit = VariableAnchorCircuit::<
			Fq,
			JubjubParameters,
			PoseidonGadget,
			TREE_HEIGHT,
			BRIDGE_SIZE,
			INS,
			OUTS,
		>::new(
			public_amount,
			public_chain_id,
			in_amounts,
			in_blindings,
			in_nullifier_hashes,
			in_private_keys,
			in_paths,
			in_indices,
			in_root_set,
			out_amounts,
			out_blindings,
			out_chain_ids,
			out_public_keys,
			out_commitments,
			arbitrary_data,
			poseidon_native2,
			poseidon_native3,
			poseidon_native4,
			poseidon_native5,
		);

		let verifier_public_inputs = vec![
			public_amount,
			public_chain_id,
			arbitrary_data,
			in_nullifier_hashes[0],
			in_nullifier_hashes[0],
			in_root_set[0].double(), // Give the verifier a different root set
			in_root_set[1],
			in_nullifier_hashes[1],
			in_nullifier_hashes[1],
			in_root_set[0],
			in_root_set[1],
			out_commitments[0],
			out_commitments[1],
		];

		// Verify proof
		let res = prove_then_verify::<Bn254, JubjubParameters, _>(
			&mut |c| circuit.gadget(c),
			1 << 19,
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

		let [poseidon_native2, poseidon_native3, poseidon_native4, poseidon_native5] =
			make_vanchor_hashers();

		// Randomly generated public inputs
		let public_amount = Fq::rand(rng);
		let public_chain_id = Fq::rand(rng);
		let arbitrary_data = Fq::rand(rng);

		// Randomly generated private inputs
		// Initialize arrays
		let mut in_private_keys = [Fq::from(0u64); INS];
		let mut in_blindings = [Fq::from(0u64); INS];
		let mut in_amounts = [Fq::from(0u64); INS];
		let mut in_nullifier_hashes = [Fq::from(0u64); INS];
		let mut in_root_set = [Fq::from(0u64); BRIDGE_SIZE];

		// Default path to initialize the `in_paths` array
		let default_path = Path::<Fq, PoseidonBn254, TREE_HEIGHT> {
			path: [(Fq::from(0u64), Fq::from(0u64)); TREE_HEIGHT],
			marker: PhantomData,
		};
		let mut in_paths: [Path<_, _, TREE_HEIGHT>; INS] = [default_path.clone(), default_path];

		// We'll say the index of each input is index:
		let index = 0u64;
		let in_indices = [Fq::from(index); INS];

		// First input will be a dummy input, so its
		// data is left as zeros.  Nullifier hashes must be
		// computed properly, and we need to add a fake merkle
		// tree membership proof since the gadget checks this,
		// but the tree's root does not belong to the root set.
		let public_key = poseidon_native2.hash(&in_private_keys[0..1]).unwrap();
		let leaf = poseidon_native5
			.hash(&[public_chain_id, in_amounts[0], public_key, in_blindings[0]])
			.unwrap();
		let signature = poseidon_native4
			.hash(&[in_private_keys[0], leaf, in_indices[0]])
			.unwrap();
		in_nullifier_hashes[0] = poseidon_native4
			.hash(&[leaf, in_indices[0], signature])
			.unwrap();
		// Simulate a Merkle tree path for this dummy input
		let default_leaf = [0u8; 32];
		let merkle_tree = SparseMerkleTree::<Fq, PoseidonBn254, TREE_HEIGHT>::new_sequential(
			&[leaf],
			&poseidon_native3,
			&default_leaf,
		)
		.unwrap();
		in_paths[0] = merkle_tree.generate_membership_proof(index);

		// The remaining input can be a random number
		in_private_keys[1] = Fq::rand(rng);
		in_blindings[1] = Fq::rand(rng);
		// Multiplying by 1/20 prevents the amounts from summing to more than
		// the size of the field (at least for fewer than 20 inputs)
		in_amounts[1] = Fq::rand(rng) * (Fq::from(20u64).inverse().unwrap());

		// Calculate what the input nullifier hashes would be based on these:
		let public_key = poseidon_native2.hash(&in_private_keys[1..2]).unwrap();
		let leaf = poseidon_native5
			.hash(&[public_chain_id, in_amounts[1], public_key, in_blindings[1]])
			.unwrap();
		let signature = poseidon_native4
			.hash(&[in_private_keys[1], leaf, in_indices[1]])
			.unwrap();
		in_nullifier_hashes[1] = poseidon_native4
			.hash(&[leaf, in_indices[1], signature])
			.unwrap();

		// Simulate a Merkle tree for each input
		let default_leaf = [0u8; 32];
		let merkle_tree = SparseMerkleTree::<Fq, PoseidonBn254, TREE_HEIGHT>::new_sequential(
			&[leaf],
			&poseidon_native3,
			&default_leaf,
		)
		.unwrap();
		in_paths[1] = merkle_tree.generate_membership_proof(index);

		// Add the root of this Merkle tree to the root set.
		in_root_set[0] = merkle_tree.root();

		// Change the second secret to something incorrect
		in_private_keys[1] = Fq::from(0u32);

		// Output amounts cannot be randomly generated since they may then exceed input
		// amount.
		let mut out_amounts = [Fq::from(0u64); OUTS];
		out_amounts[0] = in_amounts[0];
		out_amounts[1] = public_amount + in_amounts[1]; // fix for INS > 2

		// Other output quantities can be randomly generated
		let mut out_private_keys = [Fq::from(0u64); OUTS];
		let mut out_public_keys = [Fq::from(0u64); OUTS];
		let mut out_blindings = [Fq::from(0u64); OUTS];
		let mut out_chain_ids = [Fq::from(0u64); OUTS];
		let mut out_commitments = [Fq::from(0u64); OUTS];
		for i in 0..OUTS {
			out_blindings[i] = Fq::rand(rng);
			out_private_keys[i] = Fq::rand(rng);
			out_chain_ids[i] = Fq::rand(rng);
			out_public_keys[i] = poseidon_native2.hash(&out_private_keys[i..i + 1]).unwrap();
			// Compute the out commitment
			out_commitments[i] = poseidon_native5
				.hash(&[
					out_chain_ids[i],
					out_amounts[i],
					out_public_keys[i],
					out_blindings[i],
				])
				.unwrap();
		}

		// Create the VAnchor circuit
		let mut circuit = VariableAnchorCircuit::<
			Fq,
			JubjubParameters,
			PoseidonGadget,
			TREE_HEIGHT,
			BRIDGE_SIZE,
			INS,
			OUTS,
		>::new(
			public_amount,
			public_chain_id,
			in_amounts,
			in_blindings,
			in_nullifier_hashes,
			in_private_keys,
			in_paths,
			in_indices,
			in_root_set,
			out_amounts,
			out_blindings,
			out_chain_ids,
			out_public_keys,
			out_commitments,
			arbitrary_data,
			poseidon_native2,
			poseidon_native3,
			poseidon_native4,
			poseidon_native5,
		);

		// Verify proof
		let res = prove_then_verify::<Bn254, JubjubParameters, _>(
			&mut |c| circuit.gadget(c),
			1 << 19,
			None,
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

		let [poseidon_native2, poseidon_native3, poseidon_native4, poseidon_native5] =
			make_vanchor_hashers();

		// Randomly generated public inputs
		let public_amount = Fq::rand(rng);
		let public_chain_id = Fq::rand(rng);
		let arbitrary_data = Fq::rand(rng);

		// Randomly generated private inputs
		// Initialize arrays
		let mut in_private_keys = [Fq::from(0u64); INS];
		let mut in_blindings = [Fq::from(0u64); INS];
		let mut in_amounts = [Fq::from(0u64); INS];
		let mut in_nullifier_hashes = [Fq::from(0u64); INS];
		let mut in_root_set = [Fq::from(0u64); BRIDGE_SIZE];

		// Default path to initialize the `in_paths` array
		let default_path = Path::<Fq, PoseidonBn254, TREE_HEIGHT> {
			path: [(Fq::from(0u64), Fq::from(0u64)); TREE_HEIGHT],
			marker: PhantomData,
		};
		let mut in_paths: [Path<_, _, TREE_HEIGHT>; INS] = [default_path.clone(), default_path];

		// We'll say the index of each input is index:
		let index = 0u64;
		let in_indices = [Fq::from(index); INS];

		// First input will be a dummy input, so its
		// data is left as zeros.  Nullifier hashes must be
		// computed properly, and we need to add a fake merkle
		// tree membership proof since the gadget checks this,
		// but the tree's root does not belong to the root set.
		let public_key = poseidon_native2.hash(&in_private_keys[0..1]).unwrap();
		let leaf = poseidon_native5
			.hash(&[public_chain_id, in_amounts[0], public_key, in_blindings[0]])
			.unwrap();
		let signature = poseidon_native4
			.hash(&[in_private_keys[0], leaf, in_indices[0]])
			.unwrap();
		in_nullifier_hashes[0] = poseidon_native4
			.hash(&[leaf, in_indices[0], signature])
			.unwrap();
		// Simulate a Merkle tree path for this dummy input
		let default_leaf = [0u8; 32];
		let merkle_tree = SparseMerkleTree::<Fq, PoseidonBn254, TREE_HEIGHT>::new_sequential(
			&[leaf],
			&poseidon_native3,
			&default_leaf,
		)
		.unwrap();
		in_paths[0] = merkle_tree.generate_membership_proof(index);

		// The remaining input can be a random number
		in_private_keys[1] = Fq::rand(rng);
		in_blindings[1] = Fq::rand(rng);
		// Multiplying by 1/20 prevents the amounts from summing to more than
		// the size of the field (at least for fewer than 20 inputs)
		in_amounts[1] = Fq::rand(rng) * (Fq::from(20u64).inverse().unwrap());

		// Calculate what the input nullifier hashes would be based on these:
		let public_key = poseidon_native2.hash(&in_private_keys[1..2]).unwrap();
		let leaf = poseidon_native5
			.hash(&[public_chain_id, in_amounts[1], public_key, in_blindings[1]])
			.unwrap();
		let signature = poseidon_native4
			.hash(&[in_private_keys[1], leaf, in_indices[1]])
			.unwrap();
		in_nullifier_hashes[1] = poseidon_native4
			.hash(&[leaf, in_indices[1], signature])
			.unwrap();

		// Simulate a Merkle tree for each input
		let default_leaf = [0u8; 32];
		let merkle_tree = SparseMerkleTree::<Fq, PoseidonBn254, TREE_HEIGHT>::new_sequential(
			&[leaf],
			&poseidon_native3,
			&default_leaf,
		)
		.unwrap();
		in_paths[1] = merkle_tree.generate_membership_proof(index);

		// Add the root of this Merkle tree to the root set.
		in_root_set[0] = merkle_tree.root();

		// Output amounts cannot be randomly generated since they may then exceed input
		// amount.
		let mut out_amounts = [Fq::from(0u64); OUTS];
		out_amounts[0] = in_amounts[0];
		out_amounts[1] = public_amount + in_amounts[1]; // fix for INS > 2

		// Other output quantities can be randomly generated
		let mut out_private_keys = [Fq::from(0u64); OUTS];
		let mut out_public_keys = [Fq::from(0u64); OUTS];
		let mut out_blindings = [Fq::from(0u64); OUTS];
		let mut out_chain_ids = [Fq::from(0u64); OUTS];
		let mut out_commitments = [Fq::from(0u64); OUTS];
		for i in 0..OUTS {
			out_blindings[i] = Fq::rand(rng);
			out_private_keys[i] = Fq::rand(rng);
			out_chain_ids[i] = Fq::rand(rng);
			out_public_keys[i] = poseidon_native2.hash(&out_private_keys[i..i + 1]).unwrap();
			// Compute the out commitment
			out_commitments[i] = poseidon_native5
				.hash(&[
					out_chain_ids[i],
					out_amounts[i],
					out_public_keys[i],
					out_blindings[i],
				])
				.unwrap();
		}

		// Create the VAnchor circuit
		let mut circuit = VariableAnchorCircuit::<
			Fq,
			JubjubParameters,
			PoseidonGadget,
			TREE_HEIGHT,
			BRIDGE_SIZE,
			INS,
			OUTS,
		>::new(
			public_amount,
			public_chain_id,
			in_amounts,
			in_blindings,
			in_nullifier_hashes,
			in_private_keys,
			in_paths,
			in_indices,
			in_root_set,
			out_amounts,
			out_blindings,
			out_chain_ids,
			out_public_keys,
			out_commitments,
			arbitrary_data,
			poseidon_native2,
			poseidon_native3,
			poseidon_native4,
			poseidon_native5,
		);

		let verifier_public_inputs = vec![
			public_amount,
			arbitrary_data,
			public_chain_id,
			in_nullifier_hashes[0].double(), // Give the verifier a different nullifier hash here
			in_nullifier_hashes[1],
			out_commitments[0],
			out_commitments[1],
			in_root_set[0],
			in_root_set[1],
			in_root_set[2],
		];

		// Verify proof
		let res = prove_then_verify::<Bn254, JubjubParameters, _>(
			&mut |c| circuit.gadget(c),
			1 << 19,
			Some(verifier_public_inputs),
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

		let [poseidon_native2, poseidon_native3, poseidon_native4, poseidon_native5] =
			make_vanchor_hashers();

		// Randomly generated public inputs
		let public_amount = Fq::rand(rng);
		let public_chain_id = Fq::rand(rng);
		let arbitrary_data = Fq::rand(rng);

		// Randomly generated private inputs
		// Initialize arrays
		let mut in_private_keys = [Fq::from(0u64); INS];
		let mut in_blindings = [Fq::from(0u64); INS];
		let mut in_amounts = [Fq::from(0u64); INS];
		let mut in_nullifier_hashes = [Fq::from(0u64); INS];
		let mut in_root_set = [Fq::from(0u64); BRIDGE_SIZE];

		// Default path to initialize the `in_paths` array
		let default_path = Path::<Fq, PoseidonBn254, TREE_HEIGHT> {
			path: [(Fq::from(0u64), Fq::from(0u64)); TREE_HEIGHT],
			marker: PhantomData,
		};
		let mut in_paths: [Path<_, _, TREE_HEIGHT>; INS] =
			[default_path.clone(), default_path.clone()];

		// We'll say the index of each input is index:
		let index = 0u64;
		let in_indices = [Fq::from(index); INS];

		// First input will be a dummy input, so its
		// data is left as zeros.  Nullifier hashes must be
		// computed properly, and we need to add a fake merkle
		// tree membership proof since the gadget checks this,
		// but the tree's root does not belong to the root set.
		let public_key = poseidon_native2.hash(&in_private_keys[0..1]).unwrap();
		let leaf = poseidon_native5
			.hash(&[public_chain_id, in_amounts[0], public_key, in_blindings[0]])
			.unwrap();
		let signature = poseidon_native4
			.hash(&[in_private_keys[0], leaf, in_indices[0]])
			.unwrap();
		in_nullifier_hashes[0] = poseidon_native4
			.hash(&[leaf, in_indices[0], signature])
			.unwrap();
		// Simulate a Merkle tree path for this dummy input
		let default_leaf = [0u8; 32];
		let merkle_tree = SparseMerkleTree::<Fq, PoseidonBn254, TREE_HEIGHT>::new_sequential(
			&[leaf],
			&poseidon_native3,
			&default_leaf,
		)
		.unwrap();
		in_paths[0] = merkle_tree.generate_membership_proof(index);

		// The remaining input can be a random number
		in_private_keys[1] = Fq::rand(rng);
		in_blindings[1] = Fq::rand(rng);
		// Multiplying by 1/20 prevents the amounts from summing to more than
		// the size of the field (at least for fewer than 20 inputs)
		in_amounts[1] = Fq::rand(rng) * (Fq::from(20u64).inverse().unwrap());

		// Calculate what the input nullifier hashes would be based on these:
		let public_key = poseidon_native2.hash(&in_private_keys[1..2]).unwrap();
		let leaf = poseidon_native5
			.hash(&[public_chain_id, in_amounts[1], public_key, in_blindings[1]])
			.unwrap();
		let signature = poseidon_native4
			.hash(&[in_private_keys[1], leaf, in_indices[1]])
			.unwrap();
		in_nullifier_hashes[1] = poseidon_native4
			.hash(&[leaf, in_indices[1], signature])
			.unwrap();

		// Simulate a Merkle tree for each input
		let default_leaf = [0u8; 32];
		let merkle_tree = SparseMerkleTree::<Fq, PoseidonBn254, TREE_HEIGHT>::new_sequential(
			&[leaf],
			&poseidon_native3,
			&default_leaf,
		)
		.unwrap();
		in_paths[1] = merkle_tree.generate_membership_proof(index);

		// Add the root of this Merkle tree to the root set.
		in_root_set[0] = merkle_tree.root();

		// Change the first path to something incorrect
		in_paths[0] = default_path;

		// Output amounts cannot be randomly generated since they may then exceed input
		// amount.
		let mut out_amounts = [Fq::from(0u64); OUTS];
		out_amounts[0] = in_amounts[0];
		out_amounts[1] = public_amount + in_amounts[1]; // fix for INS > 2

		// Other output quantities can be randomly generated
		let mut out_private_keys = [Fq::from(0u64); OUTS];
		let mut out_public_keys = [Fq::from(0u64); OUTS];
		let mut out_blindings = [Fq::from(0u64); OUTS];
		let mut out_chain_ids = [Fq::from(0u64); OUTS];
		let mut out_commitments = [Fq::from(0u64); OUTS];
		for i in 0..OUTS {
			out_blindings[i] = Fq::rand(rng);
			out_private_keys[i] = Fq::rand(rng);
			out_chain_ids[i] = Fq::rand(rng);
			out_public_keys[i] = poseidon_native2.hash(&out_private_keys[i..i + 1]).unwrap();
			// Compute the out commitment
			out_commitments[i] = poseidon_native5
				.hash(&[
					out_chain_ids[i],
					out_amounts[i],
					out_public_keys[i],
					out_blindings[i],
				])
				.unwrap();
		}

		// Create the VAnchor circuit
		let mut circuit = VariableAnchorCircuit::<
			Fq,
			JubjubParameters,
			PoseidonGadget,
			TREE_HEIGHT,
			BRIDGE_SIZE,
			INS,
			OUTS,
		>::new(
			public_amount,
			public_chain_id,
			in_amounts,
			in_blindings,
			in_nullifier_hashes,
			in_private_keys,
			in_paths,
			in_indices,
			in_root_set,
			out_amounts,
			out_blindings,
			out_chain_ids,
			out_public_keys,
			out_commitments,
			arbitrary_data,
			poseidon_native2,
			poseidon_native3,
			poseidon_native4,
			poseidon_native5,
		);

		// Verify proof
		let res = prove_then_verify::<Bn254, JubjubParameters, _>(
			&mut |c| circuit.gadget(c),
			1 << 19,
			None,
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

		let [poseidon_native2, poseidon_native3, poseidon_native4, poseidon_native5] =
			make_vanchor_hashers();

		// Randomly generated public inputs
		let public_amount = Fq::rand(rng);
		let public_chain_id = Fq::rand(rng);
		let arbitrary_data = Fq::rand(rng);

		// Randomly generated private inputs
		// Initialize arrays
		let mut in_private_keys = [Fq::from(0u64); INS];
		let mut in_blindings = [Fq::from(0u64); INS];
		let mut in_amounts = [Fq::from(0u64); INS];
		let mut in_nullifier_hashes = [Fq::from(0u64); INS];
		let mut in_root_set = [Fq::from(0u64); BRIDGE_SIZE];

		// Default path to initialize the `in_paths` array
		let default_path = Path::<Fq, PoseidonBn254, TREE_HEIGHT> {
			path: [(Fq::from(0u64), Fq::from(0u64)); TREE_HEIGHT],
			marker: PhantomData,
		};
		let mut in_paths: [Path<_, _, TREE_HEIGHT>; INS] = [default_path.clone(), default_path];

		// We'll say the index of each input is index:
		let index = 0u64;
		let in_indices = [Fq::from(index); INS];

		// First input will be a dummy input, so its
		// data is left as zeros.  Nullifier hashes must be
		// computed properly, and we need to add a fake merkle
		// tree membership proof since the gadget checks this,
		// but the tree's root does not belong to the root set.
		let public_key = poseidon_native2.hash(&in_private_keys[0..1]).unwrap();
		let leaf = poseidon_native5
			.hash(&[public_chain_id, in_amounts[0], public_key, in_blindings[0]])
			.unwrap();
		let signature = poseidon_native4
			.hash(&[in_private_keys[0], leaf, in_indices[0]])
			.unwrap();
		in_nullifier_hashes[0] = poseidon_native4
			.hash(&[leaf, in_indices[0], signature])
			.unwrap();
		// Simulate a Merkle tree path for this dummy input
		let default_leaf = [0u8; 32];
		let merkle_tree = SparseMerkleTree::<Fq, PoseidonBn254, TREE_HEIGHT>::new_sequential(
			&[leaf],
			&poseidon_native3,
			&default_leaf,
		)
		.unwrap();
		in_paths[0] = merkle_tree.generate_membership_proof(index);

		// The remaining input can be a random number
		in_private_keys[1] = Fq::rand(rng);
		in_blindings[1] = Fq::rand(rng);
		// Multiplying by 1/20 prevents the amounts from summing to more than
		// the size of the field (at least for fewer than 20 inputs)
		in_amounts[1] = Fq::rand(rng) * (Fq::from(20u64).inverse().unwrap());

		// Calculate what the input nullifier hashes would be based on these:
		let public_key = poseidon_native2.hash(&in_private_keys[1..2]).unwrap();
		let leaf = poseidon_native5
			.hash(&[public_chain_id, in_amounts[1], public_key, in_blindings[1]])
			.unwrap();
		let signature = poseidon_native4
			.hash(&[in_private_keys[1], leaf, in_indices[1]])
			.unwrap();
		in_nullifier_hashes[1] = poseidon_native4
			.hash(&[leaf, in_indices[1], signature])
			.unwrap();

		// Simulate a Merkle tree for each input
		let default_leaf = [0u8; 32];
		let merkle_tree = SparseMerkleTree::<Fq, PoseidonBn254, TREE_HEIGHT>::new_sequential(
			&[leaf],
			&poseidon_native3,
			&default_leaf,
		)
		.unwrap();
		in_paths[1] = merkle_tree.generate_membership_proof(index);

		// Add the root of this Merkle tree to the root set.
		in_root_set[0] = merkle_tree.root();

		// Output amounts cannot be randomly generated since they may then exceed input
		// amount.
		let mut out_amounts = [Fq::from(0u64); OUTS];
		out_amounts[0] = in_amounts[0];
		out_amounts[1] = public_amount + in_amounts[1]; // fix for INS > 2

		// Other output quantities can be randomly generated
		let mut out_private_keys = [Fq::from(0u64); OUTS];
		let mut out_public_keys = [Fq::from(0u64); OUTS];
		let mut out_blindings = [Fq::from(0u64); OUTS];
		let mut out_chain_ids = [Fq::from(0u64); OUTS];
		let mut out_commitments = [Fq::from(0u64); OUTS];
		for i in 0..OUTS {
			out_blindings[i] = Fq::rand(rng);
			out_private_keys[i] = Fq::rand(rng);
			out_chain_ids[i] = Fq::rand(rng);
			out_public_keys[i] = poseidon_native2.hash(&out_private_keys[i..i + 1]).unwrap();
			// Compute the out commitment
			out_commitments[i] = poseidon_native5
				.hash(&[
					out_chain_ids[i],
					out_amounts[i],
					out_public_keys[i],
					out_blindings[i],
				])
				.unwrap();
		}

		// Create the VAnchor circuit
		let mut circuit = VariableAnchorCircuit::<
			Fq,
			JubjubParameters,
			PoseidonGadget,
			TREE_HEIGHT,
			BRIDGE_SIZE,
			INS,
			OUTS,
		>::new(
			public_amount,
			public_chain_id,
			in_amounts,
			in_blindings,
			in_nullifier_hashes,
			in_private_keys,
			in_paths,
			in_indices,
			in_root_set,
			out_amounts,
			out_blindings,
			out_chain_ids,
			out_public_keys,
			out_commitments,
			arbitrary_data,
			poseidon_native2,
			poseidon_native3,
			poseidon_native4,
			poseidon_native5,
		);

		let verifier_public_inputs = vec![
			public_amount,
			arbitrary_data.double(), // Give the verifier different arbitrary data
			public_chain_id,
			in_nullifier_hashes[0],
			in_nullifier_hashes[1],
			out_commitments[0],
			out_commitments[1],
			in_root_set[0],
			in_root_set[1],
			in_root_set[2],
		];

		// Verify proof
		let res = prove_then_verify::<Bn254, JubjubParameters, _>(
			&mut |c| circuit.gadget(c),
			1 << 19,
			Some(verifier_public_inputs),
		);

		match res {
			Err(Error::ProofVerificationError) => (),
			Err(err) => panic!("Unexpected error: {:?}", err),
			Ok(()) => panic!("Proof was successfully verified when error was expected"),
		};
	}

	#[test]
	fn should_fail_with_wrong_chain_id_plonk() {
		let rng = &mut test_rng();

		let [poseidon_native2, poseidon_native3, poseidon_native4, poseidon_native5] =
			make_vanchor_hashers();

		// Randomly generated public inputs
		let public_amount = Fq::rand(rng);
		let public_chain_id = Fq::rand(rng);
		let arbitrary_data = Fq::rand(rng);

		// Randomly generated private inputs
		// Initialize arrays
		let mut in_private_keys = [Fq::from(0u64); INS];
		let mut in_blindings = [Fq::from(0u64); INS];
		let mut in_amounts = [Fq::from(0u64); INS];
		let mut in_nullifier_hashes = [Fq::from(0u64); INS];
		let mut in_root_set = [Fq::from(0u64); BRIDGE_SIZE];

		// Default path to initialize the `in_paths` array
		let default_path = Path::<Fq, PoseidonBn254, TREE_HEIGHT> {
			path: [(Fq::from(0u64), Fq::from(0u64)); TREE_HEIGHT],
			marker: PhantomData,
		};
		let mut in_paths: [Path<_, _, TREE_HEIGHT>; INS] = [default_path.clone(), default_path];

		// We'll say the index of each input is index:
		let index = 0u64;
		let in_indices = [Fq::from(index); INS];

		// First input will be a dummy input, so its
		// data is left as zeros.  Nullifier hashes must be
		// computed properly, and we need to add a fake merkle
		// tree membership proof since the gadget checks this,
		// but the tree's root does not belong to the root set.
		let public_key = poseidon_native2.hash(&in_private_keys[0..1]).unwrap();
		let leaf = poseidon_native5
			.hash(&[public_chain_id, in_amounts[0], public_key, in_blindings[0]])
			.unwrap();
		let signature = poseidon_native4
			.hash(&[in_private_keys[0], leaf, in_indices[0]])
			.unwrap();
		in_nullifier_hashes[0] = poseidon_native4
			.hash(&[leaf, in_indices[0], signature])
			.unwrap();
		// Simulate a Merkle tree path for this dummy input
		let default_leaf = [0u8; 32];
		let merkle_tree = SparseMerkleTree::<Fq, PoseidonBn254, TREE_HEIGHT>::new_sequential(
			&[leaf],
			&poseidon_native3,
			&default_leaf,
		)
		.unwrap();
		in_paths[0] = merkle_tree.generate_membership_proof(index);

		// The remaining input can be a random number
		in_private_keys[1] = Fq::rand(rng);
		in_blindings[1] = Fq::rand(rng);
		// Multiplying by 1/20 prevents the amounts from summing to more than
		// the size of the field (at least for fewer than 20 inputs)
		in_amounts[1] = Fq::rand(rng) * (Fq::from(20u64).inverse().unwrap());

		// Calculate what the input nullifier hashes would be based on these:
		let public_key = poseidon_native2.hash(&in_private_keys[1..2]).unwrap();
		let leaf = poseidon_native5
			.hash(&[public_chain_id, in_amounts[1], public_key, in_blindings[1]])
			.unwrap();
		let signature = poseidon_native4
			.hash(&[in_private_keys[1], leaf, in_indices[1]])
			.unwrap();
		in_nullifier_hashes[1] = poseidon_native4
			.hash(&[leaf, in_indices[1], signature])
			.unwrap();

		// Simulate a Merkle tree for each input
		let default_leaf = [0u8; 32];
		let merkle_tree = SparseMerkleTree::<Fq, PoseidonBn254, TREE_HEIGHT>::new_sequential(
			&[leaf],
			&poseidon_native3,
			&default_leaf,
		)
		.unwrap();
		in_paths[1] = merkle_tree.generate_membership_proof(index);

		// Add the root of this Merkle tree to the root set.
		in_root_set[0] = merkle_tree.root();

		// Output amounts cannot be randomly generated since they may then exceed input
		// amount.
		let mut out_amounts = [Fq::from(0u64); OUTS];
		out_amounts[0] = in_amounts[0];
		out_amounts[1] = public_amount + in_amounts[1]; // fix for INS > 2

		// Other output quantities can be randomly generated
		let mut out_private_keys = [Fq::from(0u64); OUTS];
		let mut out_public_keys = [Fq::from(0u64); OUTS];
		let mut out_blindings = [Fq::from(0u64); OUTS];
		let mut out_chain_ids = [Fq::from(0u64); OUTS];
		let mut out_commitments = [Fq::from(0u64); OUTS];
		for i in 0..OUTS {
			out_blindings[i] = Fq::rand(rng);
			out_private_keys[i] = Fq::rand(rng);
			out_chain_ids[i] = Fq::rand(rng);
			out_public_keys[i] = poseidon_native2.hash(&out_private_keys[i..i + 1]).unwrap();
			// Compute the out commitment
			out_commitments[i] = poseidon_native5
				.hash(&[
					out_chain_ids[i],
					out_amounts[i],
					out_public_keys[i],
					out_blindings[i],
				])
				.unwrap();
		}

		// Create the VAnchor circuit
		let mut circuit = VariableAnchorCircuit::<
			Fq,
			JubjubParameters,
			PoseidonGadget,
			TREE_HEIGHT,
			BRIDGE_SIZE,
			INS,
			OUTS,
		>::new(
			public_amount,
			public_chain_id,
			in_amounts,
			in_blindings,
			in_nullifier_hashes,
			in_private_keys,
			in_paths,
			in_indices,
			in_root_set,
			out_amounts,
			out_blindings,
			out_chain_ids,
			out_public_keys,
			out_commitments,
			arbitrary_data,
			poseidon_native2,
			poseidon_native3,
			poseidon_native4,
			poseidon_native5,
		);

		let verifier_public_inputs = vec![
			public_amount,
			arbitrary_data,
			public_chain_id.double(), // Give the verifier different chain id
			in_nullifier_hashes[0],
			in_nullifier_hashes[1],
			out_commitments[0],
			out_commitments[1],
			in_root_set[0],
			in_root_set[1],
			in_root_set[2],
		];

		// Verify proof
		let res = prove_then_verify::<Bn254, JubjubParameters, _>(
			&mut |c| circuit.gadget(c),
			1 << 19,
			Some(verifier_public_inputs),
		);

		match res {
			Err(Error::ProofVerificationError) => (),
			Err(err) => panic!("Unexpected error: {:?}", err),
			Ok(()) => panic!("Proof was successfully verified when error was expected"),
		};
	}

	#[test]
	fn should_fail_with_wrong_public_amount_plonk() {
		let rng = &mut test_rng();

		let [poseidon_native2, poseidon_native3, poseidon_native4, poseidon_native5] =
			make_vanchor_hashers();

		// Randomly generated public inputs
		let public_amount = Fq::rand(rng);
		let public_chain_id = Fq::rand(rng);
		let arbitrary_data = Fq::rand(rng);

		// Randomly generated private inputs
		// Initialize arrays
		let mut in_private_keys = [Fq::from(0u64); INS];
		let mut in_blindings = [Fq::from(0u64); INS];
		let mut in_amounts = [Fq::from(0u64); INS];
		let mut in_nullifier_hashes = [Fq::from(0u64); INS];
		let mut in_root_set = [Fq::from(0u64); BRIDGE_SIZE];

		// Default path to initialize the `in_paths` array
		let default_path = Path::<Fq, PoseidonBn254, TREE_HEIGHT> {
			path: [(Fq::from(0u64), Fq::from(0u64)); TREE_HEIGHT],
			marker: PhantomData,
		};
		let mut in_paths: [Path<_, _, TREE_HEIGHT>; INS] = [default_path.clone(), default_path];

		// We'll say the index of each input is index:
		let index = 0u64;
		let in_indices = [Fq::from(index); INS];

		// First input will be a dummy input, so its
		// data is left as zeros.  Nullifier hashes must be
		// computed properly, and we need to add a fake merkle
		// tree membership proof since the gadget checks this,
		// but the tree's root does not belong to the root set.
		let public_key = poseidon_native2.hash(&in_private_keys[0..1]).unwrap();
		let leaf = poseidon_native5
			.hash(&[public_chain_id, in_amounts[0], public_key, in_blindings[0]])
			.unwrap();
		let signature = poseidon_native4
			.hash(&[in_private_keys[0], leaf, in_indices[0]])
			.unwrap();
		in_nullifier_hashes[0] = poseidon_native4
			.hash(&[leaf, in_indices[0], signature])
			.unwrap();
		// Simulate a Merkle tree path for this dummy input
		let default_leaf = [0u8; 32];
		let merkle_tree = SparseMerkleTree::<Fq, PoseidonBn254, TREE_HEIGHT>::new_sequential(
			&[leaf],
			&poseidon_native3,
			&default_leaf,
		)
		.unwrap();
		in_paths[0] = merkle_tree.generate_membership_proof(index);

		// The remaining input can be a random number
		in_private_keys[1] = Fq::rand(rng);
		in_blindings[1] = Fq::rand(rng);
		// Multiplying by 1/20 prevents the amounts from summing to more than
		// the size of the field (at least for fewer than 20 inputs)
		in_amounts[1] = Fq::rand(rng) * (Fq::from(20u64).inverse().unwrap());

		// Calculate what the input nullifier hashes would be based on these:
		let public_key = poseidon_native2.hash(&in_private_keys[1..2]).unwrap();
		let leaf = poseidon_native5
			.hash(&[public_chain_id, in_amounts[1], public_key, in_blindings[1]])
			.unwrap();
		let signature = poseidon_native4
			.hash(&[in_private_keys[1], leaf, in_indices[1]])
			.unwrap();
		in_nullifier_hashes[1] = poseidon_native4
			.hash(&[leaf, in_indices[1], signature])
			.unwrap();

		// Simulate a Merkle tree for each input
		let default_leaf = [0u8; 32];
		let merkle_tree = SparseMerkleTree::<Fq, PoseidonBn254, TREE_HEIGHT>::new_sequential(
			&[leaf],
			&poseidon_native3,
			&default_leaf,
		)
		.unwrap();
		in_paths[1] = merkle_tree.generate_membership_proof(index);

		// Add the root of this Merkle tree to the root set.
		in_root_set[0] = merkle_tree.root();

		// Output amounts cannot be randomly generated since they may then exceed input
		// amount.
		let mut out_amounts = [Fq::from(0u64); OUTS];
		out_amounts[0] = in_amounts[0];
		out_amounts[1] = public_amount + in_amounts[1]; // fix for INS > 2

		// Other output quantities can be randomly generated
		let mut out_private_keys = [Fq::from(0u64); OUTS];
		let mut out_public_keys = [Fq::from(0u64); OUTS];
		let mut out_blindings = [Fq::from(0u64); OUTS];
		let mut out_chain_ids = [Fq::from(0u64); OUTS];
		let mut out_commitments = [Fq::from(0u64); OUTS];
		for i in 0..OUTS {
			out_blindings[i] = Fq::rand(rng);
			out_private_keys[i] = Fq::rand(rng);
			out_chain_ids[i] = Fq::rand(rng);
			out_public_keys[i] = poseidon_native2.hash(&out_private_keys[i..i + 1]).unwrap();
			// Compute the out commitment
			out_commitments[i] = poseidon_native5
				.hash(&[
					out_chain_ids[i],
					out_amounts[i],
					out_public_keys[i],
					out_blindings[i],
				])
				.unwrap();
		}

		// Create the VAnchor circuit
		let mut circuit = VariableAnchorCircuit::<
			Fq,
			JubjubParameters,
			PoseidonGadget,
			TREE_HEIGHT,
			BRIDGE_SIZE,
			INS,
			OUTS,
		>::new(
			public_amount,
			public_chain_id,
			in_amounts,
			in_blindings,
			in_nullifier_hashes,
			in_private_keys,
			in_paths,
			in_indices,
			in_root_set,
			out_amounts,
			out_blindings,
			out_chain_ids,
			out_public_keys,
			out_commitments,
			arbitrary_data,
			poseidon_native2,
			poseidon_native3,
			poseidon_native4,
			poseidon_native5,
		);

		let verifier_public_inputs = vec![
			public_amount.double(), // Give the verifier different public amount
			arbitrary_data,
			public_chain_id,
			in_nullifier_hashes[0],
			in_nullifier_hashes[1],
			out_commitments[0],
			out_commitments[1],
			in_root_set[0],
			in_root_set[1],
			in_root_set[2],
		];

		// Verify proof
		let res = prove_then_verify::<Bn254, JubjubParameters, _>(
			&mut |c| circuit.gadget(c),
			1 << 19,
			Some(verifier_public_inputs),
		);

		match res {
			Err(Error::ProofVerificationError) => (),
			Err(err) => panic!("Unexpected error: {:?}", err),
			Ok(()) => panic!("Proof was successfully verified when error was expected"),
		};
	}
}
