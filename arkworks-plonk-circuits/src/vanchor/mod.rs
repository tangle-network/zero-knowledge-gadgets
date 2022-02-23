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

use std::ops::Add;

use crate::{
	merkle_tree::PathGadget, mixer::add_public_input_variable,
	poseidon::poseidon::FieldHasherGadget, set_membership::check_set_membership_is_enabled,
};
use ark_ec::{models::TEModelParameters, PairingEngine};
use ark_ff::PrimeField;
use ark_std::{One, Zero};
use arkworks_gadgets::{merkle_tree::simple_merkle::Path, poseidon::field_hasher::FieldHasher};
use plonk_core::{
	circuit::Circuit, constraint_system::StandardComposer, error::Error, prelude::Variable,
};

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
	// chain_id: F,
	// secret: F,
	// nullifier: F,
	// nullifier_hash: F,
	// path: Path<F, H::Native, N>,
	// roots: [F; M],
	// arbitrary_data: F,
	// hasher: H::Native,

	// INS = number of input transactions
	// OUTS = number of output transactions
	// N = Tree height
	// M = Size of the root set

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
		let public_chain_id = add_public_input_variable(composer, self.public_chain_id);
		let arbitrary_data = add_public_input_variable(composer, self.arbitrary_data);

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

		// Storage for the nullifier hash variables as we allocate them
		let mut nullifier_hashes: Vec<Variable> = Vec::new();

		// Name the composer's build in zero variable
		let zero = composer.zero_var();

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

			// Add public inputs for each input UTXO being spent
			let in_nullifier_hash_i =
				add_public_input_variable(composer, self.in_nullifier_hashes[i]);
			nullifier_hashes.push(in_nullifier_hash_i);

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
			let _ = composer.arithmetic_gate(|gate| {
				gate.witness(calc_nullifier, calc_nullifier, Some(zero))
					.add(-F::one(), F::zero())
					.pi(self.in_nullifier_hashes[i])
			});

			// Calculate the root hash
			let calc_root_hash =
				path_gadget.calculate_root(composer, &calc_leaf, &tree_hasher_gadget)?;

			// Check if calculated root hash is in the set
			// Note that if `in_amount_i = 0` then the input is a
			// "dummy" input, so the check is not needed.  The
			// `check_set_membership_is_enabled` function accounts for this.
			let is_member = check_set_membership_is_enabled(
				composer,
				&self.in_root_set.to_vec(),
				calc_root_hash,
				in_amount_i,
			);
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
				let result = composer.is_eq_with_output(nullifier_hashes[i], nullifier_hashes[j]);
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
			let _ = composer.arithmetic_gate(|gate| {
				gate.witness(calc_leaf, calc_leaf, Some(zero))
					.add(-F::one(), F::zero())
					.pi(self.out_commitments[i])
			});

			// Each amount should not be greater than the limit constant
			// TODO: Investigate if we can get the field size bits
			composer.range_gate(out_amount_i, 254);
			// assert_less_than(out_amounts[i], limit);

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
	use crate::{poseidon::poseidon::PoseidonGadget, utils::prove_then_verify};
	use ark_bn254::Bn254;
	use ark_ed_on_bn254::{EdwardsParameters as JubjubParameters, Fq};
	use ark_ff::Field;
	use ark_std::test_rng;
	use arkworks_gadgets::{
		ark_std::UniformRand,
		merkle_tree::simple_merkle::{Path, SparseMerkleTree},
		poseidon::field_hasher::{FieldHasher, Poseidon},
	};
	use arkworks_utils::utils::common::{
		setup_params_x5_2, setup_params_x5_3, setup_params_x5_4, setup_params_x5_5, Curve,
	};
	use plonk_core::prelude::*;

	type PoseidonBn254 = Poseidon<Fq>;

	const TREE_HEIGHT: usize = 3;
	const BRIDGE_SIZE: usize = 2;
	const INS: usize = 2; // currently the tests will not work if you change INS
	const OUTS: usize = 2;

	// Helper that outputs the hash functions of each width we need.
	// I have not made this generic over the curve
	fn make_vanchor_hashers() -> [PoseidonBn254; 4] {
		let curve = Curve::Bn254;

		let params2 = setup_params_x5_2::<Fq>(curve);
		let poseidon_native2 = PoseidonBn254 { params: params2 };
		let params3 = setup_params_x5_3::<Fq>(curve);
		let poseidon_native3 = PoseidonBn254 { params: params3 };
		let params4 = setup_params_x5_4::<Fq>(curve);
		let poseidon_native4 = PoseidonBn254 { params: params4 };
		let params5 = setup_params_x5_5::<Fq>(curve);
		let poseidon_native5 = PoseidonBn254 { params: params5 };

		[
			poseidon_native2,
			poseidon_native3,
			poseidon_native4,
			poseidon_native5,
		]
	}

	// Useful to know the order of public inputs in this circuit:
	// let public_inputs = vec![public_amount, public_chain_id, arbitrary_data,
	// in_nullifier_hashes[0],  in_nullifier_hashes[0], -in_root_set[0],
	// -in_root_set[1], in_nullifier_hashes[1], in_nullifier_hashes[1],
	// -in_root_set[0], -in_root_set[1], out_commitments[0], out_commitments[1]];
	// ! Note that because of how check_set_membership is written the public input
	// values are actually (-1)*root_hash, not root hash !

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

		// I don't like this default path thing -- how can I initalize the in_paths
		// array?
		let default_path = Path::<Fq, PoseidonBn254, TREE_HEIGHT> {
			path: [(Fq::from(0u64), Fq::from(0u64)); TREE_HEIGHT],
			_marker: PhantomData,
		};
		let mut in_paths: [Path<_, _, TREE_HEIGHT>; INS] = [default_path.clone(), default_path];
		// let mut in_paths_vec: Vec<Path::<Fq, PoseidonBn254, TREE_HEIGHT>>;
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

		// Populate remaining inputs with random numbers
		for i in 1..INS {
			in_private_keys[i] = Fq::rand(rng);
			in_blindings[i] = Fq::rand(rng);
			// Multiplying by 1/20 prevents the amounts from summing to more than
			// the size of the field (at least for fewer than 20 inputs)
			in_amounts[i] = Fq::rand(rng) * (Fq::from(20u64).inverse().unwrap());

			// Calculate what the input nullifier hashes would be based on these:
			let public_key = poseidon_native2.hash(&in_private_keys[i..i + 1]).unwrap();
			let leaf = poseidon_native5
				.hash(&[public_chain_id, in_amounts[i], public_key, in_blindings[i]])
				.unwrap();
			let signature = poseidon_native4
				.hash(&[in_private_keys[i], leaf, in_indices[i]])
				.unwrap();
			in_nullifier_hashes[i] = poseidon_native4
				.hash(&[leaf, in_indices[i], signature])
				.unwrap();

			// Simulate a Merkle tree for each input
			let default_leaf = [0u8; 32];
			let merkle_tree = SparseMerkleTree::<Fq, PoseidonBn254, TREE_HEIGHT>::new_sequential(
				&[leaf],
				&poseidon_native3,
				&default_leaf,
			)
			.unwrap();
			in_paths[i] = merkle_tree.generate_membership_proof(index);

			// Fix this for INS > BRIDGE_SIZE
			if i < BRIDGE_SIZE {
				in_root_set[i] = merkle_tree.root();
			}
		}

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

		// I don't like this default path thing -- how can I initalize the in_paths
		// array?
		let default_path = Path::<Fq, PoseidonBn254, TREE_HEIGHT> {
			path: [(Fq::from(0u64), Fq::from(0u64)); TREE_HEIGHT],
			_marker: PhantomData,
		};
		let mut in_paths: [Path<_, _, TREE_HEIGHT>; INS] = [default_path.clone(), default_path];
		// let mut in_paths_vec: Vec<Path::<Fq, PoseidonBn254, TREE_HEIGHT>>;
		// We'll say the index of each input is index:
		let index = 0u64;
		let in_indices = [Fq::from(index); INS];
		// Populate with random numbers
		for i in 0..INS {
			in_private_keys[i] = Fq::rand(rng);
			in_blindings[i] = Fq::rand(rng);
			// Multiplying by 1/20 prevents the amounts from summing to more than
			// the size of the field (at least for fewer than 20 inputs)
			in_amounts[i] = Fq::rand(rng) * (Fq::from(20u64).inverse().unwrap());

			// Calculate what the input nullifier hashes would be based on these:
			let public_key = poseidon_native2.hash(&in_private_keys[i..i + 1]).unwrap();
			let leaf = poseidon_native5
				.hash(&[public_chain_id, in_amounts[i], public_key, in_blindings[i]])
				.unwrap();
			let signature = poseidon_native4
				.hash(&[in_private_keys[i], leaf, in_indices[i]])
				.unwrap();
			in_nullifier_hashes[i] = poseidon_native4
				.hash(&[leaf, in_indices[i], signature])
				.unwrap();

			// Simulate a Merkle tree for each input
			let default_leaf = [0u8; 32];
			let merkle_tree = SparseMerkleTree::<Fq, PoseidonBn254, TREE_HEIGHT>::new_sequential(
				&[leaf],
				&poseidon_native3,
				&default_leaf,
			)
			.unwrap();
			in_paths[i] = merkle_tree.generate_membership_proof(index);

			// Fix this for INS > BRIDGE_SIZE
			if i < BRIDGE_SIZE {
				in_root_set[i] = merkle_tree.root();
			}
		}

		// Change the first root to something incorrect
		in_root_set[0] = Fq::from(0u32);

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
			public_chain_id,
			arbitrary_data,
			in_nullifier_hashes[0],
			in_nullifier_hashes[0],
			-in_root_set[0].double(), // Give the verifier a different root set
			-in_root_set[1],
			in_nullifier_hashes[1],
			in_nullifier_hashes[1],
			-in_root_set[0],
			-in_root_set[1],
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

		// I don't like this default path thing -- how can I initalize the in_paths
		// array?
		let default_path = Path::<Fq, PoseidonBn254, TREE_HEIGHT> {
			path: [(Fq::from(0u64), Fq::from(0u64)); TREE_HEIGHT],
			_marker: PhantomData,
		};
		let mut in_paths: [Path<_, _, TREE_HEIGHT>; INS] = [default_path.clone(), default_path];
		// let mut in_paths_vec: Vec<Path::<Fq, PoseidonBn254, TREE_HEIGHT>>;
		// We'll say the index of each input is index:
		let index = 0u64;
		let in_indices = [Fq::from(index); INS];
		// Populate with random numbers
		for i in 0..INS {
			in_private_keys[i] = Fq::rand(rng);
			in_blindings[i] = Fq::rand(rng);
			// Multiplying by 1/20 prevents the amounts from summing to more than
			// the size of the field (at least for fewer than 20 inputs)
			in_amounts[i] = Fq::rand(rng) * (Fq::from(20u64).inverse().unwrap());

			// Calculate what the input nullifier hashes would be based on these:
			let public_key = poseidon_native2.hash(&in_private_keys[i..i + 1]).unwrap();
			let leaf = poseidon_native5
				.hash(&[public_chain_id, in_amounts[i], public_key, in_blindings[i]])
				.unwrap();
			let signature = poseidon_native4
				.hash(&[in_private_keys[i], leaf, in_indices[i]])
				.unwrap();
			in_nullifier_hashes[i] = poseidon_native4
				.hash(&[leaf, in_indices[i], signature])
				.unwrap();

			// Simulate a Merkle tree for each input
			let default_leaf = [0u8; 32];
			let merkle_tree = SparseMerkleTree::<Fq, PoseidonBn254, TREE_HEIGHT>::new_sequential(
				&[leaf],
				&poseidon_native3,
				&default_leaf,
			)
			.unwrap();
			in_paths[i] = merkle_tree.generate_membership_proof(index);

			// Fix this for INS > BRIDGE_SIZE
			if i < BRIDGE_SIZE {
				in_root_set[i] = merkle_tree.root();
			}
		}

		// Change the first secret to something incorrect
		in_private_keys[0] = Fq::from(0u32);

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

		// I don't like this default path thing -- how can I initalize the in_paths
		// array?
		let default_path = Path::<Fq, PoseidonBn254, TREE_HEIGHT> {
			path: [(Fq::from(0u64), Fq::from(0u64)); TREE_HEIGHT],
			_marker: PhantomData,
		};
		let mut in_paths: [Path<_, _, TREE_HEIGHT>; INS] = [default_path.clone(), default_path];
		// let mut in_paths_vec: Vec<Path::<Fq, PoseidonBn254, TREE_HEIGHT>>;
		// We'll say the index of each input is index:
		let index = 0u64;
		let in_indices = [Fq::from(index); INS];
		// Populate with random numbers
		for i in 0..INS {
			in_private_keys[i] = Fq::rand(rng);
			in_blindings[i] = Fq::rand(rng);
			// Multiplying by 1/20 prevents the amounts from summing to more than
			// the size of the field (at least for fewer than 20 inputs)
			in_amounts[i] = Fq::rand(rng) * (Fq::from(20u64).inverse().unwrap());

			// Calculate what the input nullifier hashes would be based on these:
			let public_key = poseidon_native2.hash(&in_private_keys[i..i + 1]).unwrap();
			let leaf = poseidon_native5
				.hash(&[public_chain_id, in_amounts[i], public_key, in_blindings[i]])
				.unwrap();
			let signature = poseidon_native4
				.hash(&[in_private_keys[i], leaf, in_indices[i]])
				.unwrap();
			in_nullifier_hashes[i] = poseidon_native4
				.hash(&[leaf, in_indices[i], signature])
				.unwrap();

			// Simulate a Merkle tree for each input
			let default_leaf = [0u8; 32];
			let merkle_tree = SparseMerkleTree::<Fq, PoseidonBn254, TREE_HEIGHT>::new_sequential(
				&[leaf],
				&poseidon_native3,
				&default_leaf,
			)
			.unwrap();
			in_paths[i] = merkle_tree.generate_membership_proof(index);

			// Fix this for INS > BRIDGE_SIZE
			if i < BRIDGE_SIZE {
				in_root_set[i] = merkle_tree.root();
			}
		}

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
			public_chain_id,
			arbitrary_data,
			in_nullifier_hashes[0].double(), // Give the verifier a different nullifier hash here
			in_nullifier_hashes[0],
			-in_root_set[0],
			-in_root_set[1],
			in_nullifier_hashes[1],
			in_nullifier_hashes[1],
			-in_root_set[0],
			-in_root_set[1],
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

		// I don't like this default path thing -- how can I initalize the in_paths
		// array?
		let default_path = Path::<Fq, PoseidonBn254, TREE_HEIGHT> {
			path: [(Fq::from(0u64), Fq::from(0u64)); TREE_HEIGHT],
			_marker: PhantomData,
		};
		let mut in_paths: [Path<_, _, TREE_HEIGHT>; INS] =
			[default_path.clone(), default_path.clone()];
		// let mut in_paths_vec: Vec<Path::<Fq, PoseidonBn254, TREE_HEIGHT>>;
		// We'll say the index of each input is index:
		let index = 0u64;
		let in_indices = [Fq::from(index); INS];
		// Populate with random numbers
		for i in 0..INS {
			in_private_keys[i] = Fq::rand(rng);
			in_blindings[i] = Fq::rand(rng);
			// Multiplying by 1/20 prevents the amounts from summing to more than
			// the size of the field (at least for fewer than 20 inputs)
			in_amounts[i] = Fq::rand(rng) * (Fq::from(20u64).inverse().unwrap());

			// Calculate what the input nullifier hashes would be based on these:
			let public_key = poseidon_native2.hash(&in_private_keys[i..i + 1]).unwrap();
			let leaf = poseidon_native5
				.hash(&[public_chain_id, in_amounts[i], public_key, in_blindings[i]])
				.unwrap();
			let signature = poseidon_native4
				.hash(&[in_private_keys[i], leaf, in_indices[i]])
				.unwrap();
			in_nullifier_hashes[i] = poseidon_native4
				.hash(&[leaf, in_indices[i], signature])
				.unwrap();

			// Simulate a Merkle tree for each input
			let default_leaf = [0u8; 32];
			let merkle_tree = SparseMerkleTree::<Fq, PoseidonBn254, TREE_HEIGHT>::new_sequential(
				&[leaf],
				&poseidon_native3,
				&default_leaf,
			)
			.unwrap();
			in_paths[i] = merkle_tree.generate_membership_proof(index);

			// Fix this for INS > BRIDGE_SIZE
			if i < BRIDGE_SIZE {
				in_root_set[i] = merkle_tree.root();
			}
		}

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

		// I don't like this default path thing -- how can I initalize the in_paths
		// array?
		let default_path = Path::<Fq, PoseidonBn254, TREE_HEIGHT> {
			path: [(Fq::from(0u64), Fq::from(0u64)); TREE_HEIGHT],
			_marker: PhantomData,
		};
		let mut in_paths: [Path<_, _, TREE_HEIGHT>; INS] = [default_path.clone(), default_path];
		// let mut in_paths_vec: Vec<Path::<Fq, PoseidonBn254, TREE_HEIGHT>>;
		// We'll say the index of each input is index:
		let index = 0u64;
		let in_indices = [Fq::from(index); INS];
		// Populate with random numbers
		for i in 0..INS {
			in_private_keys[i] = Fq::rand(rng);
			in_blindings[i] = Fq::rand(rng);
			// Multiplying by 1/20 prevents the amounts from summing to more than
			// the size of the field (at least for fewer than 20 inputs)
			in_amounts[i] = Fq::rand(rng) * (Fq::from(20u64).inverse().unwrap());

			// Calculate what the input nullifier hashes would be based on these:
			let public_key = poseidon_native2.hash(&in_private_keys[i..i + 1]).unwrap();
			let leaf = poseidon_native5
				.hash(&[public_chain_id, in_amounts[i], public_key, in_blindings[i]])
				.unwrap();
			let signature = poseidon_native4
				.hash(&[in_private_keys[i], leaf, in_indices[i]])
				.unwrap();
			in_nullifier_hashes[i] = poseidon_native4
				.hash(&[leaf, in_indices[i], signature])
				.unwrap();

			// Simulate a Merkle tree for each input
			let default_leaf = [0u8; 32];
			let merkle_tree = SparseMerkleTree::<Fq, PoseidonBn254, TREE_HEIGHT>::new_sequential(
				&[leaf],
				&poseidon_native3,
				&default_leaf,
			)
			.unwrap();
			in_paths[i] = merkle_tree.generate_membership_proof(index);

			// Fix this for INS > BRIDGE_SIZE
			if i < BRIDGE_SIZE {
				in_root_set[i] = merkle_tree.root();
			}
		}

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
			public_chain_id,
			arbitrary_data.double(), // Give the verifier different arbitrary data
			in_nullifier_hashes[0],
			in_nullifier_hashes[0],
			-in_root_set[0],
			-in_root_set[1],
			in_nullifier_hashes[1],
			in_nullifier_hashes[1],
			-in_root_set[0],
			-in_root_set[1],
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

		// I don't like this default path thing -- how can I initalize the in_paths
		// array?
		let default_path = Path::<Fq, PoseidonBn254, TREE_HEIGHT> {
			path: [(Fq::from(0u64), Fq::from(0u64)); TREE_HEIGHT],
			_marker: PhantomData,
		};
		let mut in_paths: [Path<_, _, TREE_HEIGHT>; INS] = [default_path.clone(), default_path];
		// let mut in_paths_vec: Vec<Path::<Fq, PoseidonBn254, TREE_HEIGHT>>;
		// We'll say the index of each input is index:
		let index = 0u64;
		let in_indices = [Fq::from(index); INS];
		// Populate with random numbers
		for i in 0..INS {
			in_private_keys[i] = Fq::rand(rng);
			in_blindings[i] = Fq::rand(rng);
			// Multiplying by 1/20 prevents the amounts from summing to more than
			// the size of the field (at least for fewer than 20 inputs)
			in_amounts[i] = Fq::rand(rng) * (Fq::from(20u64).inverse().unwrap());

			// Calculate what the input nullifier hashes would be based on these:
			let public_key = poseidon_native2.hash(&in_private_keys[i..i + 1]).unwrap();
			let leaf = poseidon_native5
				.hash(&[public_chain_id, in_amounts[i], public_key, in_blindings[i]])
				.unwrap();
			let signature = poseidon_native4
				.hash(&[in_private_keys[i], leaf, in_indices[i]])
				.unwrap();
			in_nullifier_hashes[i] = poseidon_native4
				.hash(&[leaf, in_indices[i], signature])
				.unwrap();

			// Simulate a Merkle tree for each input
			let default_leaf = [0u8; 32];
			let merkle_tree = SparseMerkleTree::<Fq, PoseidonBn254, TREE_HEIGHT>::new_sequential(
				&[leaf],
				&poseidon_native3,
				&default_leaf,
			)
			.unwrap();
			in_paths[i] = merkle_tree.generate_membership_proof(index);

			// Fix this for INS > BRIDGE_SIZE
			if i < BRIDGE_SIZE {
				in_root_set[i] = merkle_tree.root();
			}
		}

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
			public_chain_id.double(), // Give the verifier different chain ID
			arbitrary_data,
			in_nullifier_hashes[0],
			in_nullifier_hashes[0],
			-in_root_set[0],
			-in_root_set[1],
			in_nullifier_hashes[1],
			in_nullifier_hashes[1],
			-in_root_set[0],
			-in_root_set[1],
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

		// I don't like this default path thing -- how can I initalize the in_paths
		// array?
		let default_path = Path::<Fq, PoseidonBn254, TREE_HEIGHT> {
			path: [(Fq::from(0u64), Fq::from(0u64)); TREE_HEIGHT],
			_marker: PhantomData,
		};
		let mut in_paths: [Path<_, _, TREE_HEIGHT>; INS] = [default_path.clone(), default_path];
		// let mut in_paths_vec: Vec<Path::<Fq, PoseidonBn254, TREE_HEIGHT>>;
		// We'll say the index of each input is index:
		let index = 0u64;
		let in_indices = [Fq::from(index); INS];
		// Populate with random numbers
		for i in 0..INS {
			in_private_keys[i] = Fq::rand(rng);
			in_blindings[i] = Fq::rand(rng);
			// Multiplying by 1/20 prevents the amounts from summing to more than
			// the size of the field (at least for fewer than 20 inputs)
			in_amounts[i] = Fq::rand(rng) * (Fq::from(20u64).inverse().unwrap());

			// Calculate what the input nullifier hashes would be based on these:
			let public_key = poseidon_native2.hash(&in_private_keys[i..i + 1]).unwrap();
			let leaf = poseidon_native5
				.hash(&[public_chain_id, in_amounts[i], public_key, in_blindings[i]])
				.unwrap();
			let signature = poseidon_native4
				.hash(&[in_private_keys[i], leaf, in_indices[i]])
				.unwrap();
			in_nullifier_hashes[i] = poseidon_native4
				.hash(&[leaf, in_indices[i], signature])
				.unwrap();

			// Simulate a Merkle tree for each input
			let default_leaf = [0u8; 32];
			let merkle_tree = SparseMerkleTree::<Fq, PoseidonBn254, TREE_HEIGHT>::new_sequential(
				&[leaf],
				&poseidon_native3,
				&default_leaf,
			)
			.unwrap();
			in_paths[i] = merkle_tree.generate_membership_proof(index);

			// Fix this for INS > BRIDGE_SIZE
			if i < BRIDGE_SIZE {
				in_root_set[i] = merkle_tree.root();
			}
		}

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
			public_chain_id,
			arbitrary_data,
			in_nullifier_hashes[0],
			in_nullifier_hashes[0],
			-in_root_set[0],
			-in_root_set[1],
			in_nullifier_hashes[1],
			in_nullifier_hashes[1],
			-in_root_set[0],
			-in_root_set[1],
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
}
