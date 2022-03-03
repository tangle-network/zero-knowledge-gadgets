use ark_bls12_381::{Bls12_381, Fr as BlsFr};
use ark_crypto_primitives::SNARK;
use ark_ed_on_bls12_381::{EdwardsAffine, Fr as EdBlsFr};
use ark_ff::{One, UniformRand};
use ark_groth16::Groth16;
use ark_marlin::Marlin;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::{ipa_pc::InnerProductArgPC, marlin_pc::MarlinKZG10, sonic_pc::SonicKZG10};
use ark_std::{self, test_rng, time::Instant, vec::Vec};
use arkworks_r1cs_circuits::anchor::AnchorCircuit;
use arkworks_native_gadgets::merkle_tree::SparseMerkleTree;
use arkworks_native_gadgets::poseidon::{FieldHasher, Poseidon};
use arkworks_r1cs_gadgets::poseidon::PoseidonGadget;

use arkworks_utils::utils::common::{setup_params_x5_3, setup_params_x5_4};
use blake2::Blake2s;

macro_rules! setup_circuit {
	($test_field:ty) => {{
		const ANCHOR_CT: usize = 4;
		const HEIGHT: usize = 30;
		const DEFAULT_LEAF: [u8; 32] = [0u8; 32];

		type Circuit = AnchorCircuit<$test_field, PoseidonGadget<$test_field>, HEIGHT, ANCHOR_CT>;

		let rng = &mut test_rng();
		let curve = arkworks_utils::utils::common::Curve::Bn254;
		// Secret inputs for the leaf
		let secret = <$test_field>::rand(rng);
		let nullifier = <$test_field>::rand(rng);
		// Public inputs for the leaf
		let chain_id = <$test_field>::one();

		// Round params for the poseidon in leaf creation gadget
		let params4 = setup_params_x5_4(curve);
		let leaf_hasher = Poseidon::<$test_field>::new(params4);

		let params3 = setup_params_x5_3(curve);
		let nullifier_hasher = Poseidon::<$test_field>::new(params3);
		// Creating the leaf
		let leaf_hash = leaf_hasher.hash(&[chain_id, secret, nullifier]).unwrap();
		let nullifier_hash = nullifier_hasher.hash_two(&nullifier, &nullifier).unwrap();

		// Arbitrary data
		let arbitrary_input = <$test_field>::rand(rng);

		// Making params for poseidon in merkle tree

		let params3 = setup_params_x5_3(curve);
		let leaves = vec![
			<$test_field>::rand(rng),
			<$test_field>::rand(rng),
			leaf_hash,
			<$test_field>::rand(rng),
		];
		let tree_hasher = Poseidon::<$test_field>::new(params3);
		// Making the merkle tree
		let mt = SparseMerkleTree::<$test_field, Poseidon<$test_field>, HEIGHT>::new_sequential(
			&leaves,
			&tree_hasher,
			&DEFAULT_LEAF,
		)
		.unwrap();
		// Getting the proof path
		let path = mt.generate_membership_proof(2);
		let root = mt.root();
		let roots = [
			<$test_field>::rand(rng),
			<$test_field>::rand(rng),
			<$test_field>::rand(rng),
			root.clone(),
		];
		let mc = Circuit::new(
			arbitrary_input.clone(),
			secret,
			nullifier,
			chain_id,
			roots.clone(),
			path,
			nullifier_hash,
			tree_hasher,
			leaf_hasher,
		);
		let mut public_inputs = Vec::new();
		public_inputs.push(chain_id);
		public_inputs.push(nullifier_hash);
		public_inputs.extend(roots.to_vec());
		public_inputs.push(arbitrary_input);
		(public_inputs, mc)
	}};
}

macro_rules! measure {
	($task:block, $backend:expr, $task_name:expr, $num_iter:expr) => {{
		let start = Instant::now();
		for _ in 0..($num_iter - 1) {
			$task;
		}
		let res = $task;
		let end = start.elapsed();
		println!(
			"{}: Average {} time: {:?}",
			$backend,
			$task_name,
			end / $num_iter
		);
		res
	}};
}

macro_rules! benchmark_marlin {
	($marlin:ty, $field:ty, $name:expr, $nc:expr, $nv:expr, $num_iter:expr) => {
		let rng = &mut test_rng();
		let (public_inputs, circuit) = setup_circuit!($field);

		// Setup
		let srs = measure!(
			{ <$marlin>::universal_setup($nc, $nv, 3 * $nv, rng).unwrap() },
			$name,
			"setup",
			$num_iter
		);

		// Index
		let keys = measure!(
			{ <$marlin>::index(&srs, circuit.clone()).unwrap() },
			$name,
			"index",
			$num_iter
		);

		// Prove
		let proof = measure!(
			{ <$marlin>::prove(&keys.0, circuit.clone(), rng).unwrap() },
			$name,
			"prove",
			$num_iter
		);

		// verify
		let _ = measure!(
			{ <$marlin>::verify(&keys.1, &public_inputs, &proof, rng).unwrap() },
			$name,
			"verify",
			$num_iter
		);
	};
}

macro_rules! benchmark_groth {
	($groth:ty, $field:ty, $num_iter:expr) => {
		let rng = &mut test_rng();
		let (public_inputs, circuit) = setup_circuit!($field);

		// Setup
		let keys = measure!(
			{ <$groth>::circuit_specific_setup(circuit.clone(), rng).unwrap() },
			"Groth16",
			"setup",
			$num_iter
		);

		// Prove
		let proof = measure!(
			{ <$groth>::prove(&keys.0, circuit.clone(), rng).unwrap() },
			"Groth16",
			"prove",
			$num_iter
		);

		// verify
		let _ = measure!(
			{ <$groth>::verify(&keys.1, &public_inputs, &proof).unwrap() },
			"Groth16",
			"verify",
			$num_iter
		);
	};
}

fn benchmark_groth16(num_iter: u32) {
	type GrothSetup = Groth16<Bls12_381>;
	benchmark_groth!(GrothSetup, BlsFr, num_iter);
}

fn benchmark_marlin_poly(nc: usize, nv: usize, num_iter: u32) {
	type KZG10 = MarlinKZG10<Bls12_381, DensePolynomial<BlsFr>>;
	type MarlinSetup = Marlin<BlsFr, KZG10, Blake2s>;
	benchmark_marlin!(MarlinSetup, BlsFr, "Marlin_PolyKZG10", nc, nv, num_iter);
}

fn benchmark_marlin_sonic(nc: usize, nv: usize, num_iter: u32) {
	type Sonic = SonicKZG10<Bls12_381, DensePolynomial<BlsFr>>;
	type MarlinSetup = Marlin<BlsFr, Sonic, Blake2s>;

	benchmark_marlin!(MarlinSetup, BlsFr, "Marlin_Sonic", nc, nv, num_iter);
}

fn benchmark_marlin_ipa_pc(nc: usize, nv: usize, num_iter: u32) {
	type IPA = InnerProductArgPC<EdwardsAffine, Blake2s, DensePolynomial<EdBlsFr>>;
	type MarlinSetup = Marlin<EdBlsFr, IPA, Blake2s>;

	benchmark_marlin!(MarlinSetup, EdBlsFr, "Marlin_IPA_PC", nc, nv, num_iter);
}

fn main() {
	let nc = 65536;
	let nv = 65536;
	let num_iter = 5;

	// Groth16
	benchmark_groth16(num_iter);
	// MarlinKZG10
	benchmark_marlin_poly(nc, nv, num_iter);
	// Sonic
	benchmark_marlin_sonic(nc, nv, num_iter);
	// IPA
	benchmark_marlin_ipa_pc(nc, nv, num_iter);
}
