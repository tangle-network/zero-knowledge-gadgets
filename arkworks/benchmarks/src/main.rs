use ark_bls12_381::{Bls12_381, Fr as BlsFr};
use ark_bn254::Bn254;
use ark_crypto_primitives::{Error, SNARK};
use ark_ed_on_bls12_381::{EdwardsAffine, Fr as EdBlsFr};
use ark_ff::{BigInteger, One, PrimeField, UniformRand};
use ark_groth16::Groth16;
use ark_marlin::Marlin;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::{ipa_pc::InnerProductArgPC, marlin_pc::MarlinKZG10, sonic_pc::SonicKZG10};
use ark_std::{self, test_rng, time::Instant, vec::Vec};
use arkworks_native_gadgets::{
	merkle_tree::SparseMerkleTree,
	poseidon::{sbox::PoseidonSbox, FieldHasher, Poseidon, PoseidonParameters},
};
use arkworks_r1cs_circuits::vanchor::VAnchorCircuit;
use arkworks_r1cs_gadgets::poseidon::PoseidonGadget;
use arkworks_setups::{
	common::{setup_keys_unchecked, setup_tree_and_create_path, SMT},
	r1cs::vanchor::VAnchorR1CSProver,
	VAnchorProver,
};
use arkworks_utils::{
	bytes_matrix_to_f, bytes_vec_to_f, poseidon_params::setup_poseidon_params, Curve,
};
use blake2::Blake2s;
use std::collections::btree_map::BTreeMap;

pub fn setup_params<F: PrimeField>(curve: Curve, exp: i8, width: u8) -> PoseidonParameters<F> {
	let pos_data = setup_poseidon_params(curve, exp, width).unwrap();

	let mds_f = bytes_matrix_to_f(&pos_data.mds);
	let rounds_f = bytes_vec_to_f(&pos_data.rounds);

	PoseidonParameters {
		mds_matrix: mds_f,
		round_keys: rounds_f,
		full_rounds: pos_data.full_rounds,
		partial_rounds: pos_data.partial_rounds,
		sbox: PoseidonSbox(pos_data.exp),
		width: pos_data.width,
	}
}

macro_rules! setup_circuit {
	($test_engine:ty, $test_field:ty, $test_curve:expr) => {{
		const N_INS: usize = 2;
		const N_OUTS: usize = 2;
		const ANCHOR_CT: usize = 2;
		const HEIGHT: usize = 30;
		const DEFAULT_LEAF: [u8; 32] = [0u8; 32];

		// Initialize hashers
		let params2 = setup_params::<$test_field>($test_curve, 5, 2);
		let params3 = setup_params::<$test_field>($test_curve, 5, 3);
		let params4 = setup_params::<$test_field>($test_curve, 5, 4);
		let params5 = setup_params::<$test_field>($test_curve, 5, 5);

		let keypair_hasher = Poseidon::<$test_field> { params: params2 };
		let tree_hasher = Poseidon::<$test_field> { params: params3 };
		let nullifier_hasher = Poseidon::<$test_field> { params: params4 };
		let leaf_hasher = Poseidon::<$test_field> { params: params5 };

		#[allow(non_camel_case_types)]
		type Prover = VAnchorR1CSProver<$test_engine, HEIGHT, ANCHOR_CT, N_INS, N_OUTS>;

		let rng = &mut test_rng();
		let random_circuit = Prover::setup_random_circuit($test_curve, DEFAULT_LEAF, rng);

		// Make a proof now
		let public_amount: u32 = 10;
		let ext_data_hash = <$test_field>::rand(rng);

		// Input Utxos
		let in_chain_id = 0u64;
		let in_amount = 5;
		let index = 0u64;
		let in_utxo1 =
			Prover::create_random_utxo($test_curve, in_chain_id, in_amount, Some(index), rng)
				.unwrap();
		let in_utxo2 =
			Prover::create_random_utxo($test_curve, in_chain_id, in_amount, Some(1), rng).unwrap();
		let in_utxos = [in_utxo1.clone(), in_utxo2.clone()];

		// Output Utxos
		let out_chain_id = 0u64;
		let out_amount = 10;
		let out_utxo1 =
			Prover::create_random_utxo($test_curve, out_chain_id, out_amount, None, rng).unwrap();
		let out_utxo2 =
			Prover::create_random_utxo($test_curve, out_chain_id, out_amount, None, rng).unwrap();
		let out_utxos = [out_utxo1, out_utxo2];

		let leaf0 = in_utxo1.commitment;
		let leaf1 = in_utxo2.commitment;

		let (smt, _) = setup_tree_and_create_path::<$test_field, Poseidon<$test_field>, HEIGHT>(
			&tree_hasher,
			&[leaf0, leaf1],
			0,
			&DEFAULT_LEAF,
		)
		.unwrap();

		let in_paths = [
			smt.generate_membership_proof(0),
			smt.generate_membership_proof(1),
		];

		let mut in_leaves = BTreeMap::new();
		in_leaves.insert(in_chain_id, vec![
			leaf0.into_repr().to_bytes_be(),
			leaf1.into_repr().to_bytes_be(),
		]);
		let in_indices: [u32; 2] = [0, 1];
		let in_root_set = [
			smt.root().into_repr().to_bytes_be(),
			smt.root().into_repr().to_bytes_be(),
		];

		let in_nullifiers: Vec<$test_field> = in_utxos
			.iter()
			.map(|x| x.calculate_nullifier(&nullifier_hasher.clone()).unwrap())
			.collect();

		// Cast as field elements
		let chain_id_elt = <$test_field>::from(in_chain_id);
		let public_amount_elt = <$test_field>::from(public_amount);
		let ext_data_hash_elt =
			<$test_field>::from_be_bytes_mod_order(&ext_data_hash.into_repr().to_bytes_be());
		// Generate the paths for each UTXO
		let mut trees = BTreeMap::<u64, SMT<$test_field, Poseidon<$test_field>, HEIGHT>>::new();

		let public_inputs = Prover::construct_public_inputs(
			chain_id_elt,
			public_amount_elt,
			in_root_set
				.clone()
				.map(|elt| <$test_field>::from_be_bytes_mod_order(&elt))
				.to_vec(),
			in_nullifiers.to_vec(),
			out_utxos.clone().map(|utxo| utxo.commitment).to_vec(),
			ext_data_hash_elt,
		);

		// Get the circuit
		let circuit = Prover::setup_circuit(
			chain_id_elt,
			public_amount_elt,
			ext_data_hash_elt,
			in_utxos,
			in_indices.map(<$test_field>::from),
			in_paths.to_vec(),
			in_root_set.map(|elt| <$test_field>::from_be_bytes_mod_order(&elt)),
			out_utxos.clone(),
			keypair_hasher,
			tree_hasher,
			nullifier_hasher,
			leaf_hasher,
		)
		.unwrap();

		(public_inputs, circuit)
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
	($marlin:ty, $engine:ty, $field:ty, $curve:expr, $name:expr, $nc:expr, $nv:expr, $num_iter:expr) => {
		let rng = &mut test_rng();
		let (public_inputs, circuit) = setup_circuit!($engine, $field, $curve);

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
	($groth:ty, $engine:ty, $field:ty, $curve:expr, $num_iter:expr) => {
		let rng = &mut test_rng();
		let (public_inputs, circuit) = setup_circuit!($engine, $field, $curve);

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
	type GrothSetup = Groth16<Bn254>;
	benchmark_groth!(GrothSetup, Bn254, ark_bn254::Fr, Curve::Bn254, num_iter);
}

// fn benchmark_marlin_poly(nc: usize, nv: usize, num_iter: u32) {
// 	type KZG10 = MarlinKZG10<Bls12_381, DensePolynomial<BlsFr>>;
// 	type MarlinSetup = Marlin<BlsFr, KZG10, Blake2s>;
// 	benchmark_marlin!(MarlinSetup, BlsFr, "Marlin_PolyKZG10", nc, nv, num_iter);
// }

// fn benchmark_marlin_sonic(nc: usize, nv: usize, num_iter: u32) {
// 	type Sonic = SonicKZG10<Bls12_381, DensePolynomial<BlsFr>>;
// 	type MarlinSetup = Marlin<BlsFr, Sonic, Blake2s>;

// 	benchmark_marlin!(MarlinSetup, BlsFr, "Marlin_Sonic", nc, nv, num_iter);
// }

// fn benchmark_marlin_ipa_pc(nc: usize, nv: usize, num_iter: u32) {
// 	type IPA = InnerProductArgPC<EdwardsAffine, Blake2s,
// DensePolynomial<EdBlsFr>>; 	type MarlinSetup = Marlin<EdBlsFr, IPA, Blake2s>;

// 	benchmark_marlin!(MarlinSetup, EdBlsFr, "Marlin_IPA_PC", nc, nv, num_iter);
// }

fn main() {
	let nc = 65536;
	let nv = 65536;
	let num_iter = 5;

	// Groth16
	benchmark_groth16(num_iter);
	// // MarlinKZG10
	// benchmark_marlin_poly(nc, nv, num_iter);
	// // Sonic
	// benchmark_marlin_sonic(nc, nv, num_iter);
	// // IPA
	// benchmark_marlin_ipa_pc(nc, nv, num_iter);
}
