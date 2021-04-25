use ark_bls12_381::{Bls12_381, Fr as BlsFr};
use ark_ed_on_bls12_381::{EdwardsAffine, Fr as EdBlsFr};
use ark_ff::{One, UniformRand};
use ark_groth16::Groth16;
use ark_marlin::Marlin;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::{
	ipa_pc::InnerProductArgPC, kzg10::KZG10, marlin_pc::MarlinKZG10, sonic_pc::SonicKZG10,
};
use ark_std::{test_rng, time::Instant};
use arkworks_gadgets::{
	circuit::mixer_circuit::MixerCircuit,
	leaf::{
		bridge::{constraints::BridgeLeafGadget, BridgeLeaf, Public as LeafPublic},
		LeafCreation,
	},
	set::{
		membership::{constraints::SetMembershipGadget, SetMembership},
		Set,
	},
	test_data::{get_mds_3, get_mds_5, get_rounds_3, get_rounds_5},
};
use blake2::Blake2s;
use webb_crypto_primitives::{
	crh::poseidon::{constraints::CRHGadget, sbox::PoseidonSbox, PoseidonParameters, Rounds, CRH},
	merkle_tree::{Config as MerkleConfig, MerkleTree},
	SNARK,
};

macro_rules! setup_circuit {
	($test_field:ty) => {{
		#[derive(Default, Clone)]
		struct PoseidonRounds5;

		impl Rounds for PoseidonRounds5 {
			const FULL_ROUNDS: usize = 8;
			const PARTIAL_ROUNDS: usize = 57;
			const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
			const WIDTH: usize = 5;
		}

		type PoseidonCRH5 = CRH<$test_field, PoseidonRounds5>;
		type PoseidonCRH5Gadget = CRHGadget<$test_field, PoseidonRounds5>;

		#[derive(Default, Clone)]
		struct PoseidonRounds3;

		impl Rounds for PoseidonRounds3 {
			const FULL_ROUNDS: usize = 8;
			const PARTIAL_ROUNDS: usize = 57;
			const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
			const WIDTH: usize = 3;
		}

		type PoseidonCRH3 = CRH<$test_field, PoseidonRounds3>;
		type PoseidonCRH3Gadget = CRHGadget<$test_field, PoseidonRounds3>;

		type Leaf = BridgeLeaf<$test_field, PoseidonCRH5>;
		type LeafGadget = BridgeLeafGadget<$test_field, PoseidonCRH5, PoseidonCRH5Gadget, Leaf>;

		#[derive(Clone)]
		struct MixerTreeConfig;
		impl MerkleConfig for MixerTreeConfig {
			type H = PoseidonCRH3;

			const HEIGHT: usize = 30;
		}

		type MixerTree = MerkleTree<MixerTreeConfig>;

		type TestSetMembership = SetMembership<$test_field>;
		type TestSetMembershipGadget = SetMembershipGadget<$test_field>;

		type Circuit = MixerCircuit<
			$test_field,
			MixerTreeConfig,
			PoseidonCRH5,
			PoseidonCRH5Gadget,
			PoseidonCRH3Gadget,
			Leaf,
			LeafGadget,
			TestSetMembership,
			TestSetMembershipGadget,
		>;

		let rng = &mut test_rng();

		// Secret inputs for the leaf
		let leaf_private = Leaf::generate_secrets(rng).unwrap();
		// Public inputs for the leaf
		let chain_id = <$test_field>::one();
		let leaf_public = LeafPublic::new(chain_id);

		// Round params for the poseidon in leaf creation gadget
		let rounds5 = get_rounds_5::<$test_field>();
		let mds5 = get_mds_5::<$test_field>();
		let params5 = PoseidonParameters::<$test_field>::new(rounds5, mds5);
		// Creating the leaf
		let leaf = Leaf::create_leaf(&leaf_private, &leaf_public, &params5).unwrap();
		let nullifier_hash = Leaf::create_nullifier(&leaf_private, &params5).unwrap();

		// Making params for poseidon in merkle tree
		let rounds3 = get_rounds_3::<$test_field>();
		let mds3 = get_mds_3::<$test_field>();
		let params3 = PoseidonParameters::<$test_field>::new(rounds3, mds3);
		let leaves = vec![
			<$test_field>::rand(rng),
			<$test_field>::rand(rng),
			leaf,
			<$test_field>::rand(rng),
		];
		// Making the merkle tree
		let mt = MixerTree::new(params3.clone(), &leaves).unwrap();
		// Getting the proof path
		let path = mt.generate_proof(2, &leaf).unwrap();
		let root = mt.root();
		let roots = vec![
			<$test_field>::rand(rng),
			<$test_field>::rand(rng),
			<$test_field>::rand(rng),
			root,
		];
		let set_private_inputs = TestSetMembership::generate_secrets(&root, &roots).unwrap();
		let mc = Circuit::new(
			leaf_private,
			leaf_public,
			set_private_inputs,
			roots.clone(),
			params5,
			params3,
			path,
			root,
			nullifier_hash,
		);
		let mut public_inputs = Vec::new();
		public_inputs.push(chain_id);
		public_inputs.push(nullifier_hash);
		public_inputs.extend(roots);
		public_inputs.push(root);
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
			{ <$marlin>::universal_setup($nc, $nv, $nv, rng).unwrap() },
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
	let nc = 36000;
	let nv = 36000;
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
