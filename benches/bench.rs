use ark_bls12_381::{Bls12_381, Fr as BlsFr};
use ark_ff::{One, UniformRand};
use ark_groth16::Groth16;
use ark_marlin::Marlin;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::marlin_pc::MarlinKZG10;
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

			const HEIGHT: usize = 10;
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
		(chain_id, root, roots, nullifier_hash, mc)
	}};
}

fn benchmark_groth16_setup() {
	let rng = &mut test_rng();
	let (_, _, _, _, circuit) = setup_circuit!(BlsFr);

	type GrothSetup = Groth16<Bls12_381>;

	let start = Instant::now();
	let num_iter = 10;
	for _ in 0..num_iter {
		let _ = GrothSetup::circuit_specific_setup(circuit.clone(), rng).unwrap();
	}
	let end = start.elapsed();
	println!("Groth16: Average setup time: {:?}", end / num_iter);
}

fn benchmark_groth16_prove() {
	let rng = &mut test_rng();
	let (_, _, _, _, circuit) = setup_circuit!(BlsFr);

	type GrothSetup = Groth16<Bls12_381>;

	let (pk, _) = GrothSetup::circuit_specific_setup(circuit.clone(), rng).unwrap();

	let start = Instant::now();
	let num_iter = 10;
	for _ in 0..num_iter {
		let _ = GrothSetup::prove(&pk, circuit.clone(), rng).unwrap();
	}
	let end = start.elapsed();
	println!("Groth16: Average proving time: {:?}", end / num_iter);
}

fn benchmark_groth16_verify() {
	let rng = &mut test_rng();
	let (chain_id, root, roots, nullifier_hash, circuit) = setup_circuit!(BlsFr);

	type GrothSetup = Groth16<Bls12_381>;

	let (pk, vk) = GrothSetup::circuit_specific_setup(circuit.clone(), rng).unwrap();
	let proof = GrothSetup::prove(&pk, circuit, rng).unwrap();

	let mut public_inputs = Vec::new();
	public_inputs.push(chain_id);
	public_inputs.push(nullifier_hash);
	public_inputs.extend(roots);
	public_inputs.push(root);

	let start = Instant::now();
	let num_iter = 10;
	for _ in 0..num_iter {
		let _ = GrothSetup::verify(&vk, &public_inputs, &proof).unwrap();
	}
	let end = start.elapsed();
	println!("Groth16: Average verify time: {:?}", end / num_iter);
}

fn benchmark_marlin_setup() {
	let rng = &mut test_rng();

	type KZG10 = MarlinKZG10<Bls12_381, DensePolynomial<BlsFr>>;
	type MarlinSetup = Marlin<BlsFr, KZG10, Blake2s>;

	let nc = 36000;
	let nv = 36000;
	let start = Instant::now();
	let num_iter = 10;
	for _ in 0..num_iter {
		let _ = MarlinSetup::universal_setup(nc, nv, nv, rng).unwrap();
	}
	let end = start.elapsed();
	println!("Marlin: Average setup time: {:?}", end / num_iter);
}

fn benchmark_marlin_index() {
	let rng = &mut test_rng();
	let (_, _, _, _, circuit) = setup_circuit!(BlsFr);

	type KZG10 = MarlinKZG10<Bls12_381, DensePolynomial<BlsFr>>;
	type MarlinSetup = Marlin<BlsFr, KZG10, Blake2s>;

	let nc = 36000;
	let nv = 36000;
	let srs = MarlinSetup::universal_setup(nc, nv, nv, rng).unwrap();

	let start = Instant::now();
	let num_iter = 10;
	for _ in 0..num_iter {
		let _ = MarlinSetup::index(&srs, circuit.clone()).unwrap();
	}
	let end = start.elapsed();
	println!("Marlin: Average index time: {:?}", end / num_iter);
}

fn benchmark_marlin_prove() {
	let rng = &mut test_rng();
	let (_, _, _, _, circuit) = setup_circuit!(BlsFr);

	type KZG10 = MarlinKZG10<Bls12_381, DensePolynomial<BlsFr>>;
	type MarlinSetup = Marlin<BlsFr, KZG10, Blake2s>;

	let nc = 36000;
	let nv = 36000;
	let srs = MarlinSetup::universal_setup(nc, nv, nv, rng).unwrap();
	let (pk, _) = MarlinSetup::index(&srs, circuit.clone()).unwrap();

	let start = Instant::now();
	let num_iter = 10;
	for _ in 0..num_iter {
		let _ = MarlinSetup::prove(&pk, circuit.clone(), rng).unwrap();
	}
	let end = start.elapsed();
	println!("Marlin: Average prove time: {:?}", end / num_iter);
}

fn benchmark_marlin_verify() {
	let rng = &mut test_rng();
	let (chain_id, root, roots, nullifier_hash, circuit) = setup_circuit!(BlsFr);

	type KZG10 = MarlinKZG10<Bls12_381, DensePolynomial<BlsFr>>;
	type MarlinSetup = Marlin<BlsFr, KZG10, Blake2s>;

	let nc = 36000;
	let nv = 36000;
	let srs = MarlinSetup::universal_setup(nc, nv, nv, rng).unwrap();
	let (pk, vk) = MarlinSetup::index(&srs, circuit.clone()).unwrap();
	let proof = MarlinSetup::prove(&pk, circuit, rng).unwrap();

	let mut public_inputs = Vec::new();
	public_inputs.push(chain_id);
	public_inputs.push(nullifier_hash);
	public_inputs.extend(roots);
	public_inputs.push(root);

	let start = Instant::now();
	let num_iter = 10;
	for _ in 0..num_iter {
		let _ = MarlinSetup::verify(&vk, &public_inputs, &proof, rng).unwrap();
	}
	let end = start.elapsed();
	println!("Marlin: Average verify time: {:?}", end / num_iter);
}

fn main() {
	benchmark_groth16_setup();
	benchmark_groth16_prove();
	benchmark_groth16_verify();
	benchmark_marlin_setup();
	benchmark_marlin_index();
	benchmark_marlin_prove();
	benchmark_marlin_verify();
}
