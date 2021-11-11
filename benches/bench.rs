use ark_bls12_381::{Bls12_381, Fr as BlsFr};
use ark_crypto_primitives::SNARK;
use ark_ed_on_bls12_381::{EdwardsAffine, Fr as EdBlsFr};
use ark_ff::{One, UniformRand};
use ark_groth16::Groth16;
use ark_marlin::Marlin;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::{ipa_pc::InnerProductArgPC, marlin_pc::MarlinKZG10, sonic_pc::SonicKZG10};
use ark_std::{self, rc::Rc, test_rng, time::Instant};
use arkworks_gadgets::{
	arbitrary::bridge_data::Input as BridgeDataInput,
	circuit::bridge::BridgeCircuit,
	leaf::bridge::{
		constraints::BridgeLeafGadget, BridgeLeaf, Private as LeafPrivate, Public as LeafPublic,
	},
	merkle_tree::{Config as MerkleConfig, SparseMerkleTree},
	poseidon::{constraints::CRHGadget, sbox::PoseidonSbox, PoseidonParameters, Rounds, CRH},
	set::{
		membership::{constraints::SetMembershipGadget, SetMembership},
		Set,
	},
	utils::{
		get_mds_poseidon_bn254_x5_3, get_mds_poseidon_bn254_x5_5, get_rounds_poseidon_bn254_x5_3,
		get_rounds_poseidon_bn254_x5_5,
	},
};
use blake2::Blake2s;

macro_rules! setup_circuit {
	($test_field:ty) => {{
		const M: usize = 4;
		const N: usize = 30;

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
		type LeafGadget = BridgeLeafGadget<$test_field, PoseidonCRH5, PoseidonCRH5Gadget>;

		#[derive(Clone)]
		struct BridgeTreeConfig;
		impl MerkleConfig for BridgeTreeConfig {
			type H = PoseidonCRH3;
			type LeafH = PoseidonCRH3;

			const HEIGHT: u8 = N as _;
		}

		type BridgeTree = SparseMerkleTree<BridgeTreeConfig>;

		type TestSetMembership = SetMembership<$test_field, M>;
		type TestSetMembershipGadget = SetMembershipGadget<$test_field, M>;

		type Circuit = BridgeCircuit<
			$test_field,
			PoseidonCRH5,
			PoseidonCRH5Gadget,
			BridgeTreeConfig,
			PoseidonCRH3Gadget,
			PoseidonCRH3Gadget,
			TestSetMembership,
			TestSetMembershipGadget,
			N,
			M,
		>;

		let rng = &mut test_rng();

		// Secret inputs for the leaf
		let leaf_private = LeafPrivate::generate(rng);
		// Public inputs for the leaf
		let chain_id = <$test_field>::one();
		let leaf_public = LeafPublic::new(chain_id);
		let leaf = Leaf::new(leaf_private.clone(), leaf_public.clone());

		// Round params for the poseidon in leaf creation gadget
		let rounds5 = get_rounds_poseidon_bn254_x5_5::<$test_field>();
		let mds5 = get_mds_poseidon_bn254_x5_5::<$test_field>();
		let params5 = PoseidonParameters::<$test_field>::new(rounds5, mds5);
		// Creating the leaf
		let leaf_hash = leaf.create_leaf(&params5).unwrap();
		let nullifier_hash = leaf.create_nullifier(&params5).unwrap();

		let fee = <$test_field>::rand(rng);
		let refund = <$test_field>::rand(rng);
		let recipient = <$test_field>::rand(rng);
		let relayer = <$test_field>::rand(rng);
		let commitment = <$test_field>::rand(rng);
		// Arbitrary data
		let arbitrary_input = BridgeDataInput::new(recipient, relayer, fee, refund, commitment);

		// Making params for poseidon in merkle tree
		let rounds3 = get_rounds_poseidon_bn254_x5_3::<$test_field>();
		let mds3 = get_mds_poseidon_bn254_x5_3::<$test_field>();
		let params3 = PoseidonParameters::<$test_field>::new(rounds3, mds3);
		let leaves = vec![
			<$test_field>::rand(rng),
			<$test_field>::rand(rng),
			leaf_hash,
			<$test_field>::rand(rng),
		];
		let inner_params = Rc::new(params3.clone());
		let leaf_params = inner_params.clone();
		// Making the merkle tree
		let mt = BridgeTree::new_sequential(inner_params, leaf_params, &leaves).unwrap();
		// Getting the proof path
		let path = mt.generate_membership_proof(2);
		let root = mt.root();
		let roots = [
			<$test_field>::rand(rng),
			<$test_field>::rand(rng),
			<$test_field>::rand(rng),
			root.clone().inner(),
		];
		let set_private_inputs =
			TestSetMembership::generate_secrets(&root.clone().inner(), &roots).unwrap();
		let mc = Circuit::new(
			arbitrary_input.clone(),
			leaf_private,
			leaf_public,
			set_private_inputs,
			roots.clone(),
			params5,
			path,
			root.clone().inner(),
			nullifier_hash,
		);
		let mut public_inputs = Vec::new();
		public_inputs.push(chain_id);
		public_inputs.push(nullifier_hash);
		public_inputs.extend(roots.to_vec());
		public_inputs.push(root.inner());
		public_inputs.push(arbitrary_input.recipient);
		public_inputs.push(arbitrary_input.relayer);
		public_inputs.push(arbitrary_input.fee);
		public_inputs.push(arbitrary_input.refund);
		public_inputs.push(arbitrary_input.commitment);
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
	// benchmark_marlin_ipa_pc(nc, nv, num_iter);
}
