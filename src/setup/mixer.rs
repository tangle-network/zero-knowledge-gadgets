use crate::mimc::MiMCParameters;
use ark_ec::PairingEngine;
use super::common::*;
use crate::{
	arbitrary::mixer_data::{constraints::MixerDataGadget, Input as MixerDataInput, MixerData},
	circuit::mixer::MixerCircuit,
	leaf::{
		mixer::{constraints::MixerLeafGadget, MixerLeaf, Private as LeafPrivate},
		LeafCreation,
	},
	poseidon::PoseidonParameters,
};
use ark_crypto_primitives::SNARK;
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_std::{
	rand::{CryptoRng, Rng, RngCore},
	vec::Vec,
};
use ark_ff::PrimeField;

pub type MixerConstraintData<F> = MixerData<F>;
pub type MixerConstraintDataInput<F> = MixerDataInput<F>;
pub type MixerConstraintDataGadget<F> = MixerDataGadget<F>;

pub type Leaf_x5<F> = MixerLeaf<F, PoseidonCRH_x5_5<F>>;
pub type LeafGadget_x5<F> = MixerLeafGadget<F, PoseidonCRH_x5_5<F>, PoseidonCRH_x5_5Gadget<F>, Leaf_x5<F>>;

pub type Circuit_x5<F>= MixerCircuit<
	F,
	MixerConstraintData<F>,
	MixerConstraintDataGadget<F>,
	PoseidonCRH_x5_5<F>,
	PoseidonCRH_x5_5Gadget<F>,
	TreeConfig_x5<F>,
	LeafCRHGadget<F>,
	PoseidonCRH_x5_3Gadget<F>,
	Leaf_x5<F>,
	LeafGadget_x5<F>,
>;

pub type Leaf_x17<F> = MixerLeaf<F, PoseidonCRH_x17_5<F>>;
pub type LeafGadget_x17<F> = MixerLeafGadget<F, PoseidonCRH_x17_5<F>, PoseidonCRH_x17_5Gadget<F>, Leaf_x17<F>>;

pub type Circuit_x17<F>= MixerCircuit<
	F,
	MixerConstraintData<F>,
	MixerConstraintDataGadget<F>,
	PoseidonCRH_x17_5<F>,
	PoseidonCRH_x17_5Gadget<F>,
	TreeConfig_x17<F>,
	LeafCRHGadget<F>,
	PoseidonCRH_x17_3Gadget<F>,
	Leaf_x17<F>,
	LeafGadget_x17<F>,
>;

pub type MiMCLeaf_220<F> = MixerLeaf<F, MiMCCRH_220<F>>;
pub type MiMCLeafGadget_220<F> = MixerLeafGadget<F, MiMCCRH_220<F>, MiMCCRH_220Gadget<F>, MiMCLeaf_220<F>>;

pub type MiMCCircuit_220<F>= MixerCircuit<
	F,
	MixerConstraintData<F>,
	MixerConstraintDataGadget<F>,
	MiMCCRH_220<F>,
	MiMCCRH_220Gadget<F>,
	MiMCTreeConfig_220<F>,
	LeafCRHGadget<F>,
	MiMCCRH_220Gadget<F>,
	MiMCLeaf_220<F>,
	MiMCLeafGadget_220<F>,
>;

pub fn setup_leaf_x5<R: Rng, F: PrimeField>(
	params: &PoseidonParameters<F>,
	rng: &mut R,
) -> (
	LeafPrivate<F>,
	<Leaf_x5<F> as LeafCreation<PoseidonCRH_x5_5<F>>>::Leaf,
	<Leaf_x5<F> as LeafCreation<PoseidonCRH_x5_5<F>>>::Nullifier,
) {
	// Secret inputs for the leaf
	let leaf_private = Leaf_x5::generate_secrets(rng).unwrap();

	// Creating the leaf
	let leaf = Leaf_x5::create_leaf(&leaf_private, &(), params).unwrap();
	let nullifier_hash = Leaf_x5::create_nullifier(&leaf_private, params).unwrap();
	(leaf_private, leaf, nullifier_hash)
}

pub fn setup_leaf_x17<R: Rng, F: PrimeField>(
	params: &PoseidonParameters<F>,
	rng: &mut R,
) -> (
	LeafPrivate<F>,
	<Leaf_x17<F> as LeafCreation<PoseidonCRH_x17_5<F>>>::Leaf,
	<Leaf_x17<F> as LeafCreation<PoseidonCRH_x17_5<F>>>::Nullifier,
) {
	// Secret inputs for the leaf
	let leaf_private = Leaf_x17::generate_secrets(rng).unwrap();

	// Creating the leaf
	let leaf = Leaf_x17::create_leaf(&leaf_private, &(), params).unwrap();
	let nullifier_hash = Leaf_x17::create_nullifier(&leaf_private, params).unwrap();
	(leaf_private, leaf, nullifier_hash)
}

pub fn setup_mimc_leaf_220<R: Rng, F: PrimeField>(
	params: &MiMCParameters<F>,
	rng: &mut R,
) -> (
	LeafPrivate<F>,
	<MiMCLeaf_220<F> as LeafCreation<MiMCCRH_220<F>>>::Leaf,
	<MiMCLeaf_220<F> as LeafCreation<MiMCCRH_220<F>>>::Nullifier,
) {
	// Secret inputs for the leaf
	let leaf_private = MiMCLeaf_220::generate_secrets(rng).unwrap();

	// Creating the leaf
	let leaf = MiMCLeaf_220::create_leaf(&leaf_private, &(), params).unwrap();
	let nullifier_hash = MiMCLeaf_220::create_nullifier(&leaf_private, params).unwrap();
	(leaf_private, leaf, nullifier_hash)
}

pub fn setup_arbitrary_data<F: PrimeField>(recipient: F, relayer: F) -> MixerConstraintDataInput<F> {
	let arbitrary_input = MixerConstraintDataInput::new(recipient, relayer);
	arbitrary_input
}

pub fn setup_circuit_x5<R: Rng, F: PrimeField>(
	leaves: &[F],
	index: u64,
	recipient: F,
	relayer: F,
	rng: &mut R,
	curve: Curve,
) -> (Circuit_x5<F>, F, F, F, Vec<F>) {
	let params3 = setup_params_x5_3::<F>(curve);
	let params5 = setup_params_x5_5::<F>(curve);

	let arbitrary_input = setup_arbitrary_data::<F>(recipient, relayer);
	let (leaf_private, leaf, nullifier_hash) = setup_leaf_x5::<R, F>(&params5, rng);
	let mut leaves_new = leaves.to_vec();
	leaves_new.push(leaf);
	let (tree, path) = setup_tree_and_create_path_x5::<F>(&leaves_new, index, &params3);
	let root = tree.root().inner();

	let mc = Circuit_x5::<F>::new(
		arbitrary_input.clone(),
		leaf_private,
		// leaf public
		(),
		params5,
		path,
		root.clone(),
		nullifier_hash,
	);
	let public_inputs = get_public_inputs(nullifier_hash, root, recipient, relayer);
	(mc, leaf, nullifier_hash, root, public_inputs)
}

pub fn setup_circuit_x17<R: Rng, F: PrimeField>(
	leaves: &[F],
	index: u64,
	recipient: F,
	relayer: F,
	rng: &mut R,
	curve: Curve,
) -> (Circuit_x17<F>, F, F, F, Vec<F>) {
	let params3 = setup_params_x17_3::<F>(curve);
	let params5 = setup_params_x17_5::<F>(curve);

	let arbitrary_input = setup_arbitrary_data::<F>(recipient, relayer);
	let (leaf_private, leaf, nullifier_hash) = setup_leaf_x17::<R, F>(&params5, rng);
	let mut leaves_new = leaves.to_vec();
	leaves_new.push(leaf);
	let (tree, path) = setup_tree_and_create_path_x17::<F>(&leaves_new, index, &params3);
	let root = tree.root().inner();

	let mc = Circuit_x17::<F>::new(
		arbitrary_input.clone(),
		leaf_private,
		// leaf public
		(),
		params5,
		path,
		root.clone(),
		nullifier_hash,
	);
	let public_inputs = get_public_inputs(nullifier_hash, root, recipient, relayer);
	(mc, leaf, nullifier_hash, root, public_inputs)
}

pub fn setup_circuit_mimc_220<R: Rng, F: PrimeField>(
	leaves: &[F],
	index: u64,
	recipient: F,
	relayer: F,
	rng: &mut R,
	curve: Curve,
) -> (MiMCCircuit_220<F>, F, F, F, Vec<F>) {
	let params = setup_mimc_220::<F>(curve);

	let arbitrary_input = setup_arbitrary_data::<F>(recipient, relayer);
	let (leaf_private, leaf, nullifier_hash) = setup_mimc_leaf_220::<R, F>(&params, rng);
	let mut leaves_new = leaves.to_vec();
	leaves_new.push(leaf);
	let (tree, path) = setup_tree_and_create_path_mimc_220::<F>(&leaves_new, index, &params);
	let root = tree.root().inner();

	let mc = MiMCCircuit_220::<F>::new(
		arbitrary_input.clone(),
		leaf_private,
		// leaf public
		(),
		params,
		path,
		root.clone(),
		nullifier_hash,
	);
	let public_inputs = get_public_inputs(nullifier_hash, root, recipient, relayer);
	(mc, leaf, nullifier_hash, root, public_inputs)
}

pub fn setup_random_circuit_x5<R: Rng, F: PrimeField>(rng: &mut R, curve: Curve) -> (Circuit_x5<F>, F, F, F, Vec<F>) {
	let leaves = Vec::new();
	let index = 0;
	let recipient = F::rand(rng);
	let relayer = F::rand(rng);
	setup_circuit_x5(&leaves, index, recipient, relayer, rng, curve)
}

pub fn setup_random_circuit_x17<R: Rng, F: PrimeField>(rng: &mut R, curve: Curve) -> (Circuit_x17<F>, F, F, F, Vec<F>) {
	let leaves = Vec::new();
	let index = 0;
	let recipient = F::rand(rng);
	let relayer = F::rand(rng);
	setup_circuit_x17(&leaves, index, recipient, relayer, rng, curve)
}

pub fn setup_random_circuit_mimc_220<R: Rng, F: PrimeField>(rng: &mut R, curve: Curve) -> (MiMCCircuit_220<F>, F, F, F, Vec<F>) {
	let leaves = Vec::new();
	let index = 0;
	let recipient = F::rand(rng);
	let relayer = F::rand(rng);
	setup_circuit_mimc_220(&leaves, index, recipient, relayer, rng, curve)
}

pub fn get_public_inputs<F: PrimeField>(
	nullifier_hash: F,
	root: F,
	recipient: F,
	relayer: F,
) -> Vec<F> {
	let mut public_inputs = Vec::new();
	public_inputs.push(nullifier_hash);
	public_inputs.push(root);
	public_inputs.push(recipient);
	public_inputs.push(relayer);
	public_inputs
}

pub fn prove_groth16_x5<R: RngCore + CryptoRng, E: PairingEngine>(
	pk: &ProvingKey<E>,
	c: Circuit_x5<E::Fr>,
	rng: &mut R,
) -> Proof<E> {
	Groth16::<E>::prove(pk, c, rng).unwrap()
}

pub fn setup_groth16_x5<R: RngCore + CryptoRng, E: PairingEngine>(
	rng: &mut R,
	c: Circuit_x5<E::Fr>,
) -> (ProvingKey<E>, VerifyingKey<E>) {
	let (pk, vk) = Groth16::<E>::circuit_specific_setup(c, rng).unwrap();
	(pk, vk)
}

pub fn prove_groth16_x17<R: RngCore + CryptoRng, E: PairingEngine>(
	pk: &ProvingKey<E>,
	c: Circuit_x17<E::Fr>,
	rng: &mut R,
) -> Proof<E> {
	Groth16::<E>::prove(pk, c, rng).unwrap()
}

pub fn setup_groth16_x17<R: RngCore + CryptoRng, E: PairingEngine>(
	rng: &mut R,
	c: Circuit_x17<E::Fr>,
) -> (ProvingKey<E>, VerifyingKey<E>) {
	let (pk, vk) = Groth16::<E>::circuit_specific_setup(c, rng).unwrap();
	(pk, vk)
}

pub fn prove_groth16_mimc220<R: RngCore + CryptoRng, E: PairingEngine>(
	pk: &ProvingKey<E>,
	c: MiMCCircuit_220<E::Fr>,
	rng: &mut R,
) -> Proof<E> {
	Groth16::<E>::prove(pk, c, rng).unwrap()
}

pub fn setup_groth16_mimc_220<R: RngCore + CryptoRng, E: PairingEngine>(
	rng: &mut R,
	c: MiMCCircuit_220<E::Fr>,
) -> (ProvingKey<E>, VerifyingKey<E>) {
	let (pk, vk) = Groth16::<E>::circuit_specific_setup(c, rng).unwrap();
	(pk, vk)
}

pub fn setup_random_groth16_x5<R: RngCore + CryptoRng, E: PairingEngine>(
	rng: &mut R,
	curve: Curve,
) -> (ProvingKey<E>, VerifyingKey<E>) {
	let (circuit, ..) = setup_random_circuit_x5::<R, E::Fr>(rng, curve);
	let (pk, vk) = Groth16::<E>::circuit_specific_setup(circuit.clone(), rng).unwrap();
	(pk, vk)
}

pub fn setup_random_groth16_x17<R: RngCore + CryptoRng, E: PairingEngine>(
	rng: &mut R,
	curve: Curve,
) -> (ProvingKey<E>, VerifyingKey<E>) {
	let (circuit, ..) = setup_random_circuit_x17::<R, E::Fr>(rng, curve);
	let (pk, vk) = Groth16::<E>::circuit_specific_setup(circuit.clone(), rng).unwrap();
	(pk, vk)
}

pub fn setup_random_groth16_mimc_220<R: RngCore + CryptoRng, E: PairingEngine>(
	rng: &mut R,
	curve: Curve,
) -> (ProvingKey<E>, VerifyingKey<E>) {
	let (circuit, ..) = setup_random_circuit_mimc_220::<R, E::Fr>(rng, curve);
	let (pk, vk) = Groth16::<E>::circuit_specific_setup(circuit.clone(), rng).unwrap();
	(pk, vk)
}

#[cfg(test)]
mod test {
	use super::*;
	use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
	use ark_std::{test_rng};
	use ark_bls12_381::{Bls12_381, Fr as Bls381};
	use ark_bn254::{Fr as Bn254Fr, Bn254};

	fn add_members_mock<F: PrimeField>(_leaves: Vec<F>) {}

	fn verify_zk_mock<F: PrimeField>(
		_root: F,
		_private_inputs: Vec<F>,
		_nullifier_hash: F,
		_proof_bytes: Vec<u8>,
		_path_index_commitments: Vec<F>,
		_path_node_commitments: Vec<F>,
		_recipient: F,
		_relayer: F,
	) {}

	#[test]
	fn should_create_setup() {
		let mut rng = test_rng();
		let curve = Curve::Bls381;
		let recipient = Bls381::from(0u8);
		let relayer = Bls381::from(0u8);
		let leaves = Vec::new();
		let (circuit, leaf, nullifier, root, public_inputs) =
			setup_circuit_x5::<_, Bls381>(&leaves, 0, recipient, relayer, &mut rng, curve);

		add_members_mock(vec![leaf]);

		// let (pk, vk) = setup_circuit_groth16(&mut rng, circuit.clone());
		let (pk, vk) = setup_random_groth16_x5::<_, Bls12_381>(&mut rng, curve);
		let proof = prove_groth16_x5::<_, Bls12_381>(&pk, circuit.clone(), &mut rng);
		let res = verify_groth16::<Bls12_381>(&vk, &public_inputs, &proof);

		verify_zk_mock(
			root,
			Vec::new(),
			nullifier,
			Vec::new(),
			Vec::new(),
			Vec::new(),
			recipient,
			relayer,
		);

		assert!(res);
	}

	#[test]
	fn should_create_longer_setup() {
		let mut rng = test_rng();
		let curve = Curve::Bls381;
		let recipient = Bls381::from(0u8);
		let relayer = Bls381::from(0u8);
		let leaves = Vec::new();

		let params3 = setup_params_x5_3::<Bls381>(curve);
		let params5 = setup_params_x5_5::<Bls381>(curve);

		let arbitrary_input = setup_arbitrary_data::<Bls381>(recipient, relayer);
		let (leaf_private, leaf, nullifier_hash) = setup_leaf_x5::<_, Bls381>(&params5, &mut rng);
		let mut leaves_new = leaves.to_vec();
		leaves_new.push(leaf);
		let (tree, path) = setup_tree_and_create_path_x5::<Bls381>(&leaves_new, 0, &params3);
		let root = tree.root().inner();

		let mc = Circuit_x5::<Bls381>::new(
			arbitrary_input.clone(),
			leaf_private,
			(),
			params5,
			path,
			root.clone(),
			nullifier_hash,
		);
		let public_inputs = get_public_inputs::<Bls381>(nullifier_hash, root, recipient, relayer);

		add_members_mock(vec![leaf]);

		// let (pk, vk) = setup_circuit_groth16(&mut rng, circuit.clone());
		let (pk, vk) = setup_random_groth16_x5::<_, Bls12_381>(&mut rng, curve);
		let proof = prove_groth16_x5::<_, Bls12_381>(&pk, mc.clone(), &mut rng);
		let res = verify_groth16::<Bls12_381>(&vk, &public_inputs, &proof);

		verify_zk_mock(
			root,
			Vec::new(),
			nullifier_hash,
			Vec::new(),
			Vec::new(),
			Vec::new(),
			recipient,
			relayer,
		);

		assert!(res);
	}

	#[test]
	fn should_handle_proof_deserialization() {
		let mut rng = test_rng();
		let curve = Curve::Bls381;
		let recipient = Bls381::from(0u8);
		let relayer = Bls381::from(0u8);
		let leaves = Vec::new();
		let (circuit, leaf, nullifier, root, public_inputs) =
			setup_circuit_x5(&leaves, 0, recipient, relayer, &mut rng, curve);

		add_members_mock(vec![leaf]);

		// let (pk, vk) = setup_circuit_groth16(&mut rng, circuit.clone());
		let (pk, vk) = setup_random_groth16_x5::<_, Bls12_381>(&mut rng, curve);
		let proof = prove_groth16_x5::<_, Bls12_381>(&pk, circuit.clone(), &mut rng);
		let mut proof_bytes = vec![0u8; proof.serialized_size()];
		proof.serialize(&mut proof_bytes[..]).unwrap();
		let proof_anew = Proof::<Bls12_381>::deserialize(&proof_bytes[..]).unwrap();
		let res = verify_groth16::<Bls12_381>(&vk, &public_inputs, &proof_anew);

		verify_zk_mock(
			root,
			Vec::new(),
			nullifier,
			Vec::new(),
			Vec::new(),
			Vec::new(),
			recipient,
			relayer,
		);

		assert!(res);
	}

	#[test]
	fn should_create_longer_setup_mimc() {
		let mut rng = test_rng();
		let curve = Curve::Bn254;
		let recipient = Bn254Fr::from(0u8);
		let relayer = Bn254Fr::from(0u8);
		let leaves = Vec::new();

		let params = setup_mimc_220::<Bn254Fr>(curve);

		let arbitrary_input = setup_arbitrary_data::<Bn254Fr>(recipient, relayer);
		let (leaf_private, leaf, nullifier_hash) = setup_mimc_leaf_220::<_, Bn254Fr>(&params, &mut rng);
		let mut leaves_new = leaves.to_vec();
		leaves_new.push(leaf);
		let (tree, path) = setup_tree_and_create_path_mimc_220::<Bn254Fr>(&leaves_new, 0, &params);
		let root = tree.root().inner();

		let mc = MiMCCircuit_220::<Bn254Fr>::new(
			arbitrary_input.clone(),
			leaf_private,
			(),
			params,
			path,
			root.clone(),
			nullifier_hash,
		);
		let public_inputs = get_public_inputs::<Bn254Fr>(nullifier_hash, root, recipient, relayer);

		add_members_mock(vec![leaf]);

		// let (pk, vk) = setup_circuit_groth16(&mut rng, circuit.clone());
		let (pk, vk) = setup_random_groth16_mimc_220::<_, Bn254>(&mut rng, curve);
		let proof = prove_groth16_mimc220::<_, Bn254>(&pk, mc.clone(), &mut rng);
		let res = verify_groth16::<Bn254>(&vk, &public_inputs, &proof);

		verify_zk_mock(
			root,
			Vec::new(),
			nullifier_hash,
			Vec::new(),
			Vec::new(),
			Vec::new(),
			recipient,
			relayer,
		);

		assert!(res);
	}	
}
