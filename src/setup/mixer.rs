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

pub type Leaf<F> = MixerLeaf<F, PoseidonCRH5<F>>;
pub type LeafGadget<F> = MixerLeafGadget<F, PoseidonCRH5<F>, PoseidonCRH5Gadget<F>, Leaf<F>>;

pub type Circuit<F>= MixerCircuit<
	F,
	MixerConstraintData<F>,
	MixerConstraintDataGadget<F>,
	PoseidonCRH5<F>,
	PoseidonCRH5Gadget<F>,
	TreeConfig<F>,
	LeafCRHGadget<F>,
	PoseidonCRH3Gadget<F>,
	Leaf<F>,
	LeafGadget<F>,
>;

pub fn setup_leaf<R: Rng, F: PrimeField>(
	params: &PoseidonParameters<F>,
	rng: &mut R,
) -> (
	LeafPrivate<F>,
	<Leaf<F> as LeafCreation<PoseidonCRH5<F>>>::Leaf,
	<Leaf<F> as LeafCreation<PoseidonCRH5<F>>>::Nullifier,
) {
	// Secret inputs for the leaf
	let leaf_private = Leaf::generate_secrets(rng).unwrap();

	// Creating the leaf
	let leaf = Leaf::create_leaf(&leaf_private, &(), params).unwrap();
	let nullifier_hash = Leaf::create_nullifier(&leaf_private, params).unwrap();
	(leaf_private, leaf, nullifier_hash)
}

pub fn setup_arbitrary_data<F: PrimeField>(recipient: F, relayer: F) -> MixerConstraintDataInput<F> {
	let arbitrary_input = MixerConstraintDataInput::new(recipient, relayer);
	arbitrary_input
}

pub fn setup_circuit<R: Rng, F: PrimeField>(
	leaves: &[F],
	index: u64,
	recipient: F,
	relayer: F,
	rng: &mut R,
	curve: Curve,
) -> (Circuit<F>, F, F, F, Vec<F>) {
	let params3 = setup_params_3::<F>(curve);
	let params5 = setup_params_5::<F>(curve);

	let arbitrary_input = setup_arbitrary_data::<F>(recipient, relayer);
	let (leaf_private, leaf, nullifier_hash) = setup_leaf::<R, F>(&params5, rng);
	let mut leaves_new = leaves.to_vec();
	leaves_new.push(leaf);
	let (tree, path) = setup_tree_and_create_path::<F>(&leaves_new, index, &params3);
	let root = tree.root().inner();

	let mc = Circuit::<F>::new(
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

pub fn setup_random_circuit<R: Rng, F: PrimeField>(rng: &mut R, curve: Curve) -> (Circuit<F>, F, F, F, Vec<F>) {
	let leaves = Vec::new();
	let index = 0;
	let recipient = F::rand(rng);
	let relayer = F::rand(rng);
	setup_circuit(&leaves, index, recipient, relayer, rng, curve)
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

pub fn prove_groth16<R: RngCore + CryptoRng, E: PairingEngine>(
	pk: &ProvingKey<E>,
	c: Circuit<E::Fr>,
	rng: &mut R,
) -> Proof<E> {
	Groth16::<E>::prove(pk, c, rng).unwrap()
}

pub fn setup_groth16<R: RngCore + CryptoRng, E: PairingEngine>(
	rng: &mut R,
	c: Circuit<E::Fr>,
) -> (ProvingKey<E>, VerifyingKey<E>) {
	let (pk, vk) = Groth16::<E>::circuit_specific_setup(c, rng).unwrap();
	(pk, vk)
}

pub fn setup_random_groth16<R: RngCore + CryptoRng, E: PairingEngine>(
	rng: &mut R,
	curve: Curve,
) -> (ProvingKey<E>, VerifyingKey<E>) {
	let (circuit, ..) = setup_random_circuit::<R, E::Fr>(rng, curve);
	let (pk, vk) = Groth16::<E>::circuit_specific_setup(circuit.clone(), rng).unwrap();
	(pk, vk)
}

#[cfg(test)]
mod test {
	use super::*;
	use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
	use ark_std::{test_rng};
	use ark_bls12_381::{Bls12_381, Fr as Bls381};

	fn add_members_mock(_leaves: Vec<Bls381>) {}

	fn verify_zk_mock(
		_root: Bls381,
		_private_inputs: Vec<Bls381>,
		_nullifier_hash: Bls381,
		_proof_bytes: Vec<u8>,
		_path_index_commitments: Vec<Bls381>,
		_path_node_commitments: Vec<Bls381>,
		_recipient: Bls381,
		_relayer: Bls381,
	) {}

	#[test]
	fn should_create_setup() {
		let mut rng = test_rng();
		let curve = Curve::Bls381;
		let recipient = Bls381::from(0u8);
		let relayer = Bls381::from(0u8);
		let leaves = Vec::new();
		let (circuit, leaf, nullifier, root, public_inputs) =
			setup_circuit::<_, Bls381>(&leaves, 0, recipient, relayer, &mut rng, curve);

		add_members_mock(vec![leaf]);

		// let (pk, vk) = setup_circuit_groth16(&mut rng, circuit.clone());
		let (pk, vk) = setup_random_groth16::<_, Bls12_381>(&mut rng, curve);
		let proof = prove_groth16::<_, Bls12_381>(&pk, circuit.clone(), &mut rng);
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

		let params3 = setup_params_3::<Bls381>(curve);
		let params5 = setup_params_5::<Bls381>(curve);

		let arbitrary_input = setup_arbitrary_data::<Bls381>(recipient, relayer);
		let (leaf_private, leaf, nullifier_hash) = setup_leaf::<_, Bls381>(&params5, &mut rng);
		let mut leaves_new = leaves.to_vec();
		leaves_new.push(leaf);
		let (tree, path) = setup_tree_and_create_path::<Bls381>(&leaves_new, 0, &params3);
		let root = tree.root().inner();

		let mc = Circuit::<Bls381>::new(
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
		let (pk, vk) = setup_random_groth16::<_, Bls12_381>(&mut rng, curve);
		let proof = prove_groth16::<_, Bls12_381>(&pk, mc.clone(), &mut rng);
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
			setup_circuit(&leaves, 0, recipient, relayer, &mut rng, curve);

		add_members_mock(vec![leaf]);

		// let (pk, vk) = setup_circuit_groth16(&mut rng, circuit.clone());
		let (pk, vk) = setup_random_groth16::<_, Bls12_381>(&mut rng, curve);
		let proof = prove_groth16::<_, Bls12_381>(&pk, circuit.clone(), &mut rng);
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
}
