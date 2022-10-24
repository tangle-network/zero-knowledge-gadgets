use ark_crypto_primitives::{Error, SNARK};
use ark_ec::PairingEngine;
use ark_ff::fields::PrimeField;
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
	collections::BTreeMap,
	rand::{CryptoRng, RngCore},
	vec::Vec,
};
use arkworks_native_gadgets::{
	merkle_tree::{Path, SparseMerkleTree},
	poseidon::{sbox::PoseidonSbox, FieldHasher, PoseidonParameters},
};
use arkworks_utils::{
	bytes_matrix_to_f, bytes_vec_to_f, poseidon_params::setup_poseidon_params, Curve,
};
use tiny_keccak::{Hasher, Keccak};

pub struct VAnchorLeaf {
	pub chain_id_bytes: Vec<u8>,
	pub amount: u128,
	pub public_key_bytes: Vec<u8>,
	pub blinding_bytes: Vec<u8>,
	pub index: u32,
	pub private_key_bytes: Vec<u8>,
	pub nullifier_bytes: Vec<u8>,
	pub leaf_bytes: Vec<u8>,
	pub nullifier_hash_bytes: Vec<u8>,
}

pub struct Leaf {
	pub chain_id_bytes: Option<Vec<u8>>,
	pub secret_bytes: Vec<u8>,
	pub nullifier_bytes: Vec<u8>,
	pub leaf_bytes: Vec<u8>,
	pub nullifier_hash_bytes: Vec<u8>,
}

pub struct VAnchorProof {
	pub proof: Vec<u8>,
	pub public_inputs_raw: Vec<Vec<u8>>,
}

pub struct AnchorProof {
	pub proof: Vec<u8>,
	pub leaf_raw: Vec<u8>,
	pub nullifier_hash_raw: Vec<u8>,
	pub roots_raw: Vec<Vec<u8>>,
	pub public_inputs_raw: Vec<Vec<u8>>,
}

pub struct MixerProof {
	pub proof: Vec<u8>,
	pub leaf_raw: Vec<u8>,
	pub nullifier_hash_raw: Vec<u8>,
	pub root_raw: Vec<u8>,
	pub public_inputs_raw: Vec<Vec<u8>>,
}

pub struct Keys {
	pub pk: Vec<u8>,
	pub vk: Vec<u8>,
}

pub fn setup_keys<E: PairingEngine, R: RngCore + CryptoRng, C: ConstraintSynthesizer<E::Fr>>(
	circuit: C,
	rng: &mut R,
) -> Result<(Vec<u8>, Vec<u8>), Error> {
	let (pk, vk) = Groth16::<E>::circuit_specific_setup(circuit, rng)?;

	let mut pk_bytes = Vec::new();
	let mut vk_bytes = Vec::new();
	pk.serialize(&mut pk_bytes)?;
	vk.serialize(&mut vk_bytes)?;
	Ok((pk_bytes, vk_bytes))
}

pub fn setup_keys_unchecked<
	E: PairingEngine,
	R: RngCore + CryptoRng,
	C: ConstraintSynthesizer<E::Fr>,
>(
	circuit: C,
	rng: &mut R,
) -> Result<(Vec<u8>, Vec<u8>), Error> {
	let (pk, vk) = Groth16::<E>::circuit_specific_setup(circuit, rng)?;

	let mut pk_bytes = Vec::new();
	let mut vk_bytes = Vec::new();
	pk.serialize_unchecked(&mut pk_bytes)?;
	vk.serialize_unchecked(&mut vk_bytes)?;
	Ok((pk_bytes, vk_bytes))
}

pub fn prove<E: PairingEngine, R: RngCore + CryptoRng, C: ConstraintSynthesizer<E::Fr>>(
	circuit: C,
	pk_bytes: &[u8],
	rng: &mut R,
) -> Result<Vec<u8>, Error> {
	let pk = ProvingKey::<E>::deserialize(pk_bytes)?;

	let proof = Groth16::prove(&pk, circuit, rng)?;
	let mut proof_bytes = Vec::new();
	proof.serialize(&mut proof_bytes)?;
	Ok(proof_bytes)
}

pub fn prove_unchecked<
	E: PairingEngine,
	R: RngCore + CryptoRng,
	C: ConstraintSynthesizer<E::Fr>,
>(
	circuit: C,
	pk_unchecked_bytes: &[u8],
	rng: &mut R,
) -> Result<Vec<u8>, Error> {
	let pk = ProvingKey::<E>::deserialize_unchecked(pk_unchecked_bytes)?;

	let proof = Groth16::prove(&pk, circuit, rng)?;
	let mut proof_bytes = Vec::new();
	proof.serialize(&mut proof_bytes)?;
	Ok(proof_bytes)
}

pub fn verify<E: PairingEngine>(
	public_inputs: &[E::Fr],
	vk_bytes: &[u8],
	proof: &[u8],
) -> Result<bool, Error> {
	let vk = VerifyingKey::<E>::deserialize(vk_bytes)?;
	let proof = Proof::<E>::deserialize(proof)?;
	verify_groth16(&vk, public_inputs, &proof)
}

pub fn verify_unchecked<E: PairingEngine>(
	public_inputs: &[E::Fr],
	vk_unchecked_bytes: &[u8],
	proof: &[u8],
) -> Result<bool, Error> {
	let vk = VerifyingKey::<E>::deserialize_unchecked(vk_unchecked_bytes)?;
	let proof = Proof::<E>::deserialize(proof)?;
	verify_groth16(&vk, public_inputs, &proof)
}

pub fn verify_unchecked_raw<E: PairingEngine>(
	public_inputs: &[Vec<u8>],
	vk_unchecked_bytes: &[u8],
	proof: &[u8],
) -> Result<bool, Error> {
	let pub_ins: Vec<E::Fr> = public_inputs
		.iter()
		.map(|x| E::Fr::from_be_bytes_mod_order(x))
		.collect();
	let vk = VerifyingKey::<E>::deserialize_unchecked(vk_unchecked_bytes)?;
	let proof = Proof::<E>::deserialize(proof)?;
	verify_groth16(&vk, &pub_ins, &proof)
}

pub fn verify_groth16<E: PairingEngine>(
	vk: &VerifyingKey<E>,
	public_inputs: &[E::Fr],
	proof: &Proof<E>,
) -> Result<bool, Error> {
	let res = Groth16::<E>::verify(vk, public_inputs, proof)?;
	Ok(res)
}

pub fn keccak_256(input: &[u8]) -> Vec<u8> {
	let mut keccak = Keccak::v256();
	keccak.update(input);

	let mut output = [0u8; 32];
	keccak.finalize(&mut output);
	output.to_vec()
}

pub type SMT<F, H, const HEIGHT: usize> = SparseMerkleTree<F, H, HEIGHT>;

pub fn create_merkle_tree<F: PrimeField, H: FieldHasher<F>, const N: usize>(
	hasher: &H,
	leaves: &[F],
	default_leaf: &[u8],
) -> SparseMerkleTree<F, H, N> {
	let pairs: BTreeMap<u32, F> = leaves
		.iter()
		.enumerate()
		.map(|(i, l)| (i as u32, *l))
		.collect();
	let smt = SparseMerkleTree::<F, H, N>::new(&pairs, hasher, default_leaf).unwrap();

	smt
}

pub fn setup_tree_and_create_path<F: PrimeField, H: FieldHasher<F>, const HEIGHT: usize>(
	hasher: &H,
	leaves: &[F],
	index: u64,
	default_leaf: &[u8],
) -> Result<(SMT<F, H, HEIGHT>, Path<F, H, HEIGHT>), Error> {
	// Making the merkle tree
	let smt = create_merkle_tree::<F, H, HEIGHT>(hasher, leaves, default_leaf);
	// Getting the proof path
	let path = smt.generate_membership_proof(index);
	Ok((smt, path))
}

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
