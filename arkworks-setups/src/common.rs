use ark_crypto_primitives::{Error, SNARK};
use ark_ec::PairingEngine;
use ark_ff::fields::PrimeField;
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
	marker::PhantomData,
	rand::{CryptoRng, RngCore},
	vec::Vec,
};
use arkworks_gadgets::{
	identity::{constraints::CRHGadget as IdentityCRHGadget, CRH as IdentityCRH},
	merkle_tree::{Config as MerkleConfig, SparseMerkleTree},
	poseidon::{constraints::CRHGadget, field_hasher_constraints::FieldHasherGadget, CRH},
};

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

pub struct AnchorLeaf {
	pub chain_id_bytes: Vec<u8>,
	pub secret_bytes: Vec<u8>,
	pub nullifier_bytes: Vec<u8>,
	pub leaf_bytes: Vec<u8>,
	pub nullifier_hash_bytes: Vec<u8>,
}

pub struct MixerLeaf {
	pub secret_bytes: Vec<u8>,
	pub nullifier_bytes: Vec<u8>,
	pub leaf_bytes: Vec<u8>,
	pub nullifier_hash_bytes: Vec<u8>,
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
	verify_groth16(&vk, &public_inputs, &proof)
}

pub fn verify_unchecked<E: PairingEngine>(
	public_inputs: &[E::Fr],
	vk_unchecked_bytes: &[u8],
	proof: &[u8],
) -> Result<bool, Error> {
	let vk = VerifyingKey::<E>::deserialize_unchecked(vk_unchecked_bytes)?;
	let proof = Proof::<E>::deserialize(proof)?;
	verify_groth16(&vk, &public_inputs, &proof)
}

pub fn verify_unchecked_raw<E: PairingEngine>(
	public_inputs: &[Vec<u8>],
	vk_unchecked_bytes: &[u8],
	proof: &[u8],
) -> Result<bool, Error> {
	let pub_ins: Vec<E::Fr> = public_inputs
		.iter()
		.map(|x| E::Fr::from_le_bytes_mod_order(&x))
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
