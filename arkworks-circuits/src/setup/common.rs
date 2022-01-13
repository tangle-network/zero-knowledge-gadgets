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
	poseidon::{constraints::CRHGadget, CRH},
};

pub type PoseidonCRH_x3_3<F> = CRH<F>;
pub type PoseidonCRH_x3_3Gadget<F> = CRHGadget<F>;

pub type PoseidonCRH_x3_5<F> = CRH<F>;
pub type PoseidonCRH_x3_5Gadget<F> = CRHGadget<F>;

pub type PoseidonCRH_x5_3<F> = CRH<F>;
pub type PoseidonCRH_x5_3Gadget<F> = CRHGadget<F>;

pub type PoseidonCRH_x5_5<F> = CRH<F>;
pub type PoseidonCRH_x5_5Gadget<F> = CRHGadget<F>;

pub type PoseidonCRH_x5_4<F> = CRH<F>;
pub type PoseidonCRH_x5_4Gadget<F> = CRHGadget<F>;

pub type PoseidonCRH_x5_2<F> = CRH<F>;
pub type PoseidonCRH_x5_2Gadget<F> = CRHGadget<F>;

pub type PoseidonCRH_x17_3<F> = CRH<F>;
pub type PoseidonCRH_x17_3Gadget<F> = CRHGadget<F>;

pub type PoseidonCRH_x17_5<F> = CRH<F>;
pub type PoseidonCRH_x17_5Gadget<F> = CRHGadget<F>;

#[derive(Default, Clone)]
pub struct MiMCRounds_220_3;

impl arkworks_gadgets::mimc::Rounds for MiMCRounds_220_3 {
	const ROUNDS: usize = 220;
	const WIDTH: usize = 3;
}

pub type MiMCCRH_220<F> = arkworks_gadgets::mimc::CRH<F, MiMCRounds_220_3>;
pub type MiMCCRH_220Gadget<F> = arkworks_gadgets::mimc::constraints::CRHGadget<F, MiMCRounds_220_3>;

pub type LeafCRH<F> = IdentityCRH<F>;
pub type LeafCRHGadget<F> = IdentityCRHGadget<F>;
pub type Tree_x5<F> = SparseMerkleTree<TreeConfig_x5<F>>;
pub type Tree_x17<F> = SparseMerkleTree<TreeConfig_x17<F>>;
pub type Tree_MiMC220<F> = SparseMerkleTree<TreeConfig_MiMC220<F>>;

#[derive(Clone, PartialEq)]
pub struct TreeConfig_x5<F: PrimeField>(PhantomData<F>);
impl<F: PrimeField> MerkleConfig for TreeConfig_x5<F> {
	type H = PoseidonCRH_x5_3<F>;
	type LeafH = LeafCRH<F>;

	const HEIGHT: u8 = 30;
}

#[derive(Clone, PartialEq)]
pub struct TreeConfig_x17<F: PrimeField>(PhantomData<F>);
impl<F: PrimeField> MerkleConfig for TreeConfig_x17<F> {
	type H = PoseidonCRH_x17_3<F>;
	type LeafH = LeafCRH<F>;

	const HEIGHT: u8 = 30;
}

#[derive(Clone, PartialEq)]
pub struct TreeConfig_MiMC220<F: PrimeField>(PhantomData<F>);
impl<F: PrimeField> MerkleConfig for TreeConfig_MiMC220<F> {
	type H = MiMCCRH_220<F>;
	type LeafH = LeafCRH<F>;

	const HEIGHT: u8 = 30;
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
