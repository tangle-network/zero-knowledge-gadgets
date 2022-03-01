use ark_crypto_primitives::Error;
use ark_ec::PairingEngine;
use ark_std::{
	rand::{CryptoRng, RngCore},
	vec::Vec,
};
use arkworks_gadgets::poseidon::field_hasher_constraints::FieldHasherGadget;
use arkworks_utils::utils::common::Curve;
use common::{AnchorLeaf, AnchorProof, MixerLeaf, MixerProof, VAnchorLeaf};
use r1cs::vanchor::utxo::Utxo;

pub mod common;

#[cfg(feature = "r1cs")]
pub mod r1cs;

#[cfg(feature = "plonk")]
pub mod plonk;

trait MixerProver<E: PairingEngine, const HEIGHT: usize> {
	// For creating leaves where we supply the secret and the nullifier, for
	// generating new values, pass None
	fn create_leaf_with_privates<R: RngCore + CryptoRng>(
		curve: Curve,
		secret: Option<Vec<u8>>,
		nullifier: Option<Vec<u8>>,
		rng: &mut R,
	) -> Result<MixerLeaf, Error>;
	// For making proofs
	fn create_proof<R: RngCore + CryptoRng>(
		curve: Curve,
		secret: Vec<u8>,
		nullifier: Vec<u8>,
		leaves: Vec<Vec<u8>>,
		index: u64,
		recipient: Vec<u8>,
		relayer: Vec<u8>,
		fee: u128,
		refund: u128,
		pk: Vec<u8>,
		default_leaf: [u8; 32],
		rng: &mut R,
	) -> Result<MixerProof, Error>;
}

trait AnchorProver<E: PairingEngine, const HEIGHT: usize, const ANCHOR_CT: usize> {
	// For creating leaves where we supply the chain_id, secret and the nullifier,
	// for generating new values, pass None
	fn create_leaf_with_privates<R: RngCore + CryptoRng>(
		curve: Curve,
		chain_id: u64,
		secret: Option<Vec<u8>>,
		nullifier: Option<Vec<u8>>,
		rng: &mut R,
	) -> Result<AnchorLeaf, Error>;
	// For making proofs
	fn create_proof<R: RngCore + CryptoRng>(
		curve: Curve,
		chain_id: u64,
		secret: Vec<u8>,
		nullifier: Vec<u8>,
		leaves: Vec<Vec<u8>>,
		index: u64,
		root_set: [Vec<u8>; ANCHOR_CT],
		recipient: Vec<u8>,
		relayer: Vec<u8>,
		fee: u128,
		refund: u128,
		commitment: Vec<u8>,
		pk: Vec<u8>,
		default_leaf: [u8; 32],
		rng: &mut R,
	) -> Result<AnchorProof, Error>;
}

trait VAnchorProver<E: PairingEngine, const HEIGHT: usize, const ANCHOR_CT: usize> {
	fn create_leaf_with_privates<R: RngCore + CryptoRng>(
		curve: Curve,
		chain_id: u64,
		amount: u128,
		private_key: Option<Vec<u8>>,
		blinding: Option<Vec<u8>>,
		rng: &mut R,
	) -> Result<Utxo<E::Fr>, Error> {
		Self::create_utxo(curve, chain_id, amount, index, secret_key, blinding, rng)
	}
	// For creating fresh utxo, or create a new one by passing values for secret key
	// and blinding
	pub fn create_utxo<R: RngCore>(
		curve: Curve,
		chain_id: u128,
		amount: u128,
		index: Option<u64>,
		secret_key: Option<Vec<u8>>,
		blinding: Option<Vec<u8>>,
		rng: &mut R,
	) -> Result<Utxo<E::Fr>, Error>;

	// For making proofs
	fn create_proof<R: RngCore + CryptoRng>(
		curve: Curve,
		chain_id: u64,
		secret: Vec<u8>,
		nullifier: Vec<u8>,
		leaves: Vec<Vec<u8>>,
		index: u64,
		root_set: [Vec<u8>; ANCHOR_CT],
		recipient: Vec<u8>,
		relayer: Vec<u8>,
		fee: u128,
		refund: u128,
		commitment: Vec<u8>,
		pk: Vec<u8>,
		default_leaf: [u8; 32],
		rng: &mut R,
	) -> Result<AnchorProof, Error>;
}
