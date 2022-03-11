use ark_std::collections::BTreeMap;

use ark_crypto_primitives::Error;
use ark_ec::PairingEngine;
use ark_std::{
	rand::{CryptoRng, RngCore},
	vec::Vec,
};

pub use arkworks_utils::Curve;
use common::{AnchorProof, Leaf, MixerProof, VAnchorProof};
use utxo::Utxo;

#[cfg(feature = "aead")]
pub mod aead;

pub mod common;
pub mod keypair;
pub mod utxo;

#[cfg(feature = "r1cs")]
pub mod r1cs;

#[cfg(feature = "plonk")]
pub mod plonk;

pub trait MixerProver<E: PairingEngine, const HEIGHT: usize> {
	// For creating leaves where we supply the secret and the nullifier, for
	// generating new values, pass None
	fn create_leaf_with_privates(
		curve: Curve,
		secret: Vec<u8>,
		nullifier: Vec<u8>,
	) -> Result<Leaf, Error>;
	/// Create random leaf
	fn create_random_leaf<R: RngCore + CryptoRng>(curve: Curve, rng: &mut R)
		-> Result<Leaf, Error>;
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

pub trait AnchorProver<E: PairingEngine, const HEIGHT: usize, const ANCHOR_CT: usize> {
	// For creating leaves where we supply the chain_id, secret and the nullifier,
	// for generating new values, pass None
	fn create_leaf_with_privates(
		curve: Curve,
		chain_id: u64,
		secret: Vec<u8>,
		nullifier: Vec<u8>,
	) -> Result<Leaf, Error>;
	/// Create random leaf
	fn create_random_leaf<R: RngCore + CryptoRng>(
		curve: Curve,
		chain_id: u64,
		rng: &mut R,
	) -> Result<Leaf, Error>;
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

trait VAnchorProver<
	E: PairingEngine,
	const HEIGHT: usize,
	const ANCHOR_CT: usize,
	const INS: usize,
	const OUTS: usize,
>
{
	fn create_leaf_with_privates(
		curve: Curve,
		chain_id: u64,
		amount: u128,
		index: Option<u64>,
		private_key: Vec<u8>,
		blinding: Vec<u8>,
	) -> Result<Utxo<E::Fr>, Error> {
		Self::create_utxo(curve, chain_id, amount, index, private_key, blinding)
	}
	/// Create random leaf
	fn create_random_leaf<R: RngCore + CryptoRng>(
		curve: Curve,
		chain_id: u64,
		amount: u128,
		index: Option<u64>,
		rng: &mut R,
	) -> Result<Utxo<E::Fr>, Error> {
		Self::create_random_utxo(curve, chain_id, amount, index, rng)
	}
	/// For creating UTXO from all the secrets already generated
	fn create_utxo(
		curve: Curve,
		chain_id: u64,
		amount: u128,
		index: Option<u64>,
		private_key: Vec<u8>,
		blinding: Vec<u8>,
	) -> Result<Utxo<E::Fr>, Error>;
	/// For creating UTXO from all the secrets already generated
	fn create_random_utxo<R: RngCore + CryptoRng>(
		curve: Curve,
		chain_id: u64,
		amount: u128,
		index: Option<u64>,
		rng: &mut R,
	) -> Result<Utxo<E::Fr>, Error>;
	/// For making proofs
	fn create_proof<R: RngCore + CryptoRng>(
		curve: Curve,
		chain_id: u64,
		// External data
		public_amount: u128,
		ext_data_hash: Vec<u8>,
		in_root_set: [Vec<u8>; ANCHOR_CT],
		in_indices: [u64; INS],
		in_leaves: BTreeMap<u64, Vec<Vec<u8>>>,
		// Input transactions
		in_utxos: [Utxo<E::Fr>; INS],
		// Output transactions
		out_utxos: [Utxo<E::Fr>; OUTS],
		pk: Vec<u8>,
		default_leaf: [u8; 32],
		rng: &mut R,
	) -> Result<VAnchorProof, Error>;
}
