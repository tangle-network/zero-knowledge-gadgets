use ark_crypto_primitives::Error;
use ark_ec::PairingEngine;
use ark_std::{
	rand::{CryptoRng, RngCore},
	vec::Vec,
};
use arkworks_gadgets::poseidon::field_hasher_constraints::FieldHasherGadget;
use arkworks_utils::utils::common::Curve;
use common::{Leaf, MixerProof};

pub mod common;

#[cfg(feature = "r1cs")]
pub mod r1cs;

#[cfg(feature = "plonk")]
pub mod plonk;

trait MixerProver<E: PairingEngine, HG: FieldHasherGadget<E::Fr>, const HEIGHT: usize> {
	// For creating leaves where we supply the secret and the nullifier, for
	// generating new values, pass None
	fn create_leaf_with_privates<R: RngCore + CryptoRng>(
		&self,
		secret: Option<Vec<u8>>,
		nullifier: Option<Vec<u8>>,
		rng: &mut R,
	) -> Result<Leaf, Error>;
	// For making proofs
	fn create_proof<R: RngCore + CryptoRng>(
		&self,
		secret: Vec<u8>,
		nullifier: Vec<u8>,
		leaves: Vec<Vec<u8>>,
		index: u64,
		recipient: Vec<u8>,
		relayer: Vec<u8>,
		fee: u128,
		refund: u128,
		pk: Vec<u8>,
		rng: &mut R,
	) -> Result<MixerProof, Error>;
}
