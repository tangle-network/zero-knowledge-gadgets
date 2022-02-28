use ark_ec::PairingEngine;
use arkworks_gadgets::poseidon::field_hasher::{FieldHasher};
use ark_crypto_primitives::Error;
use ark_std::{
	rand::{CryptoRng, RngCore},
	vec::Vec,
};
use arkworks_circuits::setup::common::MixerProof;
use arkworks_circuits::setup::common::Leaf;
use arkworks_utils::utils::common::Curve;

#[cfg(feature="r1cs")]
pub mod r1cs;

#[cfg(feature="plonk")]
pub mod plonk;

trait MixerProver<E: PairingEngine, H: FieldHasher<E::Fr>, const HEIGHT: usize> {
    // For creating leaves where we supply the secret and the nullifier, for generating new values, pass None
    fn create_leaf_with_privates<R: RngCore + CryptoRng>(
        &self,
        curve: Curve,
        secret: Option<Vec<u8>>,
        nullifier: Option<Vec<u8>>,
        rng: &mut R,
    ) -> Result<Leaf, Error>;
    // For making proofs
    fn create_proof<R: RngCore + CryptoRng>(
        &self,
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
        rng: &mut R,
    ) -> Result<MixerProof, Error>;
}
