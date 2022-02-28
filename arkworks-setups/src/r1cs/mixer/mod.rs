use ark_ec::PairingEngine;
use ark_ff::{PrimeField, BigInteger};
use arkworks_gadgets::poseidon::field_hasher::{Poseidon, FieldHasher};
use ark_bn254::{Fr as Bn254Fr, Bn254};
use ark_std::UniformRand;
use ark_crypto_primitives::Error;
use ark_std::{
	rand::{CryptoRng, RngCore},
	vec::Vec,
};
use arkworks_circuits::setup::common::MixerProof;
use arkworks_circuits::setup::common::Leaf;
use arkworks_utils::utils::common::Curve;

use arkworks_gadgets::{
	arbitrary::mixer_data::Input as MixerDataInput,
	leaf::mixer::Private,
	merkle_tree::Path,
};

use crate::MixerProver;

pub fn create_leaf<F: PrimeField, H: FieldHasher<F>>(hasher: &H, private: &Private<F>) -> Result<F, Error> {
    let leaf = hasher.hash_two(&private.secret(), &private.nullifier())?;
    Ok(leaf)
}

pub fn create_nullifier<F: PrimeField, H: FieldHasher<F>>(hasher: &H, private: &Private<F>) -> Result<F, Error> {
    let nullifier_hash = hasher.hash_two(&private.nullifier(), &private.nullifier())?;
    Ok(nullifier_hash)
}

#[derive(Clone)]
struct MixerR1CSProver<E: PairingEngine, H: FieldHasher<E::Fr>, const HEIGHT: usize> {
    engine: E,
    hasher: H,
}

impl<E: PairingEngine, H: FieldHasher<E::Fr>, const HEIGHT: usize> MixerProver<E, H, HEIGHT> for MixerR1CSProver<E, H, HEIGHT> {
    fn create_leaf_with_privates<R: RngCore + CryptoRng>(
        &self,
        curve: Curve,
        secret: Option<Vec<u8>>,
        nullifier: Option<Vec<u8>>,
        rng: &mut R,
    ) -> Result<Leaf, Error> {
        let secret_field_elt: E::Fr = match secret {
            Some(secret) => E::Fr::from_le_bytes_mod_order(&secret),
            None => E::Fr::rand(rng),
        };
        let nullifier_field_elt: E::Fr = match nullifier {
            Some(nullifier) => E::Fr::from_le_bytes_mod_order(&nullifier),
            None => E::Fr::rand(rng),
        };

        let private: Private<E::Fr> = Private::new(secret_field_elt, nullifier_field_elt);
        let leaf_field_element = create_leaf(&self.hasher, &private)?;
        let nullifier_hash_field_element = create_nullifier(&self.hasher, &private)?;
        Ok(Leaf {
            secret_bytes: secret_field_elt.into_repr().to_bytes_le(),
            nullifier_bytes: nullifier_field_elt.into_repr().to_bytes_le(),
            leaf_bytes: leaf_field_element.into_repr().to_bytes_le(),
            nullifier_hash_bytes: nullifier_hash_field_element.into_repr().to_bytes_le(),
        })
    }

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
    ) -> Result<MixerProof, Error> {
        todo!()
    }
}

type MixerR1CSProver_Bn254_Poseidon_30 = MixerR1CSProver<Bn254, Poseidon<Bn254Fr>, 30>;
