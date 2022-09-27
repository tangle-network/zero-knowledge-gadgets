use ark_crypto_primitives::Error;
use ark_ff::PrimeField;
use ark_std::{error::Error as ArkError, marker::PhantomData, string::ToString};
use arkworks_native_gadgets::poseidon::FieldHasher;

#[derive(Debug)]
pub enum KeypairError {
	EncryptionFailed,
	DecryptionFailed,
	SecretKeyParseFailed,
	DecodeFailed,
	EncodeFailed,
}

impl core::fmt::Display for KeypairError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		let msg = match self {
			KeypairError::EncryptionFailed => "Data encryption failed".to_string(),
			KeypairError::DecryptionFailed => "Data decryption failed".to_string(),
			KeypairError::SecretKeyParseFailed => "Failed to parse secret key".to_string(),
			KeypairError::DecodeFailed => "Failed to decode encrypted data".to_string(),
			KeypairError::EncodeFailed => "Failed to encode encrypted data".to_string(),
		};
		write!(f, "{}", msg)
	}
}

impl ArkError for KeypairError {}

#[derive(Default, Debug, Copy)]
pub struct Keypair<F: PrimeField, H: FieldHasher<F>> {
	pub secret_key: Option<F>,
	pub public_key: F,
	_h: PhantomData<H>,
}

impl<F: PrimeField, H: FieldHasher<F>> Keypair<F, H> {
	pub fn new(secret_key: F, hasher: &H) -> Self {
		let pubkey = hasher.hash(&[secret_key]).unwrap();

		Self {
			public_key: pubkey,
			secret_key: Some(secret_key),
			_h: PhantomData,
		}
	}

	pub fn new_from_keys(public_key: F, secret_key: Option<F>) -> Self {
		Self {
			public_key,
			secret_key,
			_h: PhantomData,
		}
	}

	pub fn new_from_public_key(public_key: F) -> Self {
		Self {
			public_key,
			secret_key: None,
			_h: PhantomData,
		}
	}

	// Computes the signature = hash(secret_key, commitment, pathIndices)
	// If the secret_key is not configured on this Keypair, return an error
	pub fn signature(&self, commitment: &F, index: &F, hasher4: &H) -> Result<F, Error> {
		let res = hasher4.hash(&[self.secret_key.unwrap(), commitment.clone(), index.clone()])?;
		Ok(res)
	}
}

impl<F: PrimeField, H: FieldHasher<F>> Clone for Keypair<F, H> {
	fn clone(&self) -> Self {
		match self.secret_key {
			Some(secret) => Self::new_from_keys(self.public_key.clone(), Some(secret)),
			None => Self::new_from_public_key(self.public_key.clone()),
		}
	}
}

#[cfg(test)]
mod test {
	use crate::common::setup_params;
	use ark_bn254::Fq;
	use ark_std::{test_rng, UniformRand, Zero};
	use arkworks_native_gadgets::poseidon::{FieldHasher, Poseidon};
	use arkworks_utils::Curve;

	use super::Keypair;

	#[test]
	fn should_create_new_public_key() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;

		let params = setup_params(curve, 5, 2);
		let hasher = Poseidon::<Fq>::new(params.clone());
		let private_key = Fq::rand(rng);

		let pubkey = hasher.hash(&[private_key]).unwrap();

		let keypair = Keypair::<Fq, Poseidon<Fq>>::new(private_key.clone(), &hasher);
		let new_pubkey = keypair.public_key;

		assert_eq!(new_pubkey, pubkey)
	}
	#[test]
	fn should_create_new_signature() {
		let rng = &mut test_rng();
		let index = Fq::zero();
		let private_key = Fq::rand(rng);
		let curve = Curve::Bn254;
		// create the hasher which is used for deriving the public key from the private
		// key
		let params2 = setup_params(curve, 5, 2);
		let hasher2 = Poseidon::<Fq>::new(params2.clone());

		// create the hasher which is used for generating a signature.
		let params4 = setup_params(curve, 5, 4);
		let hasher4 = Poseidon::<Fq>::new(params4.clone());
		let commitment = Fq::rand(rng);

		let keypair = Keypair::<Fq, Poseidon<Fq>>::new(private_key.clone(), &hasher2);

		// Since signature = hash(privKey, commitment, pathIndices)
		let ev_res = hasher4.hash(&[private_key, commitment, index]).unwrap();
		let signature = keypair.signature(&commitment, &index, &hasher4).unwrap();
		assert_eq!(ev_res, signature);
	}
}
