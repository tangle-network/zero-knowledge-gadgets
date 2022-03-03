use ark_crypto_primitives::{Error, CRH};
use ark_ff::{to_bytes, ToBytes};
use ark_std::{
	convert::TryInto,
	error::Error as ArkError,
	marker::PhantomData,
	rand::{CryptoRng, RngCore},
	string::ToString,
	vec::Vec,
};

use crypto_box::{
	aead::{generic_array::GenericArray, Aead, Payload},
	generate_nonce, ChaChaBox, PublicKey, SecretKey,
};

#[cfg(feature = "r1cs")]
pub mod constraints;

#[derive(Debug)]
pub enum KeypairError {
	EncryptionFailed,
	DecryptionFailed,
	SecretKeyParseFailed,
}

impl core::fmt::Display for KeypairError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		let msg = match self {
			KeypairError::EncryptionFailed => "Data encryption failed".to_string(),
			KeypairError::DecryptionFailed => "Data decryption failed".to_string(),
			KeypairError::SecretKeyParseFailed => "Failed to parse secret key".to_string(),
		};
		write!(f, "{}", msg)
	}
}

impl ArkError for KeypairError {}

pub struct EncryptedData {
	pub nonce: Vec<u8>,
	pub ephemeral_pk: Vec<u8>,
	pub cypher_text: Vec<u8>,
}

#[derive(Default, Debug, Copy)]
pub struct Keypair<B: Clone + Copy + ToBytes, H: CRH> {
	pub secret_key: B,
	_h: PhantomData<H>,
}

impl<B: Clone + Copy + ToBytes, H: CRH> Keypair<B, H> {
	pub fn new(secret_key: B) -> Self {
		Self {
			secret_key,
			_h: PhantomData,
		}
	}

	pub fn public_key(&self, h: &H::Parameters) -> Result<H::Output, Error> {
		let bytes = to_bytes![&self.secret_key]?;
		H::evaluate(h, &bytes)
	}

	// Computes the signature = hash(privKey, commitment, pathIndices)
	pub fn signature(
		&self,
		commitment: &H::Output,
		index: &B,
		h_w4: &H::Parameters,
	) -> Result<H::Output, Error> {
		let bytes = to_bytes![self.secret_key.clone(), commitment, index]?;
		H::evaluate(h_w4, &bytes)
	}

	pub fn encrypt<R: RngCore + CryptoRng>(
		&self,
		msg: &[u8],
		rng: &mut R,
	) -> Result<EncryptedData, Error> {
		// Generate new nonce
		let nonce = generate_nonce(rng);

		// Convert private key into bytes array
		let secret_key_bytes = to_bytes!(self.secret_key)?;
		let sc_bytes: [u8; 32] = secret_key_bytes
			.try_into()
			.map_err(|_| KeypairError::SecretKeyParseFailed)?;

		// Generate public key from secret key
		// QUESTION: Should we derive the public key with poseidon.hash(secret_key)?
		let secret_key = SecretKey::from(sc_bytes);
		let public_key = PublicKey::from(&secret_key);

		// Generate ephemeral sk/pk
		let ephemeral_sk = SecretKey::generate(rng);
		let ephemeral_pk = PublicKey::from(&ephemeral_sk);

		let my_box = ChaChaBox::new(&public_key, &ephemeral_sk);

		// Encrypting the message
		let ct = my_box
			.encrypt(&nonce, Payload {
				msg: &msg,
				aad: &[],
			})
			.map_err::<Error, _>(|_| KeypairError::EncryptionFailed.into())?;

		Ok(EncryptedData {
			nonce: nonce.as_slice().to_vec(),
			cypher_text: ct,
			ephemeral_pk: ephemeral_pk.as_bytes().to_vec(),
		})
	}

	pub fn decrypt(&self, encrypted_data: &EncryptedData) -> Result<Vec<u8>, Error> {
		// Creating a secret key
		let secret_key_bytes = to_bytes![self.secret_key]?;

		let sc_bytes: [u8; 32] = secret_key_bytes
			.try_into()
			.map_err(|_| KeypairError::SecretKeyParseFailed)?;
		let secret_key = SecretKey::from(sc_bytes);

		// Making ephemeral public key from the encryption data
		let eph_bytes = &encrypted_data.ephemeral_pk[..];
		let ephemeral_pk_bytes: [u8; 32] = eph_bytes
			.try_into()
			.map_err(|_| KeypairError::DecryptionFailed)?;
		let ephemeral_pk = PublicKey::from(ephemeral_pk_bytes);

		let my_box = ChaChaBox::new(&ephemeral_pk, &secret_key);

		// Converting nonce into proper type
		let nonce = GenericArray::from_slice(&encrypted_data.nonce);

		// Decrypt the cypher text, get the plaintext
		let plaintext = my_box
			.decrypt(&nonce, Payload {
				msg: &encrypted_data.cypher_text,
				aad: &[],
			})
			.map_err::<Error, _>(|_| KeypairError::DecryptionFailed.into())?;
		Ok(plaintext)
	}
}

impl<B: Clone + Copy + ToBytes, H2: CRH> Clone for Keypair<B, H2> {
	fn clone(&self) -> Self {
		let secret_key = self.secret_key.clone();
		Self::new(secret_key)
	}
}

#[cfg(test)]
mod test {
	use crate::{
		ark_std::{UniformRand, Zero},
		poseidon::CRH,
	};

	use ark_bn254::Fq;
	use ark_crypto_primitives::crh::CRH as CRHTrait;
	use ark_ff::to_bytes;
	use arkworks_utils::utils::common::{setup_params_x5_2, setup_params_x5_4, Curve};

	use ark_std::test_rng;

	use super::Keypair;

	type PoseidonCRH = CRH<Fq>;

	#[test]
	fn should_crate_new_public_key() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;

		let params = setup_params_x5_2(curve);

		let private_key = Fq::rand(rng);

		let privkey = to_bytes![private_key].unwrap();
		let pubkey = PoseidonCRH::evaluate(&params, &privkey).unwrap();

		let keypair = Keypair::<Fq, PoseidonCRH>::new(private_key.clone());
		let new_pubkey = keypair.public_key(&params).unwrap();

		assert_eq!(new_pubkey, pubkey)
	}
	#[test]
	fn should_crate_new_signature() {
		let rng = &mut test_rng();
		let index = Fq::zero();
		let private_key = Fq::rand(rng);
		let curve = Curve::Bn254;

		let params4 = setup_params_x5_4(curve);

		let commitment = Fq::rand(rng);

		let keypair = Keypair::<Fq, PoseidonCRH>::new(private_key.clone());

		// Since signature = hash(privKey, commitment, pathIndices)
		let inputs_signature = to_bytes![private_key, commitment, index].unwrap();
		let ev_res = PoseidonCRH::evaluate(&params4, &inputs_signature).unwrap();
		let signature = keypair.signature(&commitment, &index, &params4).unwrap();
		assert_eq!(ev_res, signature);
	}

	#[test]
	fn should_encrypt_decrypt() {
		let rng = &mut test_rng();
		let private_key = Fq::rand(rng);
		let keypair = Keypair::<Fq, PoseidonCRH>::new(private_key.clone());

		let msg = vec![1, 2, 3];
		let encrypted_data = keypair.encrypt(&msg, rng).unwrap();
		let plaintext = keypair.decrypt(&encrypted_data).unwrap();

		assert_eq!(plaintext, msg);
	}
}
