use ark_crypto_primitives::Error;
use ark_ff::{to_bytes, PrimeField};
use ark_std::{
	convert::TryInto,
	error::Error as ArkError,
	marker::PhantomData,
	rand::{CryptoRng, RngCore},
	string::ToString,
	vec::Vec,
};
use arkworks_native_gadgets::poseidon::FieldHasher;
use codec::{Decode, Encode};
use crypto_box::{
	aead::{generic_array::GenericArray, Aead, AeadCore, Payload},
	generate_nonce, ChaChaBox, PublicKey, SecretKey,
};

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

type NonceSize = <ChaChaBox as AeadCore>::NonceSize;
type Nonce = GenericArray<u8, NonceSize>;
pub struct EncryptedData {
	pub nonce: Nonce,
	pub ephemeral_pk: PublicKey,
	pub cypher_text: Vec<u8>,
}

impl Decode for EncryptedData {
	fn decode<I: codec::Input>(input: &mut I) -> Result<Self, codec::Error> {
		// Getting the size of Nonce
		const NONCE_LEN: usize = core::mem::size_of::<Nonce>();
		// Getting the size of pub key
		const PUB_KEY_LEN: usize = core::mem::size_of::<PublicKey>();
		let mut nonce_data = [0u8; NONCE_LEN];
		let mut ephemeral_pk_data = [0u8; PUB_KEY_LEN];

		// Reading the data for nonce and public key
		input.read(&mut nonce_data)?;
		input.read(&mut ephemeral_pk_data)?;

		// Getting the length of the remaining data
		let remaining_len: usize = input.remaining_len()?.unwrap_or(0usize);
		let mut cypher_text_data = vec![0u8; remaining_len];

		// Use the remaining data as cypher text
		input.read(&mut cypher_text_data)?;

		let nonce: Nonce = *GenericArray::<u8, NonceSize>::from_slice(&nonce_data);
		let ephemeral_pk: PublicKey = PublicKey::from(ephemeral_pk_data);
		let cypher_text = cypher_text_data.to_vec();

		Ok(Self {
			nonce,
			ephemeral_pk,
			cypher_text,
		})
	}
}

impl Encode for EncryptedData {
	fn encode(&self) -> Vec<u8> {
		const NONCE_LEN: usize = core::mem::size_of::<Nonce>();
		const PUB_KEY_LEN: usize = core::mem::size_of::<PublicKey>();

		// Initialize return array
		let mut ret = vec![0u8; self.encoded_size()];

		// Populate it with data
		ret[0..NONCE_LEN].copy_from_slice(&self.nonce.as_slice());
		ret[NONCE_LEN..(NONCE_LEN + PUB_KEY_LEN)].copy_from_slice(self.ephemeral_pk.as_bytes());
		ret[(NONCE_LEN + PUB_KEY_LEN)..].copy_from_slice(&self.cypher_text);

		ret
	}

	fn encoded_size(&self) -> usize {
		const NONCE_LEN: usize = core::mem::size_of::<Nonce>();
		const PUB_KEY_LEN: usize = core::mem::size_of::<PublicKey>();
		let cypher_text_len = self.cypher_text.len();
		NONCE_LEN + PUB_KEY_LEN + cypher_text_len
	}
}

#[derive(Default, Debug, Copy)]
pub struct Keypair<F: PrimeField, H: FieldHasher<F>> {
	pub secret_key: F,
	_h: PhantomData<H>,
}

impl<F: PrimeField, H: FieldHasher<F>> Keypair<F, H> {
	pub fn new(secret_key: F) -> Self {
		Self {
			secret_key,
			_h: PhantomData,
		}
	}

	pub fn public_key(&self, hasher2: &H) -> Result<F, Error> {
		let res = hasher2.hash(&[self.secret_key])?;
		Ok(res)
	}

	// Computes the signature = hash(privKey, commitment, pathIndices)
	pub fn signature(&self, commitment: &F, index: &F, hasher4: &H) -> Result<F, Error> {
		let res = hasher4.hash(&[self.secret_key.clone(), commitment.clone(), index.clone()])?;
		Ok(res)
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
			.map_err::<KeypairError, _>(|_| KeypairError::EncryptionFailed.into())?;

		Ok(EncryptedData {
			nonce,
			cypher_text: ct,
			ephemeral_pk,
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
		let my_box = ChaChaBox::new(&encrypted_data.ephemeral_pk, &secret_key);

		// Converting nonce into proper type
		let nonce = GenericArray::from_slice(&encrypted_data.nonce);

		// Decrypt the cypher text, get the plaintext
		let plaintext = my_box
			.decrypt(&nonce, Payload {
				msg: &encrypted_data.cypher_text,
				aad: &[],
			})
			.map_err::<KeypairError, _>(|_| KeypairError::DecryptionFailed.into())?;
		Ok(plaintext)
	}
}

impl<F: PrimeField, H: FieldHasher<F>> Clone for Keypair<F, H> {
	fn clone(&self) -> Self {
		let secret_key = self.secret_key.clone();
		Self::new(secret_key)
	}
}

#[cfg(test)]
mod test {
	use ark_bn254::Fq;
	use ark_std::{test_rng, UniformRand, Zero};
	use arkworks_native_gadgets::poseidon::{FieldHasher, Poseidon};
	use arkworks_utils::utils::common::{setup_params_x5_2, setup_params_x5_4, Curve};
	use codec::{Decode, Encode};

	use crate::keypair::EncryptedData;

	use super::Keypair;

	#[test]
	fn should_crate_new_public_key() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;

		let params = setup_params_x5_2(curve);
		let hasher = Poseidon::<Fq>::new(params.clone());
		let private_key = Fq::rand(rng);

		let pubkey = hasher.hash(&[private_key]).unwrap();

		let keypair = Keypair::<Fq, Poseidon<Fq>>::new(private_key.clone());
		let new_pubkey = keypair.public_key(&hasher).unwrap();

		assert_eq!(new_pubkey, pubkey)
	}
	#[test]
	fn should_crate_new_signature() {
		let rng = &mut test_rng();
		let index = Fq::zero();
		let private_key = Fq::rand(rng);
		let curve = Curve::Bn254;

		let params4 = setup_params_x5_4(curve);
		let hasher = Poseidon::<Fq>::new(params4.clone());
		let commitment = Fq::rand(rng);

		let keypair = Keypair::<Fq, Poseidon<Fq>>::new(private_key.clone());

		// Since signature = hash(privKey, commitment, pathIndices)
		let ev_res = hasher.hash(&[private_key, commitment, index]).unwrap();
		let signature = keypair.signature(&commitment, &index, &hasher).unwrap();
		assert_eq!(ev_res, signature);
	}

	#[test]
	fn should_encrypt_decrypt() {
		let rng = &mut test_rng();

		let private_key = Fq::rand(rng);
		let keypair = Keypair::<Fq, Poseidon<Fq>>::new(private_key.clone());

		let msg = vec![1, 2, 3];
		let encrypted_data = keypair.encrypt(&msg, rng).unwrap();
		let plaintext = keypair.decrypt(&encrypted_data).unwrap();

		assert_eq!(plaintext, msg);
	}

	#[test]
	fn should_encode_decode_encrypted_data() {
		let rng = &mut test_rng();

		let private_key = Fq::rand(rng);
		let keypair = Keypair::<Fq, Poseidon<Fq>>::new(private_key.clone());

		let msg = vec![1, 2, 3];
		let encrypted_data = keypair.encrypt(&msg, rng).unwrap();
		let encoded_ed = encrypted_data.encode();
		let decoded_ed = EncryptedData::decode(&mut &encoded_ed[..]).unwrap();
		let plaintext = keypair.decrypt(&decoded_ed).unwrap();

		assert_eq!(plaintext, msg);
	}
}
