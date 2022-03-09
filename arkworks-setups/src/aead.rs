use crate::{
	keypair::{Keypair, KeypairError},
	utxo::{Utxo, UtxoError},
};
use ark_crypto_primitives::Error;
use ark_ff::{to_bytes, PrimeField};
use ark_std::{
	convert::TryInto,
	rand::{CryptoRng, RngCore},
	vec::Vec,
};
use arkworks_native_gadgets::poseidon::FieldHasher;
use codec::{Decode, Encode};
use crypto_box::{
	aead::{generic_array::GenericArray, Aead, AeadCore, Payload},
	generate_nonce, PublicKey, SalsaBox, SecretKey,
};

type NonceSize = <SalsaBox as AeadCore>::NonceSize;
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

impl<F: PrimeField, H: FieldHasher<F>> Keypair<F, H> {
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

		let my_box = SalsaBox::new(&public_key, &ephemeral_sk);

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
		let my_box = SalsaBox::new(&encrypted_data.ephemeral_pk, &secret_key);

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

impl<F: PrimeField> Utxo<F> {
	pub fn encrypt<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Result<Vec<u8>, Error> {
		// We are encrypting the amount and the blinding
		let msg = to_bytes![self.chain_id, self.amount, self.blinding]?;
		// Encrypting the message
		let enc_data = self.keypair.encrypt(&msg, rng)?;

		Ok(enc_data.encode())
	}

	pub fn decrypt(&self, data: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), Error> {
		let decoded_ed = EncryptedData::decode(&mut &data[..])
			.map_err(|_| UtxoError::EncryptedDataDecodeError)?;
		// Decrypting the message
		let plaintext = self.keypair.decrypt(&decoded_ed)?;

		// First 32 bytes is chain id
		let chain_id = plaintext[..32].to_vec();
		// Second 32 bytes is amount
		let amount = plaintext[32..64].to_vec();
		// Third 32 bytes is blinding
		let blinding = plaintext[64..96].to_vec();

		Ok((chain_id, amount, blinding))
	}
}

#[cfg(test)]
mod test {
	use crate::common::setup_params;
	use ark_bn254::Fr;
	use ark_ff::{BigInteger, PrimeField};
	use ark_std::{test_rng, UniformRand};
	use arkworks_native_gadgets::poseidon::Poseidon;
	use arkworks_utils::Curve;
	use codec::{Decode, Encode};

	use super::EncryptedData;
	use crate::{keypair::Keypair, utxo::Utxo};

	#[test]
	fn should_encrypt_decrypt() {
		let rng = &mut test_rng();

		let private_key = Fr::rand(rng);
		let keypair = Keypair::<Fr, Poseidon<Fr>>::new(private_key.clone());

		let msg = vec![1, 2, 3];
		let encrypted_data = keypair.encrypt(&msg, rng).unwrap();
		let plaintext = keypair.decrypt(&encrypted_data).unwrap();

		assert_eq!(plaintext, msg);
	}

	#[test]
	fn should_encode_decode_encrypted_data() {
		let rng = &mut test_rng();

		let private_key = Fr::rand(rng);
		let keypair = Keypair::<Fr, Poseidon<Fr>>::new(private_key.clone());

		let msg = vec![1, 2, 3];
		let encrypted_data = keypair.encrypt(&msg, rng).unwrap();
		let encoded_ed = encrypted_data.encode();
		let decoded_ed = EncryptedData::decode(&mut &encoded_ed[..]).unwrap();
		let plaintext = keypair.decrypt(&decoded_ed).unwrap();

		assert_eq!(plaintext, msg);
	}

	#[test]
	fn test_utxo_encrypt() {
		let curve = Curve::Bn254;
		let params2 = setup_params::<Fr>(curve, 5, 2);
		let params4 = setup_params::<Fr>(curve, 5, 4);
		let params5 = setup_params::<Fr>(curve, 5, 5);
		let poseidon2 = Poseidon::new(params2);
		let poseidon4 = Poseidon::new(params4);
		let poseidon5 = Poseidon::new(params5);

		let rng = &mut test_rng();

		let chain_id_raw = 0u64;
		let chain_id = Fr::from(chain_id_raw);
		let amount = Fr::rand(rng);
		let blinding = Fr::rand(rng);
		// let utxo
		let utxo = Utxo::new(
			chain_id_raw,
			amount,
			None,
			None,
			Some(blinding),
			&poseidon2,
			&poseidon4,
			&poseidon5,
			rng,
		)
		.unwrap();

		let encrypted_data = utxo.encrypt(rng).unwrap();
		let (chain_id_bytes, amount_bytes, blinding_bytes) = utxo.decrypt(&encrypted_data).unwrap();

		assert_eq!(chain_id_bytes, chain_id.into_repr().to_bytes_le());
		assert_eq!(amount_bytes, amount.into_repr().to_bytes_le());
		assert_eq!(blinding_bytes, blinding.into_repr().to_bytes_le());
	}
}
