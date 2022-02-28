use crate::setup::common::{PoseidonCRH_x5_2, PoseidonCRH_x5_4};
use ark_crypto_primitives::Error;
use ark_ff::{to_bytes, PrimeField};
use ark_std::{
	convert::TryInto,
	error::Error as ArkError,
	rand::{CryptoRng, RngCore},
	string::ToString,
	vec::Vec,
};
use arkworks_gadgets::{
	keypair::vanchor::Keypair,
	leaf::vanchor::{Private as LeafPrivateInput, Public as LeafPublicInput, VAnchorLeaf as Leaf},
};
use arkworks_utils::poseidon::PoseidonParameters;
use crypto_box::{
	aead::{generic_array::GenericArray, Aead, Payload},
	generate_nonce, ChaChaBox, PublicKey, SecretKey,
};

#[derive(Debug)]
pub enum UtxoError {
	NullifierNotCalculated,
	EncryptionFailed,
	DecryptionFailed,
}

impl core::fmt::Display for UtxoError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		let msg = match self {
			UtxoError::NullifierNotCalculated => "Nullifier not calculated".to_string(),
			UtxoError::EncryptionFailed => "Utxo encryption failed".to_string(),
			UtxoError::DecryptionFailed => "Utxo data decryption failed".to_string(),
		};
		write!(f, "{}", msg)
	}
}

impl ArkError for UtxoError {}

pub struct EncryptedUtxo {
	pub nonce: Vec<u8>,
	pub cypher_text: Vec<u8>,
	pub ephemeral_pk: Vec<u8>,
}

#[derive(Clone, Copy)]
pub struct Utxo<F: PrimeField> {
	pub chain_id: F,
	pub amount: F,
	pub keypair: Keypair<F, PoseidonCRH_x5_2<F>>,
	pub leaf_private: LeafPrivateInput<F>,
	pub leaf_public: LeafPublicInput<F>,
	pub index: Option<F>,
	pub nullifier: Option<F>,
	pub commitment: F,
}

impl<F: PrimeField> Utxo<F> {
	pub fn new<R: RngCore>(
		chain_id: F,
		amount: F,
		index: Option<F>,
		private_key: Option<F>,
		blinding: Option<F>,
		params2: &PoseidonParameters<F>,
		params4: &PoseidonParameters<F>,
		params5: &PoseidonParameters<F>,
		rng: &mut R,
	) -> Result<Self, Error> {
		let blinding = blinding.unwrap_or(F::rand(rng));
		let private_input = LeafPrivateInput::<F>::new(amount, blinding);
		let public_input = LeafPublicInput::<F>::new(chain_id);

		let keypair = Keypair::new(private_key.unwrap_or(F::rand(rng)));
		let pub_key = keypair.public_key(params2)?;

		let leaf = Leaf::<F, PoseidonCRH_x5_4<F>>::create_leaf(
			&private_input,
			&public_input,
			&pub_key,
			&params5,
		)?;

		let nullifier = if index.is_some() {
			let i = index.unwrap();

			let signature = keypair.signature(&leaf, &i, params4)?;

			let nullifier =
				Leaf::<_, PoseidonCRH_x5_4<F>>::create_nullifier(&signature, &leaf, &params4, &i)?;

			Some(nullifier)
		} else {
			None
		};

		Ok(Self {
			chain_id,
			amount,
			keypair,
			leaf_private: private_input,
			leaf_public: public_input,
			index,
			nullifier,
			commitment: leaf,
		})
	}

	pub fn get_nullifier(&self) -> Result<F, Error> {
		self.nullifier
			.ok_or(UtxoError::NullifierNotCalculated.into())
	}

	pub fn set_index(&mut self, i: F, params4: &PoseidonParameters<F>) -> Result<(), Error> {
		let signature = self.keypair.signature(&self.commitment, &i, params4)?;

		let nullifier = Leaf::<_, PoseidonCRH_x5_4<F>>::create_nullifier(
			&signature,
			&self.commitment,
			&params4,
			&i,
		)?;

		self.nullifier = Some(nullifier);

		Ok(())
	}

	pub fn encrypt<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Result<EncryptedUtxo, Error> {
		// Generate new nonce
		let nonce = generate_nonce(rng);

		// Convert private key into bytes array
		let private_key_bytes = to_bytes!(self.keypair.secret_key)?;
		let mut sc_bytes = [0u8; 32];
		for i in 0..sc_bytes.len() {
			sc_bytes[i] = private_key_bytes[i];
		}

		// Generate public key from secret key
		// QUESTION: Should we derive the public key with poseidon.hash(secret_key)?
		let secret_key = SecretKey::from(sc_bytes);
		let public_key = PublicKey::from(&secret_key);

		// Generate ephemeral sk/pk
		// QUESTION: What are those?
		let ephemeral_sk = SecretKey::generate(rng);
		let ephemeral_pk = PublicKey::from(&ephemeral_sk);

		let my_box = ChaChaBox::new(&public_key, &ephemeral_sk);

		// We are encrypting the amount and the blinding
		let msg = to_bytes![self.leaf_private.amount, self.leaf_private.blinding]?;
		// Encrypting the message
		let ct = my_box
			.encrypt(&nonce, Payload {
				msg: &msg,
				aad: &[],
			})
			.map_err::<Error, _>(|_| UtxoError::EncryptionFailed.into())?;
		Ok(EncryptedUtxo {
			nonce: nonce.as_slice().to_vec(),
			cypher_text: ct,
			ephemeral_pk: ephemeral_pk.as_bytes().to_vec(),
		})
	}

	pub fn decrypt(&self, encrypted_utxo: &EncryptedUtxo) -> Result<(Vec<u8>, Vec<u8>), Error> {
		let private_key_bytes = to_bytes![self.keypair.secret_key]?;
		let mut sc_bytes = [0u8; 32];
		for i in 0..sc_bytes.len() {
			sc_bytes[i] = private_key_bytes[i];
		}
		let secret_key = SecretKey::from(sc_bytes);
		let eph_bytes = &encrypted_utxo.ephemeral_pk[..];
		let ephemeral_pk_bytes: [u8; 32] = eph_bytes
			.try_into()
			.map_err(|_| UtxoError::DecryptionFailed)?;
		let ephemeral_pk = PublicKey::from(ephemeral_pk_bytes);

		let my_box = ChaChaBox::new(&ephemeral_pk, &secret_key);

		let nonce = GenericArray::from_slice(&encrypted_utxo.nonce);
		let plaintext = my_box
			.decrypt(&nonce, Payload {
				msg: &encrypted_utxo.cypher_text,
				aad: &[],
			})
			.map_err::<Error, _>(|_| UtxoError::DecryptionFailed.into())?;

		let amount = plaintext[..32].to_vec();
		let blinding = plaintext[32..64].to_vec();
		Ok((amount, blinding))
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use ark_bn254::Fr as BnFr;
	use ark_ff::BigInteger;
	use ark_std::test_rng;
	use arkworks_utils::utils::common::{
		setup_params_x5_2, setup_params_x5_4, setup_params_x5_5, Curve,
	};

	#[test]
	fn test_encrypt() {
		let curve = Curve::Bn254;
		let params2 = setup_params_x5_2::<BnFr>(curve);
		let params4 = setup_params_x5_4::<BnFr>(curve);
		let params5 = setup_params_x5_5::<BnFr>(curve);

		let rng = &mut test_rng();

		let chain_id = BnFr::from(0u32);
		let amount = BnFr::from(5u32);
		let blinding = BnFr::from(10u32);
		// let utxo
		let utxo = Utxo::new(
			chain_id,
			amount,
			None,
			None,
			Some(blinding),
			&params2,
			&params4,
			&params5,
			rng,
		)
		.unwrap();

		let encrypted_data = utxo.encrypt(rng).unwrap();
		let (amount_bytes, blinding_bytes) = utxo.decrypt(&encrypted_data).unwrap();

		assert_eq!(amount_bytes, amount.into_repr().to_bytes_le());
		assert_eq!(blinding_bytes, blinding.into_repr().to_bytes_le());
	}
}
