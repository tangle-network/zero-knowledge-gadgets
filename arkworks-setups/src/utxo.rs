use ark_crypto_primitives::Error;
use ark_ff::{to_bytes, PrimeField};
use ark_std::{
	error::Error as ArkError,
	rand::{CryptoRng, RngCore},
	string::ToString,
	vec::Vec,
};
use crate::keypair::{EncryptedData, Keypair};
use arkworks_gadgets::poseidon::field_hasher::{FieldHasher, Poseidon};

#[derive(Debug)]
pub enum UtxoError {
	NullifierNotCalculated,
}

impl core::fmt::Display for UtxoError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		let msg = match self {
			UtxoError::NullifierNotCalculated => "Nullifier not calculated".to_string(),
		};
		write!(f, "{}", msg)
	}
}

impl ArkError for UtxoError {}

#[derive(Clone)]
pub struct Utxo<F: PrimeField> {
	pub chain_id_raw: u64,
	pub chain_id: F,
	pub amount: F,
	pub blinding: F,
	pub keypair: Keypair<F, Poseidon<F>>,
	pub index: Option<u64>,
	pub nullifier: Option<F>,
	pub commitment: F,
}

impl<F: PrimeField> Utxo<F> {
	pub fn new<R: RngCore>(
		chain_id_raw: u64,
		amount: F,
		index: Option<u64>,
		private_key: Option<F>,
		blinding: Option<F>,
		hasher2: &Poseidon<F>,
		hasher4: &Poseidon<F>,
		hasher5: &Poseidon<F>,
		rng: &mut R,
	) -> Result<Self, Error> {
		let chain_id = F::from(chain_id_raw);
		let blinding = blinding.unwrap_or(F::rand(rng));

		let private_key = private_key.unwrap_or(F::rand(rng));
		let keypair = Keypair::new(private_key);

		let pub_key = keypair.public_key(hasher2)?;

		let leaf = hasher5.hash(&[chain_id, amount, pub_key, blinding])?;

		let nullifier = if index.is_some() {
			let i = F::from(index.unwrap());

			let signature = keypair.signature(&leaf, &i, hasher4)?;
			// Nullifier
			let nullifier = hasher4.hash(&[leaf, i, signature])?;

			Some(nullifier)
		} else {
			None
		};

		Ok(Self {
			chain_id_raw,
			chain_id,
			amount,
			keypair,
			blinding,
			index,
			nullifier,
			commitment: leaf,
		})
	}

	pub fn new_with_privates(
		chain_id_raw: u64,
		amount: F,
		index: Option<u64>,
		private_key: F,
		blinding: F,
		hasher2: &Poseidon<F>,
		hasher4: &Poseidon<F>,
		hasher5: &Poseidon<F>,
	) -> Result<Self, Error> {
		let chain_id = F::from(chain_id_raw);
		let keypair = Keypair::new(private_key);

		let pub_key = keypair.public_key(hasher2)?;
		let leaf = hasher5.hash(&[chain_id, amount, pub_key, blinding])?;

		let nullifier = if index.is_some() {
			let i = F::from(index.unwrap());

			let signature = keypair.signature(&leaf, &i, hasher4)?;
			// Nullifier
			let nullifier = hasher4.hash(&[leaf, i, signature])?;

			Some(nullifier)
		} else {
			None
		};

		Ok(Self {
			chain_id_raw,
			chain_id,
			amount,
			keypair,
			blinding,
			index,
			nullifier,
			commitment: leaf,
		})
	}

	pub fn get_nullifier(&self) -> Result<F, Error> {
		self.nullifier
			.ok_or(UtxoError::NullifierNotCalculated.into())
	}

	pub fn encrypt<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Result<EncryptedData, Error> {
		// We are encrypting the amount and the blinding
		let msg = to_bytes![self.chain_id, self.amount, self.blinding]?;
		// Encrypting the message
		let enc_data = self.keypair.encrypt(&msg, rng)?;
		Ok(enc_data)
	}

	pub fn decrypt(&self, data: &EncryptedData) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), Error> {
		// Decrypting the message
		let plaintext = self.keypair.decrypt(data)?;

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
		let poseidon2 = Poseidon::new(params2);
		let poseidon4 = Poseidon::new(params4);
		let poseidon5 = Poseidon::new(params5);

		let rng = &mut test_rng();

		let chain_id_raw = 0u64;
		let chain_id = BnFr::from(chain_id_raw);
		let amount = BnFr::from(5u64);
		let blinding = BnFr::from(10u32);
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
