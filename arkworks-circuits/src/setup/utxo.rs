use crate::setup::common::{PoseidonCRH_x5_2, PoseidonCRH_x5_4};
use ark_crypto_primitives::Error;
use ark_ff::{to_bytes, PrimeField};
use ark_std::{
	error::Error as ArkError,
	rand::{CryptoRng, RngCore},
	string::ToString,
	vec::Vec,
};
use arkworks_gadgets::{
	keypair::vanchor::{EncryptedData, Keypair},
	leaf::vanchor::{Private as LeafPrivateInput, Public as LeafPublicInput, VAnchorLeaf as Leaf},
};
use arkworks_utils::poseidon::PoseidonParameters;

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

	pub fn encrypt<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Result<EncryptedData, Error> {
		// We are encrypting the amount and the blinding
		let msg = to_bytes![self.leaf_private.amount, self.leaf_private.blinding]?;
		// Encrypting the message
		let enc_data = self.keypair.encrypt(&msg, rng)?;
		Ok(enc_data)
	}

	pub fn decrypt(&self, data: &EncryptedData) -> Result<(Vec<u8>, Vec<u8>), Error> {
		// Decrypting the message
		let plaintext = self.keypair.decrypt(data)?;

		// First 32 bytes is amount
		// Second 32 bytes is blinding
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
