use crate::keypair::Keypair;
use ark_crypto_primitives::Error;
use ark_ff::PrimeField;
use ark_std::{error::Error as ArkError, rand::RngCore, string::ToString};
use arkworks_native_gadgets::poseidon::{FieldHasher, Poseidon};

#[derive(Debug)]
pub enum UtxoError {
	NullifierNotCalculated,
	EncryptedDataDecodeError,
	IndexNotSet,
}

impl core::fmt::Display for UtxoError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		let msg = match self {
			UtxoError::NullifierNotCalculated => "Nullifier not calculated".to_string(),
			UtxoError::EncryptedDataDecodeError => "Failed to decode encrypted data".to_string(),
			&UtxoError::IndexNotSet => "Utxo index not set".to_string(),
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
		let keypair = Keypair::new(private_key, hasher2);

		let pub_key = keypair.public_key;
		let leaf = hasher5.hash(&[chain_id, amount, pub_key, blinding])?;

		let nullifier = if index.is_some() {
			let i = F::from(index.unwrap());
			let signature = keypair.signature(&leaf, &i, hasher4)?;
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
			nullifier: nullifier,
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
		let keypair = Keypair::new(private_key, hasher2);

		let pub_key = keypair.public_key;
		let leaf = hasher5.hash(&[chain_id, amount, pub_key, blinding])?;

		let nullifier = if index.is_some() {
			let i = F::from(index.unwrap());
			let signature = keypair.signature(&leaf, &i, hasher4)?;
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

	pub fn new_with_public(
		chain_id_raw: u64,
		amount: F,
		index: Option<u64>,
		public_key: F,
		blinding: F,
		hasher5: &Poseidon<F>,
	) -> Result<Self, Error> {
		let chain_id = F::from(chain_id_raw);
		let keypair = Keypair::new_from_public_key(public_key);

		let commitment = hasher5.hash(&[chain_id, amount, public_key, blinding])?;

		Ok(Self {
			chain_id_raw,
			chain_id,
			amount,
			keypair,
			blinding,
			index,
			nullifier: None,
			commitment,
		})
	}

	pub fn set_index(&mut self, index: u64) {
		self.index = Some(index);
	}

	pub fn calculate_nullifier(&self, hasher4: &Poseidon<F>) -> Result<F, Error> {
		let i = F::from(self.index.unwrap());
		let signature = self.keypair.signature(&self.commitment, &i, hasher4)?;
		let nullifier = hasher4.hash(&[self.commitment, i, signature])?;
		Ok(nullifier)
	}

	pub fn get_index(&self) -> Result<u64, Error> {
		self.index.ok_or(UtxoError::IndexNotSet.into())
	}
}
