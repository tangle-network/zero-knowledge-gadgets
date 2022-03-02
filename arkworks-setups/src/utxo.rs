use ark_crypto_primitives::Error;
use ark_ff::PrimeField;
use ark_std::{error::Error as ArkError, rand::RngCore};
use arkworks_gadgets::{
	keypair::vanchor::Keypair,
	poseidon::field_hasher::{FieldHasher, Poseidon},
};

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

#[derive(Default, Clone)]
pub struct Utxo<F: PrimeField> {
	pub chain_id_raw: u64,
	pub chain_id: F,
	pub amount: F,
	pub blinding: F,
	pub keypair: Keypair<F, Poseidon<F>, Poseidon<F>>,
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

		let keypair = Keypair::new(private_key.unwrap_or(F::rand(rng)));
		let pub_key = keypair.public_key(hasher2)?;

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

	pub fn get_nullifier(&self) -> Result<F, Error> {
		self.nullifier
			.ok_or(UtxoError::NullifierNotCalculated.into())
	}
}
