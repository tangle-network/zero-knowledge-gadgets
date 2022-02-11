use crate::setup::common::{PoseidonCRH_x5_2, PoseidonCRH_x5_4};
use ark_crypto_primitives::Error;
use ark_ff::PrimeField;
use ark_std::{error::Error as ArkError, rand::{RngCore, Rng}, string::ToString};
use arkworks_gadgets::{
	keypair::vanchor::Keypair,
	leaf::vanchor::{Private as LeafPrivateInput, Public as LeafPublicInput, VAnchorLeaf as Leaf},
};
use arkworks_utils::poseidon::PoseidonParameters;

use sodalite::box_keypair_seed;

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

        let nullifier =
            Leaf::<_, PoseidonCRH_x5_4<F>>::create_nullifier(&signature, &self.commitment, &params4, &i)?;

        self.nullifier = Some(nullifier);

        Ok(())
    }

    pub fn encrypt<R: RngCore>(&self) -> Result<Vec<u8>, Error> {

        Ok(Vec::new())
    }
}
