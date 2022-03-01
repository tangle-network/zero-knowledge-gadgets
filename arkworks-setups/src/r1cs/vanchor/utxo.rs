#[derive(Clone, Copy)]
pub struct Utxo<F: PrimeField> {
	pub chain_id: F,
	pub amount: F,
	pub keypair: Keypair<F, PoseidonCRH_x5_2<F>>,
	pub leaf_private: Private<F>,
	pub leaf_public: Public<F>,
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
		hasher2: &Poseidon<F>,
		hasher4: &Poseidon<F>,
		hasher5: &Poseidon<F>,
		rng: &mut R,
	) -> Result<Self, Error> {
		let blinding = blinding.unwrap_or(F::rand(rng));
		let private_input = Private::<F>::new(amount, blinding);
		let public_input = Public::<F>::new(chain_id);

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
}