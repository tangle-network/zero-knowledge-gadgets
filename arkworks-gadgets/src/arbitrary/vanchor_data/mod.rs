use ark_ff::fields::PrimeField;

#[cfg(feature = "r1cs")]
pub mod constraints;

#[derive(Clone, Default)]
pub struct VAnchorArbitraryData<F: PrimeField> {
	pub ext_data: F,
}

impl<F: PrimeField> VAnchorArbitraryData<F> {
	pub fn new(ext_data: F) -> Self {
		Self { ext_data }
	}
}
