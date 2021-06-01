use super::Arbitrary;
use ark_ff::fields::PrimeField;
use ark_std::marker::PhantomData;

#[cfg(feature = "r1cs")]
pub mod constraints;

#[derive(Clone, Default)]
pub struct Input<F: PrimeField> {
	pub recipient: F,
	pub relayer: F,
	pub fee: F,
}

impl<F: PrimeField> Input<F> {
	pub fn new(recipient: F, relayer: F, fee: F) -> Self {
		Self {
			recipient,
			relayer,
			fee,
		}
	}
}

pub struct BridgeData<F: PrimeField> {
	field: PhantomData<F>,
}

impl<F: PrimeField> Arbitrary for BridgeData<F> {
	type Input = Input<F>;
}
