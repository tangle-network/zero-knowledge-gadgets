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
	pub refund: F,
}

impl<F: PrimeField> Input<F> {
	pub fn new(recipient: F, relayer: F, fee: F, refund: F) -> Self {
		Self {
			recipient,
			relayer,
			fee,
			refund,
		}
	}
}

pub struct BridgeData<F: PrimeField> {
	field: PhantomData<F>,
}

impl<F: PrimeField> Arbitrary for BridgeData<F> {
	type Input = Input<F>;
}
