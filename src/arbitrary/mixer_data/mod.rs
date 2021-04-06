use super::Arbitrary;
use ark_ff::fields::PrimeField;
use ark_std::marker::PhantomData;

#[cfg(feature = "r1cs")]
mod constraints;

#[derive(Clone, Default)]
pub struct Input<F: PrimeField> {
	recipient: F,
	relayer: F,
	fee: F,
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

pub struct MixerData<F: PrimeField> {
	field: PhantomData<F>,
}

impl<F: PrimeField> Arbitrary for MixerData<F> {
	type Input = Input<F>;
}
