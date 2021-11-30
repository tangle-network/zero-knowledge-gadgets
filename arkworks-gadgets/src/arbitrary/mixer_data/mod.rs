use ark_ff::fields::PrimeField;

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
