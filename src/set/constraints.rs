use super::Set;
use ark_ff::fields::PrimeField;
use ark_r1cs_std::{
	fields::fp::FpVar,
	prelude::{AllocVar, Boolean, ToBytesGadget},
};
use ark_relations::r1cs::SynthesisError;

pub trait SetGadget<F: PrimeField, S: Set<F>>: Sized {
	type PrivateVar: AllocVar<S::Private, F> + Clone;

	fn check<T: ToBytesGadget<F>>(
		target: &T,
		elements: &Vec<FpVar<F>>,
		private: &Self::PrivateVar,
	) -> Result<Boolean<F>, SynthesisError>;
}
