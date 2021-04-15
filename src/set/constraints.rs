use super::Set;
use ark_ff::fields::PrimeField;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::SynthesisError;

pub trait SetGadget<F: PrimeField, S: Set<F>>: Sized {
	type PublicVar: AllocVar<S::Public, F> + Clone;
	type PrivateVar: AllocVar<S::Private, F> + Clone;

	fn check_membership(
		p: &Self::PublicVar,
		s: &Self::PrivateVar,
	) -> Result<Boolean<F>, SynthesisError>;
}
