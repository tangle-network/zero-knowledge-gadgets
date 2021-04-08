use super::Set;
use ark_ff::fields::PrimeField;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::SynthesisError;

pub trait SetGadget<F: PrimeField, S: Set<F>>: Sized {
	type InputVar: AllocVar<S::Input, F> + Clone;

	fn check_membership(input: &Self::InputVar) -> Result<Boolean<F>, SynthesisError>;
}
