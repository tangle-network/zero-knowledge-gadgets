use super::Set;
use ark_ff::fields::PrimeField;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::SynthesisError;
use core::fmt::Debug;

pub trait SetGadget<F: PrimeField, S: Set<F>>: Sized {
	type OutputVar: EqGadget<F>
		+ ToBytesGadget<F>
		+ CondSelectGadget<F>
		+ AllocVar<S::Output, F>
		+ R1CSVar<F>
		+ Debug
		+ Clone
		+ Sized;

	type InputVar: AllocVar<S::Input, F> + Clone;

	fn product(input: &Self::InputVar) -> Result<Self::OutputVar, SynthesisError>;
}
