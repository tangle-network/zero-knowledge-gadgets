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
	type SetVar: AllocVar<[F], F> + Clone;

	fn product(s: &Self::InputVar, p: &Self::SetVar) -> Result<Self::OutputVar, SynthesisError>;
}
