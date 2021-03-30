use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::SynthesisError;

use ark_ff::Field;
use core::fmt::Debug;

use crate::leaf::LeafCreation;

pub trait LeafCreationGadget<L: LeafCreation, F: Field>: Sized {
	type OutputVar: EqGadget<F>
		+ ToBytesGadget<F>
		+ CondSelectGadget<F>
		+ AllocVar<L::Output, F>
		+ R1CSVar<F>
		+ Debug
		+ Clone
		+ Sized;

	type SecretsVar: AllocVar<L::Secrets, F> + Clone;

	fn evaluate(s: &Self::SecretsVar) -> Result<Self::OutputVar, SynthesisError>;
}
