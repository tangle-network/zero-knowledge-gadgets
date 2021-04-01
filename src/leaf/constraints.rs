use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::SynthesisError;
use webb_crypto_primitives::crh::{constraints::FixedLengthCRHGadget, FixedLengthCRH};

use ark_ff::Field;
use core::fmt::Debug;

use crate::leaf::LeafCreation;

pub trait LeafCreationGadget<
	F: Field,
	H: FixedLengthCRH,
	HG: FixedLengthCRHGadget<H, F>,
	L: LeafCreation<H>,
>: Sized
{
	type OutputVar: EqGadget<F>
		+ ToBytesGadget<F>
		+ CondSelectGadget<F>
		+ AllocVar<H::Output, F>
		+ R1CSVar<F>
		+ Debug
		+ Clone
		+ Sized;

	type SecretsVar: AllocVar<L::Secrets, F> + Clone;
	type PublicsVar: AllocVar<L::Publics, F> + Clone;

	fn create(
		s: &Self::SecretsVar,
		p: &Self::PublicsVar,
		h: &HG::ParametersVar,
	) -> Result<Self::OutputVar, SynthesisError>;
}
