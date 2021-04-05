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
		+ AllocVar<L::Output, F>
		+ R1CSVar<F>
		+ Debug
		+ Clone
		+ Sized;

	type PrivateVar: AllocVar<L::Private, F> + Clone;
	type PublicVar: AllocVar<L::Public, F> + Clone;

	fn create(
		s: &Self::PrivateVar,
		p: &Self::PublicVar,
		h: &HG::ParametersVar,
	) -> Result<Self::OutputVar, SynthesisError>;
}
