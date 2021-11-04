use ark_crypto_primitives::crh::{constraints::CRHGadget, CRH};
use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::SynthesisError;

use ark_ff::Field;
use core::fmt::Debug;

use crate::leaf::{LeafCreation, NewLeafCreation};

pub trait LeafCreationGadget<F: Field, H: CRH, HG: CRHGadget<H, F>, L: LeafCreation<H>>:
	Sized
{
	type LeafVar: EqGadget<F>
		+ ToBytesGadget<F>
		+ CondSelectGadget<F>
		+ AllocVar<L::Leaf, F>
		+ R1CSVar<F>
		+ Debug
		+ Clone
		+ Sized;

	type NullifierVar: EqGadget<F>
		+ ToBytesGadget<F>
		+ CondSelectGadget<F>
		+ AllocVar<L::Nullifier, F>
		+ R1CSVar<F>
		+ Debug
		+ Clone
		+ Sized;

	type PrivateVar: AllocVar<L::Private, F> + Clone;
	type PublicVar: AllocVar<L::Public, F> + Clone;

	fn create_leaf(
		s: &Self::PrivateVar,
		p: &Self::PublicVar,
		h: &HG::ParametersVar,
	) -> Result<Self::LeafVar, SynthesisError>;

	fn create_nullifier(
		s: &Self::PrivateVar,
		h: &HG::ParametersVar,
	) -> Result<Self::NullifierVar, SynthesisError>;
}

pub trait NewLeafCreationGadget<F: PrimeField, H: CRH, HG: CRHGadget<H, F>, L: NewLeafCreation<H>>:
	Sized
{
	type LeafVar: EqGadget<F>
		+ ToBytesGadget<F>
		+ CondSelectGadget<F>
		+ AllocVar<L::Leaf, F>
		+ R1CSVar<F>
		+ Debug
		+ Clone
		+ Sized;

	type NullifierVar: EqGadget<F>
		+ ToBytesGadget<F>
		+ CondSelectGadget<F>
		+ AllocVar<L::Nullifier, F>
		+ R1CSVar<F>
		+ Debug
		+ Clone
		+ Sized;

	type PrivateVar: AllocVar<L::Private, F> + Clone;
	type PublicVar: AllocVar<L::Public, F> + Clone;

	fn create_leaf(
		s: &Self::PrivateVar,
		p: &Self::PublicVar,
		pubkey: &<HG as CRHGadget<H, F>>::OutputVar,
		h: &HG::ParametersVar,
	) -> Result<Self::LeafVar, SynthesisError>;

	fn create_nullifier(
		s: &Self::PrivateVar,
		c: &Self::LeafVar,
		h: &HG::ParametersVar,
		indices: &FpVar<F>,
	) -> Result<Self::NullifierVar, SynthesisError>;
}
