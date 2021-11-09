
use ark_crypto_primitives::{crh::CRHGadget, CRH};
use ark_ff::fields::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;

use ark_relations::r1cs::SynthesisError;

use crate::leaf::{VanchorLeafCreation, VanchorLeafCreationGadget};

pub trait KeypairCreationGadget<
	H: CRH,
	HG: CRHGadget<H, F>,
	F: PrimeField,
	L: VanchorLeafCreation<H, F>,
	LG: VanchorLeafCreationGadget<F, H, HG, L>,
>: Sized
{
	fn new(
		h: &HG::ParametersVar,
		secrets: &<LG as VanchorLeafCreationGadget<F, H, HG, L>>::PrivateVar,
	) -> Result<Self, SynthesisError>;

	fn new_from_key(h: &HG::ParametersVar, privkey: &FpVar<F>) -> Result<Self, SynthesisError>;
	fn public_key_var(&self) -> Result<<HG as CRHGadget<H, F>>::OutputVar, SynthesisError>;
	fn private_key_var(&self) -> Result<FpVar<F>, SynthesisError>;
}