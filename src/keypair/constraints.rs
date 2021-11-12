use ark_crypto_primitives::{crh::CRHGadget, CRH};
use ark_ff::fields::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;

use ark_relations::r1cs::SynthesisError;

use crate::leaf::{VanchorLeafCreation, VanchorLeafCreationGadget};

pub trait KeypairCreationGadget<
	F: PrimeField,
	H2: CRH,
	HG2: CRHGadget<H2, F>,
	H4: CRH,
	HG4: CRHGadget<H4, F>,
	H5: CRH,
	HG5: CRHGadget<H5, F>,
	L: VanchorLeafCreation<F, H2, H4, H5>,
	LG: VanchorLeafCreationGadget<F, H2, HG2, H4, HG4, H5, HG5, L>,
>: Sized
{
	fn new(
		h: &HG2::ParametersVar,
		secrets: &<LG as VanchorLeafCreationGadget<F, H2, HG2, H4, HG4, H5, HG5, L>>::PrivateVar,
	) -> Result<Self, SynthesisError>;

	fn new_from_key(h: &HG2::ParametersVar, privkey: &FpVar<F>) -> Result<Self, SynthesisError>;
	fn public_key_var(&self) -> Result<<HG2 as CRHGadget<H2, F>>::OutputVar, SynthesisError>;
	fn private_key_var(&self) -> Result<FpVar<F>, SynthesisError>;
}
