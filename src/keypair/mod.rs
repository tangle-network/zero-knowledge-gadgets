use crate::leaf::VanchorLeafCreation;
use ark_crypto_primitives::{Error, CRH};
use ark_ff::fields::PrimeField;

#[cfg(feature = "r1cs")]
pub mod constraints;
pub mod vanchor;
pub trait KeypairCreation<
	F: PrimeField,
	H2: CRH,
	H4: CRH,
	H5: CRH,
	L: VanchorLeafCreation<F, H2, H4, H5>,
>: Sized
{
	fn new(h: &H2::Parameters, secrets: &L::Private) -> Result<Self, Error>;
	fn public_key(&self) -> Result<<H2 as CRH>::Output, Error>;
	fn private_key(&self) -> Result<F, Error>;
	fn public_key_raw(h: &H2::Parameters, secrets: &F) -> Result<Self, Error>;
}
