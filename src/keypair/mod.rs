use crate::leaf::VanchorLeafCreation;
use ark_crypto_primitives::{Error, CRH};
use ark_ff::fields::PrimeField;

#[cfg(feature = "r1cs")]
pub mod constraints;
pub mod vanchor;
pub trait KeypairCreation<H: CRH, F: PrimeField, L: VanchorLeafCreation<H, F>>: Sized {
	fn new(h: &H::Parameters, secrets: &L::Private) -> Result<Self, Error>;
	fn public_key(&self) -> Result<<H as CRH>::Output, Error>;
	fn private_key(&self) -> Result<F, Error>;
	fn public_key_raw(h: &H::Parameters, secrets: &F) -> Result<Self, Error>;
}
