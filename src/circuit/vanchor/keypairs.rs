use crate::{
	leaf::newleaf,
};
use ark_crypto_primitives::CRH;
use ark_ff::{fields::PrimeField, to_bytes};
use ark_std::marker::PhantomData;

#[derive(Default, Clone)]
pub struct Keypairs<H: CRH, F: PrimeField> {
	pubkey: <H as CRH>::Output,
	data: PhantomData<F>,
}
impl<H: CRH, F: PrimeField> Keypairs<H, F> {
	pub fn public_key(h: H::Parameters, secrets: newleaf::Private<F>) -> Self {
		let bytes = to_bytes![secrets.priv_key].unwrap();
		let pubkey = H::evaluate(&h, &bytes).unwrap();
		Keypairs {
			pubkey,
			data: PhantomData,
		}
	}
}
