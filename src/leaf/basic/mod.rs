use crate::leaf::LeafCreation;
use ark_crypto_primitives::Error;
use ark_ff::fields::PrimeField;
use ark_std::{marker::PhantomData, rand::Rng};

#[derive(Default, Clone)]
struct Secrets<F> {
	r: F,
	nullifier: F,
}

impl<F: PrimeField> Secrets<F> {
	pub fn generate<R: Rng>(rng: &mut R) -> Self {
		Self {
			r: F::rand(rng),
			nullifier: F::rand(rng),
		}
	}
}

struct BasicLeaf<F: PrimeField> {
	field: PhantomData<F>,
}

impl<F: PrimeField> LeafCreation for BasicLeaf<F> {
	type Output = F;
	type Secrets = Secrets<F>;

	fn generate_secrets<R: Rng>(r: &mut R) -> Result<Self::Secrets, Error> {
		Ok(Self::Secrets::generate(r))
	}

	fn create(_: &Self::Secrets) -> Result<Self::Output, Error> {
		Ok(F::zero())
	}
}
