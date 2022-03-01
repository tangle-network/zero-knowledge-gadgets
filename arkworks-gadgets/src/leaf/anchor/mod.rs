use ark_crypto_primitives::{crh::CRH, Error};
use ark_ff::{fields::PrimeField, to_bytes};
use ark_relations::r1cs::SynthesisError;
use ark_std::{marker::PhantomData, rand::Rng};

use crate::poseidon::field_hasher::FieldHasher;

#[cfg(feature = "r1cs")]
pub mod constraints;

#[derive(Default, Clone)]
pub struct Private<F: PrimeField> {
	pub secret: F,
	pub nullifier: F,
}

impl<F: PrimeField> Private<F> {
	pub fn generate<R: Rng>(rng: &mut R) -> Self {
		Self {
			secret: F::rand(rng),
			nullifier: F::rand(rng),
		}
	}

	pub fn new(secret: F, nullifier: F) -> Self {
		Self { secret, nullifier }
	}

	pub fn secret(&self) -> F {
		self.secret
	}

	pub fn nullifier(&self) -> F {
		self.nullifier
	}
}

#[derive(Default, Clone)]
pub struct Public<F: PrimeField> {
	pub chain_id: F,
}

impl<F: PrimeField> Public<F> {
	pub fn new(chain_id: F) -> Self {
		Self { chain_id }
	}
}

#[derive(Clone)]
pub struct AnchorLeaf<F: PrimeField, H: FieldHasher<F>> {
	field: PhantomData<F>,
	hasher: PhantomData<H>,
}

impl<F: PrimeField, H: FieldHasher<F>> AnchorLeaf<F, H> {
	pub fn create_leaf(
		private: &Private<F>,
		public: &Public<F>,
		h: &H,
	) -> Result<F, String> {
		h.hash(&[private.secret, private.nullifier, public.chain_id]).map_err(|_| "Leaf hash error".to_string())
	}

	pub fn create_nullifier(private: &Private<F>, h: &H) -> Result<F, String> {
		h.hash_two(&private.nullifier, &private.nullifier).map_err(|_| "Nullifier hash error".to_string())
	}
}

