use ark_crypto_primitives::Error;
use ark_ff::PrimeField;
use ark_std::marker::PhantomData;
use arkworks_utils::poseidon::PoseidonError;

use crate::poseidon::field_hasher::FieldHasher;

#[cfg(feature = "r1cs")]
pub mod constraints;

#[derive(Default, Debug, Copy)]
pub struct Keypair<F: PrimeField, PH: FieldHasher<F>, SH: FieldHasher<F>> {
	pub private_key: F,
	_h: PhantomData<(PH, SH)>,
}

impl<F: PrimeField, PH: FieldHasher<F>, SH: FieldHasher<F>> Keypair<F, PH, SH> {
	pub fn new(private_key: F) -> Self {
		Self {
			private_key,
			_h: PhantomData,
		}
	}

	pub fn public_key(&self, h: &PH) -> Result<F, PoseidonError> {
		h.hash(&[self.private_key])
	}

	// Computes the signature = hash(privKey, commitment, pathIndices)
	pub fn signature(&self, commitment: &F, index: &F, h_w4: &SH) -> Result<F, PoseidonError> {
		h_w4.hash(&[self.private_key.clone(), commitment.clone(), index.clone()])
	}
}

impl<F: PrimeField, PH: FieldHasher<F>, SH: FieldHasher<F>> Clone for Keypair<F, PH, SH> {
	fn clone(&self) -> Self {
		let private_key = self.private_key.clone();
		Self::new(private_key)
	}
}

#[cfg(test)]
mod test {
	use crate::{
		ark_std::{UniformRand, Zero},
		poseidon::field_hasher::{FieldHasher, Poseidon},
	};

	use ark_ed_on_bn254::Fq;
	use ark_ff::to_bytes;
	use arkworks_utils::utils::common::{setup_params_x5_2, setup_params_x5_4, Curve};

	use ark_std::test_rng;

	use super::Keypair;

	#[test]
	fn should_crate_new_public_key() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;

		let params = setup_params_x5_2(curve);
		let hasher = Poseidon::<Fq>::new(params.clone());
		let private_key = Fq::rand(rng);

		let pubkey = hasher.hash(&[private_key]).unwrap();

		let keypair = Keypair::<Fq, Poseidon<Fq>, Poseidon<Fq>>::new(private_key.clone());
		let new_pubkey = keypair.public_key(&hasher).unwrap();

		assert_eq!(new_pubkey, pubkey)
	}
	#[test]
	fn should_crate_new_signature() {
		let rng = &mut test_rng();
		let index = Fq::zero();
		let private_key = Fq::rand(rng);
		let curve = Curve::Bn254;

		let params4 = setup_params_x5_4(curve);
		let hasher = Poseidon::<Fq>::new(params4.clone());
		let commitment = Fq::rand(rng);

		let keypair = Keypair::<Fq, Poseidon<Fq>, Poseidon<Fq>>::new(private_key.clone());

		// Since signature = hash(privKey, commitment, pathIndices)
		let ev_res = hasher.hash(&[private_key, commitment, index]).unwrap();
		let signature = keypair.signature(&commitment, &index, &hasher).unwrap();
		assert_eq!(ev_res, signature);
	}
}
