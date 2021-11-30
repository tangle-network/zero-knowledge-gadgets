use ark_crypto_primitives::{crh::CRH, Error};
use ark_ff::{fields::PrimeField, to_bytes};
use ark_std::{marker::PhantomData, rand::Rng};

#[cfg(feature = "r1cs")]
pub mod constraints;

#[derive(Default, Clone)]
pub struct Private<F: PrimeField> {
	r: F,
	nullifier: F,
}

impl<F: PrimeField> Private<F> {
	pub fn generate<R: Rng>(rng: &mut R) -> Self {
		Self {
			r: F::rand(rng),
			nullifier: F::rand(rng),
		}
	}
}

pub struct BasicLeaf<F: PrimeField, H: CRH> {
	_field: PhantomData<F>,
	_hasher: PhantomData<H>,
}

impl<F: PrimeField, H: CRH> BasicLeaf<F, H> {
	pub fn create_leaf(private: &Private<F>, h: &H::Parameters) -> Result<H::Output, Error> {
		let bytes = to_bytes![private.r, private.nullifier]?;
		H::evaluate(h, &bytes)
	}

	pub fn create_nullifier(private: &Private<F>, h: &H::Parameters) -> Result<H::Output, Error> {
		let bytes = to_bytes![private.nullifier, private.nullifier]?;
		H::evaluate(h, &bytes)
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::poseidon::CRH;
	use ark_bls12_381::Fq;
	use ark_crypto_primitives::crh::CRH as CRHTrait;
	use ark_ff::to_bytes;
	use ark_std::test_rng;
	use arkworks_utils::utils::common::setup_params_x5_3;

	type PoseidonCRH3 = CRH<Fq>;

	type Leaf = BasicLeaf<Fq, PoseidonCRH3>;
	#[test]
	fn should_create_leaf() {
		let rng = &mut test_rng();
		let curve = arkworks_utils::utils::common::Curve::Bls381;

		let secrets = Private::<Fq>::generate(rng);

		let inputs_leaf = to_bytes![secrets.r, secrets.nullifier].unwrap();

		let params = setup_params_x5_3(curve);
		let ev_res = PoseidonCRH3::evaluate(&params, &inputs_leaf).unwrap();

		let leaf = Leaf::create_leaf(&secrets, &params).unwrap();
		assert_eq!(ev_res, leaf);
	}
}
