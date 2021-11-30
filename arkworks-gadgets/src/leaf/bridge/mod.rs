use ark_crypto_primitives::{crh::CRH, Error};
use ark_ff::{fields::PrimeField, to_bytes};
use ark_std::{marker::PhantomData, rand::Rng};

#[cfg(feature = "r1cs")]
pub mod constraints;

#[derive(Default, Clone)]
pub struct Private<F: PrimeField> {
	secret: F,
	nullifier: F,
}

impl<F: PrimeField> Private<F> {
	pub fn generate<R: Rng>(rng: &mut R) -> Self {
		Self {
			secret: F::rand(rng),
			nullifier: F::rand(rng),
		}
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
pub struct BridgeLeaf<F: PrimeField, H: CRH> {
	field: PhantomData<F>,
	hasher: PhantomData<H>,
}

impl<F: PrimeField, H: CRH> BridgeLeaf<F, H> {
	pub fn create_leaf(
		private: &Private<F>,
		public: &Public<F>,
		h: &H::Parameters,
	) -> Result<H::Output, Error> {
		let input_bytes = to_bytes![private.secret, private.nullifier, public.chain_id]?;
		H::evaluate(h, &input_bytes)
	}

	pub fn create_nullifier(private: &Private<F>, h: &H::Parameters) -> Result<H::Output, Error> {
		let nullifier_bytes = to_bytes![private.nullifier, private.nullifier]?;
		H::evaluate(h, &nullifier_bytes)
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::poseidon::CRH;
	use ark_bls12_381::Fq;
	use ark_crypto_primitives::crh::CRH as CRHTrait;
	use ark_ff::One;
	use ark_std::test_rng;
	use arkworks_utils::utils::common::setup_params_x5_5;

	type PoseidonCRH5 = CRH<Fq>;

	type Leaf = BridgeLeaf<Fq, PoseidonCRH5>;
	#[test]
	fn should_crate_bridge_leaf() {
		let rng = &mut test_rng();
		let curve = arkworks_utils::utils::common::Curve::Bls381;

		let private = Private::generate(rng);

		let chain_id = Fq::one();
		let public = Public::new(chain_id);

		let leaf_inputs = to_bytes![private.secret, private.nullifier, public.chain_id].unwrap();

		let nullifier_inputs = to_bytes![private.nullifier, private.nullifier].unwrap();

		let params = setup_params_x5_5(curve);

		let leaf_res = PoseidonCRH5::evaluate(&params, &leaf_inputs).unwrap();
		let nullifier_res = PoseidonCRH5::evaluate(&params, &nullifier_inputs).unwrap();

		let leaf_hash = Leaf::create_leaf(&private, &public, &params).unwrap();
		let nullifier_hash = Leaf::create_nullifier(&private, &params).unwrap();
		assert_eq!(leaf_res, leaf_hash);
		assert_eq!(nullifier_res, nullifier_hash);
	}
}
