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

#[cfg(feature = "default_poseidon")]
#[cfg(test)]
mod test {
	use super::*;
	use crate::{
		poseidon::{sbox::PoseidonSbox, PoseidonParameters, Rounds, CRH},
		utils::{get_mds_poseidon_bls381_x5_5, get_rounds_poseidon_bls381_x5_5},
	};
	use ark_bls12_381::Fq;
	use ark_crypto_primitives::crh::CRH as CRHTrait;
	use ark_ff::One;
	use ark_std::test_rng;

	#[derive(Default, Clone)]
	struct PoseidonRounds5;

	impl Rounds for PoseidonRounds5 {
		const FULL_ROUNDS: usize = 8;
		const PARTIAL_ROUNDS: usize = 60;
		const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
		const WIDTH: usize = 5;
	}

	type PoseidonCRH5 = CRH<Fq, PoseidonRounds5>;

	type Leaf = BridgeLeaf<Fq, PoseidonCRH5>;
	#[test]
	fn should_crate_bridge_leaf() {
		let rng = &mut test_rng();
		let private = Private::generate(rng);

		let chain_id = Fq::one();
		let public = Public::new(chain_id);

		let leaf_inputs = to_bytes![private.secret, private.nullifier, public.chain_id].unwrap();

		let nullifier_inputs = to_bytes![private.nullifier, private.nullifier].unwrap();

		let rounds = get_rounds_poseidon_bls381_x5_5::<Fq>();
		let mds = get_mds_poseidon_bls381_x5_5::<Fq>();
		let params = PoseidonParameters::<Fq>::new(rounds, mds);
		let leaf_res = PoseidonCRH5::evaluate(&params, &leaf_inputs).unwrap();
		let nullifier_res = PoseidonCRH5::evaluate(&params, &nullifier_inputs).unwrap();

		let leaf_hash = Leaf::create_leaf(&private, &public, &params).unwrap();
		let nullifier_hash = Leaf::create_nullifier(&private, &params).unwrap();
		assert_eq!(leaf_res, leaf_hash);
		assert_eq!(nullifier_res, nullifier_hash);
	}
}
