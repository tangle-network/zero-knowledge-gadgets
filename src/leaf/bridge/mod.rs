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
	private: Private<F>,
	public: Public<F>,
	hasher: PhantomData<H>,
}

impl<F: PrimeField, H: CRH> BridgeLeaf<F, H> {
	pub fn new(private: Private<F>, public: Public<F>) -> BridgeLeaf<F, H> {
		Self {
			private,
			public,
			hasher: PhantomData,
		}
	}

	pub fn create_leaf(&self, h: &H::Parameters) -> Result<H::Output, Error> {
		let input_bytes = to_bytes![
			self.private.secret,
			self.private.nullifier,
			self.public.chain_id
		]?;
		H::evaluate(h, &input_bytes)
	}

	pub fn create_nullifier(&self, h: &H::Parameters) -> Result<H::Output, Error> {
		let nullifier_bytes = to_bytes![self.private.nullifier, self.private.nullifier]?;
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
		let secrets = Private::generate(rng);

		let chain_id = Fq::one();
		let publics = Public::new(chain_id);

		let leaf = Leaf::new(secrets.clone(), publics.clone());

		let leaf_inputs = to_bytes![secrets.secret, secrets.nullifier, publics.chain_id].unwrap();

		let nullifier_inputs = to_bytes![secrets.nullifier, secrets.nullifier].unwrap();

		let rounds = get_rounds_poseidon_bls381_x5_5::<Fq>();
		let mds = get_mds_poseidon_bls381_x5_5::<Fq>();
		let params = PoseidonParameters::<Fq>::new(rounds, mds);
		let leaf_res = PoseidonCRH5::evaluate(&params, &leaf_inputs).unwrap();
		let nullifier_res = PoseidonCRH5::evaluate(&params, &nullifier_inputs).unwrap();

		let leaf_hash = leaf.create_leaf(&params).unwrap();
		let nullifier_hash = leaf.create_nullifier(&params).unwrap();
		assert_eq!(leaf_res, leaf_hash);
		assert_eq!(nullifier_res, nullifier_hash);
	}
}
