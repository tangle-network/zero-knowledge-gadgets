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

#[cfg(feature = "default_poseidon")]
#[cfg(test)]
mod test {
	use super::*;
	use crate::{
		poseidon::{sbox::PoseidonSbox, PoseidonParameters, Rounds, CRH},
		utils::{get_mds_poseidon_bls381_x5_3, get_rounds_poseidon_bls381_x5_3},
	};
	use ark_bls12_381::Fq;
	use ark_crypto_primitives::crh::CRH as CRHTrait;
	use ark_ff::to_bytes;
	use ark_std::test_rng;

	#[derive(Default, Clone)]
	struct PoseidonRounds3;

	impl Rounds for PoseidonRounds3 {
		const FULL_ROUNDS: usize = 8;
		const PARTIAL_ROUNDS: usize = 57;
		const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
		const WIDTH: usize = 3;
	}

	type PoseidonCRH3 = CRH<Fq, PoseidonRounds3>;

	type Leaf = BasicLeaf<Fq, PoseidonCRH3>;
	#[test]
	fn should_create_leaf() {
		let rng = &mut test_rng();
		let secrets = Private::<Fq>::generate(rng);

		let inputs_leaf = to_bytes![secrets.r, secrets.nullifier].unwrap();

		let rounds = get_rounds_poseidon_bls381_x5_3::<Fq>();
		let mds = get_mds_poseidon_bls381_x5_3::<Fq>();
		let params = PoseidonParameters::<Fq>::new(rounds, mds);
		let ev_res = PoseidonCRH3::evaluate(&params, &inputs_leaf).unwrap();

		let leaf = Leaf::create_leaf(&secrets, &params).unwrap();
		assert_eq!(ev_res, leaf);
	}
}
