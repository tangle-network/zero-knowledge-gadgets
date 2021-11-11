use ark_crypto_primitives::{crh::CRH, Error};
use ark_ff::{fields::PrimeField, to_bytes};

use ark_std::{marker::PhantomData, rand::Rng};
//use std::convert::TryInto;
//use std::vec::Vec;

#[cfg(feature = "r1cs")]
pub mod constraints;

#[derive(Clone)]
pub struct Private<F: PrimeField> {
	amount: F,
	blinding: F,
	priv_key: F,
}

#[derive(Default, Clone)]
pub struct Public<F: PrimeField> {
	chain_id: F,
}

impl<F: PrimeField> Public<F> {
	pub fn new(chain_id: F) -> Self {
		Self { chain_id }
	}
}

impl<F: PrimeField> Private<F> {
	pub fn generate<R: Rng>(rng: &mut R) -> Self {
		Self {
			amount: F::rand(rng),
			blinding: F::rand(rng),
			priv_key: F::rand(rng),
		}
	}
}

struct NewLeaf<F: PrimeField, H: CRH> {
	field: PhantomData<F>,
	hasher: PhantomData<H>,
}

impl<F: PrimeField, H: CRH> NewLeaf<F, H> {
	// Commits to the values = hash(chain_id, amount, pubKey, blinding)
	pub fn create_leaf(
		private: &Private<F>,
		public: &Public<F>,
		pubk: &H::Output,
		h: &H::Parameters,
	) -> Result<H::Output, Error> {
		let bytes = to_bytes![public.chain_id, private.amount, pubk, private.blinding]?;
		H::evaluate(h, &bytes)
	}

	// Computes the nullifier = hash(commitment, pathIndices, privKey)
	pub fn create_nullifier(
		private: &Private<F>,
		leaf: &H::Output,
		h: &H::Parameters,
		index: &F,
	) -> Result<H::Output, Error> {
		let bytes = to_bytes![leaf, index, private.priv_key]?;
		H::evaluate(h, &bytes)
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
	use ark_ff::to_bytes;
	use ark_std::test_rng;

	#[derive(Default, Clone)]
	struct PoseidonRounds3;

	impl Rounds for PoseidonRounds3 {
		const FULL_ROUNDS: usize = 8;
		const PARTIAL_ROUNDS: usize = 57;
		const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
		const WIDTH: usize = 4;
	}

	type PoseidonCRH3 = CRH<Fq, PoseidonRounds3>;
	type Leaf = NewLeaf<Fq, PoseidonCRH3>;

	#[test]
	fn should_create_leaf() {
		let rng = &mut test_rng();
		let private = Private::generate(rng);
		let public = Public::default();

		let rounds = get_rounds_poseidon_bls381_x5_5::<Fq>();
		let mds = get_mds_poseidon_bls381_x5_5::<Fq>();
		let params = PoseidonParameters::<Fq>::new(rounds, mds);
		let privkey = to_bytes![private.priv_key].unwrap();
		let pubkey = PoseidonCRH3::evaluate(&params, &privkey).unwrap();
		// Commitment = hash(chainID, amount, blinding, pubKey)
		let inputs_leaf =
			to_bytes![public.chain_id, private.amount, pubkey, private.blinding].unwrap();
		let ev_res = PoseidonCRH3::evaluate(&params, &inputs_leaf).unwrap();

		let leaf_hash = Leaf::create_leaf(&private, &public, &pubkey, &params).unwrap();
		assert_eq!(ev_res, leaf_hash);
	}
	use crate::ark_std::Zero;
	#[test]
	fn should_create_nullifier() {
		let rng = &mut test_rng();
		let private = Private::generate(rng);
		let chain_id = Fq::zero();
		let public = Public::new(chain_id);
		let index = Fq::zero();

		let rounds = get_rounds_poseidon_bls381_x5_5::<Fq>();
		let mds = get_mds_poseidon_bls381_x5_5::<Fq>();
		let params = PoseidonParameters::<Fq>::new(rounds, mds);
		let privkey = to_bytes![private.priv_key].unwrap();
		let pubkey = PoseidonCRH3::evaluate(&params, &privkey).unwrap();
		// Since Commitment = hash(chainID, amount, blinding, pubKey)
		let inputs_leaf =
			to_bytes![public.chain_id, private.amount, pubkey, private.blinding].unwrap();
		let commitment = PoseidonCRH3::evaluate(&params, &inputs_leaf).unwrap();
		let leaf_hash = Leaf::create_leaf(&private, &public, &pubkey, &params).unwrap();
		assert_eq!(leaf_hash, commitment);

		// Since Nullifier = hash(commitment, pathIndices, privKey)
		let inputs_null = to_bytes![commitment, index, private.priv_key].unwrap();

		let ev_res = PoseidonCRH3::evaluate(&params, &inputs_null).unwrap();
		let nullifier = Leaf::create_nullifier(&private, &commitment, &params, &index).unwrap();
		assert_eq!(ev_res, nullifier);
	}
}
