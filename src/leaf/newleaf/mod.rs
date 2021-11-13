use crate::leaf::NewLeafCreation;
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

impl<F: PrimeField, H: CRH> NewLeafCreation<H> for NewLeaf<F, H> {
	// Commitment = hash(chain_id, amount, pubKey, blinding)
	type Leaf = H::Output;
	// Nullifier = hash(commitment, pathIndices, privKey)
	type Nullifier = H::Output;
	type Private = Private<F>;
	type Public = Public<F>;

	// Creates Random Secrets: r, nullifier, amount, blinding, priv_key,
	// merkle_path(TODO: merkle_path needs to be costructed) // TODO
	fn generate_secrets<R: Rng>(r: &mut R) -> Result<Self::Private, Error> {
		Ok(Self::Private::generate(r))
	}

	// Commits to the values = hash(chain_id, amount, pubKey, blinding)
	fn create_leaf(
		s: &Self::Private,
		p: &Self::Public,
		pubk: &<H as CRH>::Output,
		h: &H::Parameters,
	) -> Result<Self::Leaf, Error> {
		let bytes = to_bytes![p.chain_id, s.amount, pubk, s.blinding]?;
		H::evaluate(h, &bytes)
	}

	// Computes the nullifier = hash(commitment, pathIndices, privKey)
	fn create_nullifier<F1: PrimeField>(
		s: &Self::Private,
		c: &Self::Leaf,
		h: &H::Parameters,
		f: &F1,
	) -> Result<Self::Nullifier, Error> {
		let bytes = to_bytes![c, f, s.priv_key]?;
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
		let secrets = Leaf::generate_secrets(rng).unwrap();
		let publics = Public::default();

		let rounds = get_rounds_poseidon_bls381_x5_5::<Fq>();
		let mds = get_mds_poseidon_bls381_x5_5::<Fq>();
		let params = PoseidonParameters::<Fq>::new(rounds, mds);
		let privkey = to_bytes![secrets.priv_key].unwrap();
		let pubkey = PoseidonCRH3::evaluate(&params, &privkey).unwrap();
		// Commitment = hash(chainID, amount, blinding, pubKey)
		let inputs_leaf =
			to_bytes![publics.chain_id, secrets.amount, pubkey, secrets.blinding].unwrap();
		let ev_res = PoseidonCRH3::evaluate(&params, &inputs_leaf).unwrap();

		let leaf = Leaf::create_leaf(&secrets, &publics, &pubkey, &params).unwrap();
		assert_eq!(ev_res, leaf);
	}
	use crate::ark_std::Zero;
	#[test]
	fn should_create_nullifier() {
		let rng = &mut test_rng();
		let secrets = Leaf::generate_secrets(rng).unwrap();
		let chain_id = Fq::zero();
		let publics = Public::new(chain_id);
		let index = Fq::zero();

		let rounds = get_rounds_poseidon_bls381_x5_5::<Fq>();
		let mds = get_mds_poseidon_bls381_x5_5::<Fq>();
		let params = PoseidonParameters::<Fq>::new(rounds, mds);
		let privkey = to_bytes![secrets.priv_key].unwrap();
		let pubkey = PoseidonCRH3::evaluate(&params, &privkey).unwrap();
		// Since Commitment = hash(chainID, amount, blinding, pubKey)
		let inputs_leaf =
			to_bytes![publics.chain_id, secrets.amount, pubkey, secrets.blinding].unwrap();
		let commitment = PoseidonCRH3::evaluate(&params, &inputs_leaf).unwrap();
		let leaf = Leaf::create_leaf(&secrets, &publics, &pubkey, &params).unwrap();
		assert_eq!(leaf, commitment);

		// Since Nullifier = hash(commitment, pathIndices, privKey)
		let inputs_null = to_bytes![commitment, index, secrets.priv_key].unwrap();

		let ev_res = PoseidonCRH3::evaluate(&params, &inputs_null).unwrap();
		let nullifier = Leaf::create_nullifier(&secrets, &commitment, &params, &index).unwrap();
		assert_eq!(ev_res, nullifier);
	}
}
