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

pub struct VAnchorLeaf<F: PrimeField, H2: CRH, H4: CRH, H5: CRH> {
	field: PhantomData<F>,
	hasher2: PhantomData<H2>,
	hasher4: PhantomData<H4>,
	hasher5: PhantomData<H5>,
}

impl<F: PrimeField, H2: CRH, H4: CRH, H5: CRH> VAnchorLeaf<F, H2, H4, H5> {

	// Commits to the values = hash(chain_id, amount, pubKey, blinding)
	pub fn create_leaf(
		private: &Private<F>,
		public: &Public<F>,
		h_w2: &H2::Parameters,
		h_w5: &H5::Parameters,
	) -> Result<H5::Output, Error> {
		let bytes = to_bytes![private.priv_key]?;
		let pubk = H2::evaluate(h_w2, &bytes).unwrap();
		let bytes = to_bytes![public.chain_id, private.amount, pubk, private.blinding]?;
		H5::evaluate(h_w5, &bytes)
	}

	// Computes the nullifier = hash(commitment, pathIndices, privKey)
	fn create_nullifier(
		private: &Private<F>,
		commitment: &H5::Output,
		h_w4: &H4::Parameters,
		index: &F,
	) -> Result<H4::Output, Error> {
		let bytes = to_bytes![commitment, index, private.priv_key]?;
		H4::evaluate(h_w4, &bytes)
	}

	pub fn get_private_key(s: &Private<F>) -> Result<F, Error> {
		Ok(s.priv_key.clone())
	}

	fn gen_public_key(s: &Private<F>, h_w2: &H2::Parameters) -> Result<H2::Output, Error> {
		let bytes = to_bytes![s.priv_key]?;
		H2::evaluate(h_w2, &bytes)
	}
}

#[cfg(feature = "default_poseidon")]
#[cfg(test)]
mod test {
	use super::*;
	use crate::{
		poseidon::{sbox::PoseidonSbox, PoseidonParameters, Rounds, CRH},
		utils::{
			get_mds_poseidon_bls381_x5_5, get_mds_poseidon_bn254_x5_2, get_mds_poseidon_bn254_x5_5,
			get_rounds_poseidon_bls381_x5_5, get_rounds_poseidon_bn254_x5_2,
			get_rounds_poseidon_bn254_x5_5,
		},
	};
	//use ark_bls12_381::Fq;
	use ark_bn254::Fq;

	use ark_crypto_primitives::crh::CRH as CRHTrait;
	use ark_ff::to_bytes;
	use ark_std::test_rng;

	#[derive(Default, Clone)]
	struct PoseidonRounds2;

	impl Rounds for PoseidonRounds2 {
		const FULL_ROUNDS: usize = 8;
		const PARTIAL_ROUNDS: usize = 56;
		const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
		const WIDTH: usize = 2;
	}

	#[derive(Default, Clone)]
	struct PoseidonRounds4;

	impl Rounds for PoseidonRounds4 {
		const FULL_ROUNDS: usize = 8;
		const PARTIAL_ROUNDS: usize = 59;
		const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
		const WIDTH: usize = 4;
	}

	#[derive(Default, Clone)]
	struct PoseidonRounds5;

	impl Rounds for PoseidonRounds5 {
		const FULL_ROUNDS: usize = 8;
		const PARTIAL_ROUNDS: usize = 60;
		const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
		const WIDTH: usize = 5;
	}

	type PoseidonCRH2 = CRH<Fq, PoseidonRounds2>;
	type PoseidonCRH4 = CRH<Fq, PoseidonRounds4>;
	type PoseidonCRH5 = CRH<Fq, PoseidonRounds5>;

	type Leaf = VAnchorLeaf<Fq, PoseidonCRH2, PoseidonCRH4, PoseidonCRH5>;

	#[test]
	fn should_create_leaf() {
		let rng = &mut test_rng();
		let secrets = Private::generate(rng);
		let publics = Public::default();

		let rounds = get_rounds_poseidon_bn254_x5_5::<Fq>();
		let mds = get_mds_poseidon_bn254_x5_5::<Fq>();
		let params5 = PoseidonParameters::<Fq>::new(rounds, mds);
		let rounds = get_rounds_poseidon_bn254_x5_2::<Fq>();
		let mds = get_mds_poseidon_bn254_x5_2::<Fq>();
		let params2 = PoseidonParameters::<Fq>::new(rounds, mds);
		let privkey = to_bytes![secrets.priv_key].unwrap();
		let pubkey = PoseidonCRH2::evaluate(&params2, &privkey).unwrap();
		// Commitment = hash(chainID, amount, blinding, pubKey)
		let inputs_leaf =
			to_bytes![publics.chain_id, secrets.amount, pubkey, secrets.blinding].unwrap();
		let ev_res = PoseidonCRH5::evaluate(&params5, &inputs_leaf).unwrap();

		//TODO: change the params
		let leaf = Leaf::create_leaf(&secrets, &publics, &params2, &params5).unwrap();
		assert_eq!(ev_res, leaf);
	}
	use crate::ark_std::Zero;
	#[test]
	fn should_create_nullifier() {
		let rng = &mut test_rng();
		let secrets = Private::generate(rng);
		let chain_id = Fq::zero();
		let publics = Public::new(chain_id);
		let index = Fq::zero();

		let rounds = get_rounds_poseidon_bn254_x5_5::<Fq>();
		let mds = get_mds_poseidon_bn254_x5_5::<Fq>();
		let params = PoseidonParameters::<Fq>::new(rounds, mds);
		let privkey = to_bytes![secrets.priv_key].unwrap();
		let pubkey = PoseidonCRH2::evaluate(&params, &privkey).unwrap();
		// Since Commitment = hash(chainID, amount, blinding, pubKey)
		let inputs_leaf =
			to_bytes![publics.chain_id, secrets.amount, pubkey, secrets.blinding].unwrap();
		let commitment = PoseidonCRH5::evaluate(&params, &inputs_leaf).unwrap();

		//TODO: change the params
		let leaf = Leaf::create_leaf(&secrets, &publics, &params, &params).unwrap();
		assert_eq!(leaf, commitment);

		// Since Nullifier = hash(commitment, pathIndices, privKey)
		let inputs_null = to_bytes![commitment, index, secrets.priv_key].unwrap();
		let ev_res = PoseidonCRH4::evaluate(&params, &inputs_null).unwrap();
		let nullifier = Leaf::create_nullifier(&secrets, &commitment, &params, &index).unwrap();
		assert_eq!(ev_res, nullifier);
	}
}
