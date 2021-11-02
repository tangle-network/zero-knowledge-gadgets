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
	index: F,
}

// #[derive(Clone)]
// pub struct nullifier<F: PrimeField>{
// 	val: PhantomData<F>
// }

#[derive(Default, Clone)]
pub struct Public<F: PrimeField> {
	pubkey: F,

}

impl<F: PrimeField> Private<F> {
	
	pub fn generate<R: Rng>(rng: &mut R) -> Self {

		Self {
			amount: F::rand(rng),
			blinding: F::rand(rng),
			priv_key: F::rand(rng),
			index: F::zero()
		}
	}
}

struct NewLeaf<F: PrimeField, H: CRH> {
	field: PhantomData<F>,
	hasher: PhantomData<H>,
	//configs: PhantomData<P>,
	//commitment: H::Output,

}

impl<F: PrimeField, H: CRH> NewLeafCreation<H> for NewLeaf<F, H> {
	type Leaf = H::Output; // Commitment = hash(amount, blinding, pubKey)
	type Nullifier = H::Output; // Nullifier = hash(commitment, pathIndices, privKey)
	type Private = Private<F>;
	type Public = Public<F>;

	// Creates Random Secrets: r, nullifier, amount, blinding, priv_key, merkle_path(TODO: merkle_path needs to be costructed) // TODO
	fn generate_secrets<R: Rng>(r: &mut R) -> Result<Self::Private, Error> {
		Ok(Self::Private::generate(r))
	}

	// Commits to the values = hash(amount, blinding, pubKey)
	fn create_leaf(
		s: &Self::Private,
		p: &Self::Public,
		h: &H::Parameters,
	) -> Result<Self::Leaf, Error> {
		let bytes = to_bytes![s.amount,s.blinding,p.pubkey]?;
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
		// Commitment = hash(amount, blinding, pubKey)
		let inputs_leaf = to_bytes![secrets.amount, secrets.blinding, publics.pubkey].unwrap();

		let rounds = get_rounds_poseidon_bls381_x5_5::<Fq>();
		let mds = get_mds_poseidon_bls381_x5_5::<Fq>();
		let params = PoseidonParameters::<Fq>::new(rounds, mds);
		let ev_res = PoseidonCRH3::evaluate(&params, &inputs_leaf).unwrap();

		let leaf = Leaf::create_leaf(&secrets, &publics, &params).unwrap();
		assert_eq!(ev_res, leaf);
	}
	#[test]
	fn should_create_nullifier() { 
		let rng = &mut test_rng();
		let secrets = Leaf::generate_secrets(rng).unwrap();
		let publics = Public::default();
		
		// Since Commitment = hash(amount, blinding, pubKey)
		let inputs_leaf = to_bytes![secrets.amount, secrets.blinding, publics.pubkey].unwrap();

		let rounds = get_rounds_poseidon_bls381_x5_5::<Fq>();
		let mds = get_mds_poseidon_bls381_x5_5::<Fq>();
		let params = PoseidonParameters::<Fq>::new(rounds, mds);
		
		let commitment = PoseidonCRH3::evaluate(&params, &inputs_leaf).unwrap();
		let leaf = Leaf::create_leaf(&secrets, &publics, &params).unwrap();
		assert_eq!(leaf, commitment);
		
		// Since Nullifier = hash(commitment, pathIndices, privKey)
		let inputs_null = to_bytes![commitment,  secrets.index, secrets.priv_key].unwrap();

		let ev_res = PoseidonCRH3::evaluate(&params, &inputs_null).unwrap();
		let nullifier = Leaf::create_nullifier(&secrets, &commitment, 
			&params,&secrets.index).unwrap();
		assert_eq!(ev_res, nullifier);
	}
}
