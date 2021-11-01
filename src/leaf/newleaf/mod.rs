use crate::leaf::NewLeafCreation;
use ark_crypto_primitives::{crh::CRH, Error};
use ark_ff::{fields::PrimeField, to_bytes};

use ark_std::{marker::PhantomData, rand::Rng};
//use std::convert::TryInto;
use std::vec::Vec;

#[cfg(feature = "r1cs")]
pub mod constraints;

#[derive(Clone)]
pub struct Private<F: PrimeField> {
	amount: F,
	blinding: F,
	priv_key: F,
	indices: Vec<F>,
}

// #[derive(Clone)]
// pub struct nullifier<F: PrimeField>{
// 	val: PhantomData<F>
// }

#[derive(Default, Clone)]
pub struct Public<F: PrimeField> {
	f: PhantomData<F>,
	pubkey: F,

}
//type InnerParameters<P> = <<P as Config>::H as CRH>::Parameters;
//type LeafParameters<P> = <<P as Config>::LeafH as CRH>::Parameters;


impl<F: PrimeField> Private<F> {
	
	pub fn generate<R: Rng>(rng: &mut R) -> Self {

		Self {
			amount: F::rand(rng),
			blinding: F::rand(rng),
			priv_key: F::rand(rng),
			indices: vec!{F::zero()}
		}
	}
}

struct NewLeaf<F: PrimeField, H: CRH> {
	field: PhantomData<F>,
	hasher: PhantomData<H>,
	//configs: PhantomData<P>,
	//commitment: H::Output,

}

impl<F: PrimeField, H1: CRH> NewLeafCreation<H1> for NewLeaf<F, H1> {
	type Leaf = H1::Output; // Commitment
	type Private = Private<F>;
	type Public = Public<F>;

	// Creates Random Secrets: r, nullifier, amount, blinding, priv_key, merkle_path(TODO: merkle_path needs to be costructed) // TODO
	fn generate_secrets<R: Rng>(r: &mut R) -> Result<Self::Private, Error> {
		Ok(Self::Private::generate(r))
	}

	// Commits to the values:=
	fn create_leaf(
		s: &Self::Private,
		p: &Self::Public,
		h: &H1::Parameters,
	) -> Result<Self::Leaf, Error> {
		let bytes = to_bytes![s.amount,s.blinding,p.pubkey]?;
		H1::evaluate(h, &bytes)
	}

}


#[cfg(feature = "default_poseidon")]
#[cfg(test)]
mod test {
	use super::*;
	use crate::{
		poseidon::{sbox::PoseidonSbox, PoseidonParameters, Rounds, CRH},
		utils::{get_mds_poseidon_bls381_x5_3, get_rounds_poseidon_bls381_x5_3,
			get_mds_poseidon_bls381_x5_5, get_rounds_poseidon_bls381_x5_5},
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
	//type Leaf = NewLeaf<Fq, PoseidonCRH3>;

//222

#[derive(Default, Clone)]
	struct PoseidonRounds3_1;

	impl Rounds for PoseidonRounds3_1 {
		const FULL_ROUNDS: usize = 8;
		const PARTIAL_ROUNDS: usize = 57;
		const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
		const WIDTH: usize = 4;
	}
	
	type PoseidonCRH3_1 = CRH<Fq, PoseidonRounds3_1>;
	type Leaf = NewLeaf<Fq, PoseidonCRH3>;

	#[test]
	fn should_create_leaf() {
		let rng = &mut test_rng();
		let secrets = Leaf::generate_secrets(rng).unwrap();
		let publics = Public::default();

		let inputs_leaf = to_bytes![secrets.amount, secrets.blinding, publics.pubkey].unwrap();

		let rounds = get_rounds_poseidon_bls381_x5_3::<Fq>();
		let mds = get_mds_poseidon_bls381_x5_3::<Fq>();
		let params = PoseidonParameters::<Fq>::new(rounds, mds);
		let ev_res = PoseidonCRH3::evaluate(&params, &inputs_leaf).unwrap();

		let leaf = Leaf::create_leaf(&secrets, &publics, &params).unwrap();
		assert_eq!(ev_res, leaf);
	}
	#[test]
	fn should_create_nullifier() { //TODO: write the test
		let rng = &mut test_rng();
		let secrets = Leaf::generate_secrets(rng).unwrap();
		let publics = Public::default();

		let inputs_leaf = to_bytes![secrets.amount, secrets.blinding, publics.pubkey].unwrap();

		let rounds = get_rounds_poseidon_bls381_x5_3::<Fq>();
		let mds = get_mds_poseidon_bls381_x5_3::<Fq>();
		let params = PoseidonParameters::<Fq>::new(rounds, mds);
		
		let commitment = PoseidonCRH3::evaluate(&params, &inputs_leaf).unwrap();
		let leaf = Leaf::create_leaf(&secrets, &publics, &params).unwrap();
		assert_eq!(leaf, commitment);

		let rounds1 = get_rounds_poseidon_bls381_x5_5::<Fq>();
		let mds1 = get_mds_poseidon_bls381_x5_5::<Fq>();
		let params1 = PoseidonParameters::<Fq>::new(rounds1, mds1);
		let inputs_null = to_bytes![commitment, secrets.priv_key, secrets.indices].unwrap();

		let ev_res = PoseidonCRH3_1::evaluate(&params1, &inputs_null).unwrap();
		//let nullifier = create_nullifier_hash(&secrets, &commitment, &params1).unwrap();
		//assert_eq!(ev_res, nullifier);
	}
}
