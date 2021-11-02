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
	chain_id: F,
	amount: F,
	blinding: F,
	priv_key: F,
	indices: Vec<u8>,
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
			chain_id: F::zero(),
			amount: F::rand(rng),
			blinding: F::rand(rng),
			priv_key: F::rand(rng),
			indices: vec!{0}
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

	// Commits to the values:=
	fn create_leaf(
		s: &Self::Private,
		p: &Self::Public,
		h: &H::Parameters,
	) -> Result<Self::Leaf, Error> {
		let bytes = to_bytes![s.chain_id,s.amount,s.blinding,p.pubkey]?;
		H::evaluate(h, &bytes)
	}
	fn create_nullifier_hash(
		s: &Self::Private,
		c: &Self::Leaf,
		h: &H::Parameters,
		f: &Vec<u8>,
	) -> Result<Self::Nullifier, Error> {
		let bytes = to_bytes![c, s.priv_key,f]?;
		H::evaluate(h, &bytes)
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
		const WIDTH: usize = 5;
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

		let inputs_leaf = to_bytes![secrets.chain_id,secrets.amount, secrets.blinding, publics.pubkey].unwrap();

		let rounds = get_rounds_poseidon_bls381_x5_5::<Fq>();
		let mds = get_mds_poseidon_bls381_x5_5::<Fq>();
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

		let inputs_leaf = to_bytes![secrets.chain_id,secrets.amount, secrets.blinding, publics.pubkey].unwrap();

		let rounds = get_rounds_poseidon_bls381_x5_5::<Fq>();
		let mds = get_mds_poseidon_bls381_x5_5::<Fq>();
		let params = PoseidonParameters::<Fq>::new(rounds, mds);
		
		let commitment = PoseidonCRH3::evaluate(&params, &inputs_leaf).unwrap();
		let leaf = Leaf::create_leaf(&secrets, &publics, &params).unwrap();
		assert_eq!(leaf, commitment);

		let rounds1 = get_rounds_poseidon_bls381_x5_5::<Fq>();
		let mds1 = get_mds_poseidon_bls381_x5_5::<Fq>();
		let params1 = PoseidonParameters::<Fq>::new(rounds1, mds1);
		let inputs_null = to_bytes![commitment, secrets.priv_key, secrets.indices].unwrap();

		let ev_res = PoseidonCRH3::evaluate(&params1, &inputs_null).unwrap();
		let nullifier = Leaf::create_nullifier_hash(&secrets, &commitment, 
			&params1,&secrets.indices).unwrap();
		assert_eq!(ev_res, nullifier);
	}
}
