use crate::leaf::NewLeafCreation;
use crate::merkle_tree::{Path,SparseMerkleTree,Config};
use crate::poseidon::{PoseidonParameters};
use crate::utils::{get_mds_poseidon_bls381_x5_3, get_rounds_poseidon_bls381_x5_3};

use ark_crypto_primitives::{crh::CRH, Error};
use ark_ff::{fields::PrimeField, to_bytes};
use ark_std::test_rng;
use ark_std::{marker::PhantomData, rand::Rng};
use std::collections::BTreeMap;
//use std::convert::TryInto;
use std::vec::Vec;

//#[cfg(feature = "r1cs")]
//pub mod constraints;

#[derive(Clone)]
pub struct Private<F: PrimeField, P: Config, const N: usize> {
	r: F,
	nullifier: F,
	amount: F,
	blinding: F,
	priv_key: F,
	merkle_path: Path<P, N>,
}

#[derive(Default, Clone)]
pub struct Public<F: PrimeField> {
	f: PhantomData<F>,
	pubkey: F,

}
use ark_std::rc::Rc;
type InnerParameters<P> = <<P as Config>::H as CRH>::Parameters;
type LeafParameters<P> = <<P as Config>::LeafH as CRH>::Parameters;

fn create_merkle_tree<L: Default + ToBytes + Copy, C: Config>(
	inner_params: Rc<<C::H as CRH>::Parameters>,
	leaf_params: Rc<<C::LeafH as CRH>::Parameters>,
	leaves: &[L],
) -> SparseMerkleTree<C> {
	let pairs: BTreeMap<u32, L> = leaves
		.iter()
		.enumerate()
		.map(|(i, l)| (i as u32, *l))
		.collect();
	let smt = SparseMerkleTree::<C>::new(inner_params, leaf_params, &pairs).unwrap();

	smt
}
impl<F: PrimeField,P: Config, const N: usize> Private<F,P,N> {
	
	pub fn generate<R: Rng>(rng: &mut R) -> Self {
		
		let mut path = Vec::with_capacity(N);
		
		let rng = &mut test_rng();
		let rounds = get_rounds_poseidon_bls381_x5_3::<F>();
		let mds = get_mds_poseidon_bls381_x5_3::<F>();
		let params = PoseidonParameters::new(rounds, mds);
		let inner_params1 = Rc::new(params);
		let leaf_params1 = inner_params1.clone();
		let leaves = vec![F::rand(rng)];
		let smt =create_merkle_tree(inner_params1.clone(), leaf_params1.clone(),&leaves);
		let root = smt.root();

		//path.push((smt.empty_hashes[0], smt.empty_hashes[1]));
		//let mp = SparseMerkleTree::blank(inner_params1, leaf_params1);
		let path = smt.generate_membership_proof(0);
		Self {
			r: F::rand(rng),
			nullifier: F::rand(rng),
			amount: F::rand(rng),
			blinding: F::rand(rng),
			priv_key: F::rand(rng),
			merkle_path:path,
			// merkle_path: Path {
			// 				path: path.try_into()
			// 				.unwrap_or_else(|v: Vec<(Node<P>, Node<P>)>| {
			// 					panic!("Expected a Vec of length {} but it was {}", N, v.len())
			// 				}),
			// 				inner_params: Rc::clone(&inner_params),
			// 				leaf_params: Rc::clone(&leaf_params),
			// 				// TODO: Create the correct path
			// 			}

		}
	}
}

struct NewLeaf<F: PrimeField, H: CRH,> {
	field: PhantomData<F>,
	hasher: PhantomData<H>,
	//commitment: H::Output,

}
struct NewLeaf1<F: PrimeField, H1: CRH, H2: CRH, P: Config, const N: usize> {
	field: PhantomData<F>,
	hasher1: PhantomData<H1>,
	hasher2: PhantomData<H2>,
	configs: PhantomData<P>,
	//commitment: H::Output,

}
use ark_ff::{ToBytes};
use ark_std::io::{Result as IoResult,Write};
impl<P: Config, const N: usize> ToBytes for Path<P,N> {
	fn write<W: Write>(&self, writer: W) -> IoResult<()> {
			self.write(writer)
	}
}


impl<F: PrimeField, H1: CRH, H2: CRH, P: Config, const N: usize> NewLeafCreation<H1,H2> for NewLeaf1<F, H1, H2,P,N> {
	type Leaf = H1::Output; // Commitment
	type Nullifier = H2::Output;
	type Private = Private<F,P,N>;
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

	fn create_nullifier_hash(
		s: &Self::Private,
		c: &H1::Output, //the commitment
		h: &H2::Parameters,
	) -> Result<Self::Nullifier, Error> {
		let bytes = to_bytes![c, s.priv_key, s.merkle_path]?;
		H2::evaluate(h, &bytes)
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
	
	type SMTCRH = CRH<Fq, PoseidonRounds3>;

	#[derive(Default, Clone)]
	struct SMTConfig;
	impl Config for SMTConfig {
		type H = SMTCRH;
		type LeafH = SMTCRH;

		const HEIGHT: u8 = 3;
	}
	type PoseidonCRH3_1 = CRH<Fq, PoseidonRounds3_1>;
	type Nullifier1 = NewLeaf<Fq, PoseidonCRH3_1>;
	type Leaf = NewLeaf1<Fq, PoseidonCRH3,PoseidonCRH3_1,SMTConfig,3>;

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
	fn should_create_nullifier() {
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
		let inputs_null = to_bytes![commitment, secrets.priv_key, secrets.merkle_path].unwrap();

		let ev_res = PoseidonCRH3_1::evaluate(&params1, &inputs_null).unwrap();
		let nullifier = Leaf::create_nullifier_hash(&secrets, &commitment, &params1).unwrap();
		assert_eq!(ev_res, nullifier);
	}
}
