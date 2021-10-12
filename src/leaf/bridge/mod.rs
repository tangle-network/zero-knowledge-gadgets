use crate::leaf::LeafCreation;
use ark_crypto_primitives::{crh::CRH, Error};
use ark_ff::{fields::PrimeField, to_bytes, ToBytes};
use ark_std::{
	io::{Result as IoResult, Write},
	marker::PhantomData,
	rand::Rng,
};

#[cfg(feature = "r1cs")]
pub mod constraints;

#[derive(Default, Clone)]
pub struct Private<F: PrimeField> {
	r: F,
	nullifier: F,
	rho: F,
}

impl<F: PrimeField> Private<F> {
	pub fn generate<R: Rng>(rng: &mut R) -> Self {
		Self {
			r: F::rand(rng),
			nullifier: F::rand(rng),
			rho: F::rand(rng),
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

#[derive(Clone, Eq, PartialEq, Debug, Hash, Default)]
pub struct Output<F: PrimeField> {
	pub leaf: F,
	pub nullifier_hash: F,
}

impl<F: PrimeField> ToBytes for Output<F> {
	fn write<W: Write>(&self, mut writer: W) -> IoResult<()> {
		writer.write_all(&to_bytes![self.leaf].unwrap())?;
		writer.write_all(&to_bytes![self.nullifier_hash].unwrap())?;
		Ok(())
	}
}

#[derive(Clone)]
pub struct BridgeLeaf<F: PrimeField, H: CRH> {
	field: PhantomData<F>,
	hasher: PhantomData<H>,
}

impl<F: PrimeField, H: CRH> LeafCreation<H> for BridgeLeaf<F, H> {
	type Leaf = H::Output;
	type Nullifier = H::Output;
	type Private = Private<F>;
	type Public = Public<F>;

	fn generate_secrets<R: Rng>(r: &mut R) -> Result<Self::Private, Error> {
		Ok(Self::Private::generate(r))
	}

	fn create_leaf(
		s: &Self::Private,
		p: &Self::Public,
		h: &H::Parameters,
	) -> Result<Self::Leaf, Error> {
		let input_bytes = to_bytes![s.r, s.nullifier, s.rho, p.chain_id]?;
		H::evaluate(h, &input_bytes)
	}

	fn create_nullifier_hash(
		s: &Self::Private,
		h: &H::Parameters,
	) -> Result<Self::Nullifier, Error> {
		let nullifier_bytes = to_bytes![s.nullifier, s.nullifier]?;
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
		let secrets = Leaf::generate_secrets(rng).unwrap();

		let chain_id = Fq::one();
		let publics = Public::new(chain_id);

		let leaf_inputs =
			to_bytes![secrets.r, secrets.nullifier, secrets.rho, publics.chain_id].unwrap();

		let nullifier_inputs = to_bytes![secrets.nullifier, secrets.nullifier].unwrap();

		let rounds = get_rounds_poseidon_bls381_x5_5::<Fq>();
		let mds = get_mds_poseidon_bls381_x5_5::<Fq>();
		let params = PoseidonParameters::<Fq>::new(rounds, mds);
		let leaf_res = PoseidonCRH5::evaluate(&params, &leaf_inputs).unwrap();
		let nullifier_res = PoseidonCRH5::evaluate(&params, &nullifier_inputs).unwrap();

		let leaf = Leaf::create_leaf(&secrets, &publics, &params).unwrap();
		let nullifier_hash = Leaf::create_nullifier_hash(&secrets, &params).unwrap();
		assert_eq!(leaf_res, leaf);
		assert_eq!(nullifier_res, nullifier_hash);
	}
}
