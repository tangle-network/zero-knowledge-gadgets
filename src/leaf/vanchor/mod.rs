use ark_crypto_primitives::{crh::CRH, Error};
use ark_ff::{fields::PrimeField, to_bytes, ToBytes};

use ark_std::{marker::PhantomData, rand::Rng};
//use std::convert::TryInto;
//use std::vec::Vec;

#[cfg(feature = "r1cs")]
pub mod constraints;

#[derive(Clone)]
pub struct Private<F: PrimeField> {
	amount: F,
	blinding: F,
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
		}
	}

	pub fn new(amount: &F, blinding: &F) -> Self {
		let amount = amount.clone();
		let blinding = blinding.clone();
		Self { amount, blinding }
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
	pub fn create_leaf<B: ToBytes>(
		private: &Private<F>,
		public_key: &B,
		public: &Public<F>,
		h_w5: &H5::Parameters,
	) -> Result<H5::Output, Error> {
		let bytes = to_bytes![
			public.chain_id,
			private.amount,
			public_key,
			private.blinding
		]?;
		H5::evaluate(h_w5, &bytes)
	}

	// Computes the nullifier = hash(commitment, pathIndices, privKey)
	pub fn create_nullifier<B: ToBytes>(
		private_key: &B,
		commitment: &H5::Output,
		h_w4: &H4::Parameters,
		index: &F,
	) -> Result<H4::Output, Error> {
		let bytes = to_bytes![commitment, index, private_key]?;
		H4::evaluate(h_w4, &bytes)
	}
}

#[cfg(feature = "default_poseidon")]
#[cfg(test)]
mod test {
	use super::*;
	use crate::{
		poseidon::{circom::CircomCRH, sbox::PoseidonSbox, PoseidonParameters, Rounds, CRH},
		utils::{
			get_mds_poseidon_bn254_x5_2, get_mds_poseidon_bn254_x5_4, get_mds_poseidon_bn254_x5_5,
			get_rounds_poseidon_bn254_x5_2, get_rounds_poseidon_bn254_x5_4,
			get_rounds_poseidon_bn254_x5_5, parse_vec,
		},
	};
	//use ark_bls12_381::Fq;
	//use ark_bn254::Fq;
	use ark_ed_on_bn254::Fq;

	use ark_crypto_primitives::crh::CRH as CRHTrait;
	use ark_ff::{to_bytes, BigInteger};
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
		const PARTIAL_ROUNDS: usize = 56;
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
	use crate::ark_std::UniformRand;
	#[test]
	fn should_create_leaf() {
		let rng = &mut test_rng();
		let secrets = Private::generate(rng);
		let publics = Public::default();
		let private_key = Fq::rand(rng);
		let rounds = get_rounds_poseidon_bn254_x5_5::<Fq>();
		let mds = get_mds_poseidon_bn254_x5_5::<Fq>();
		let params5 = PoseidonParameters::<Fq>::new(rounds, mds);
		let rounds = get_rounds_poseidon_bn254_x5_2::<Fq>();
		let mds = get_mds_poseidon_bn254_x5_2::<Fq>();
		let params2 = PoseidonParameters::<Fq>::new(rounds, mds);
		let privkey = to_bytes![private_key].unwrap();
		let pubkey = PoseidonCRH2::evaluate(&params2, &privkey).unwrap();
		// Commitment = hash(chainID, amount, blinding, pubKey)
		let inputs_leaf =
			to_bytes![publics.chain_id, secrets.amount, pubkey, secrets.blinding].unwrap();
		let ev_res = PoseidonCRH5::evaluate(&params5, &inputs_leaf).unwrap();

		//TODO: change the params
		let leaf = Leaf::create_leaf(&secrets, &pubkey, &publics, &params5).unwrap();
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
		let private_key = Fq::rand(rng);
		let rounds = get_rounds_poseidon_bn254_x5_2::<Fq>();
		let mds = get_mds_poseidon_bn254_x5_2::<Fq>();
		let params2 = PoseidonParameters::<Fq>::new(rounds, mds);
		let rounds = get_rounds_poseidon_bn254_x5_4::<Fq>();
		let mds = get_mds_poseidon_bn254_x5_4::<Fq>();
		let params4 = PoseidonParameters::<Fq>::new(rounds, mds);
		let rounds = get_rounds_poseidon_bn254_x5_5::<Fq>();
		let mds = get_mds_poseidon_bn254_x5_5::<Fq>();
		let params5 = PoseidonParameters::<Fq>::new(rounds, mds);
		let privkey = to_bytes![private_key].unwrap();
		let pubkey = PoseidonCRH2::evaluate(&params2, &privkey).unwrap();
		// Since Commitment = hash(chainID, amount, blinding, pubKey)
		let inputs_leaf =
			to_bytes![publics.chain_id, secrets.amount, pubkey, secrets.blinding].unwrap();
		let commitment = PoseidonCRH5::evaluate(&params5, &inputs_leaf).unwrap();

		//TODO: change the params
		let leaf = Leaf::create_leaf(&secrets, &pubkey, &publics, &params5).unwrap();
		assert_eq!(leaf, commitment);

		// Since Nullifier = hash(commitment, pathIndices, privKey)
		let inputs_null = to_bytes![commitment, index, private_key].unwrap();
		let ev_res = PoseidonCRH4::evaluate(&params4, &inputs_null).unwrap();
		let nullifier = Leaf::create_nullifier(&private_key, &commitment, &params4, &index).unwrap();
		assert_eq!(ev_res, nullifier);
	}

	#[derive(Default, Clone)]
	struct PoseidonCircomRounds2;
	impl Rounds for PoseidonCircomRounds2 {
		const FULL_ROUNDS: usize = 8;
		const PARTIAL_ROUNDS: usize = 56;
		const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
		const WIDTH: usize = 2;
	}

	#[derive(Default, Clone)]
	struct PoseidonCircomRounds4;
	impl Rounds for PoseidonCircomRounds4 {
		const FULL_ROUNDS: usize = 8;
		const PARTIAL_ROUNDS: usize = 56;
		const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
		const WIDTH: usize = 4;
	}

	#[derive(Default, Clone)]
	struct PoseidonCircomRounds5;
	impl Rounds for PoseidonCircomRounds5 {
		const FULL_ROUNDS: usize = 8;
		const PARTIAL_ROUNDS: usize = 60;
		const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
		const WIDTH: usize = 5;
	}

	type PoseidonCircomCRH4 = CircomCRH<Fq, PoseidonCircomRounds4>;
	type PoseidonCircomCRH2 = CircomCRH<Fq, PoseidonCircomRounds2>;
	type PoseidonCircomCRH5 = CircomCRH<Fq, PoseidonCircomRounds5>;

	type LeafCircom = VAnchorLeaf<Fq, PoseidonCircomCRH2, PoseidonCircomCRH4, PoseidonCircomCRH5>;

	#[test]
	fn should_be_the_same_as_circom() {
		let round_keys = get_rounds_poseidon_bn254_x5_2::<Fq>();
		let mds_matrix = get_mds_poseidon_bn254_x5_2::<Fq>();
		let parameters2 = PoseidonParameters::<Fq>::new(round_keys, mds_matrix);

		let round_keys = get_rounds_poseidon_bn254_x5_4::<Fq>();
		let mds_matrix = get_mds_poseidon_bn254_x5_4::<Fq>();
		let parameters4 = PoseidonParameters::<Fq>::new(round_keys, mds_matrix);

		let round_keys = get_rounds_poseidon_bn254_x5_5::<Fq>();
		let mds_matrix = get_mds_poseidon_bn254_x5_5::<Fq>();
		let parameters5 = PoseidonParameters::<Fq>::new(round_keys, mds_matrix);

		let private_key: Vec<Fq> = parse_vec(vec![
			"0xb2ac10dccfb5a5712d632464a359668bb513e80e9d145ab5a88381de83af1046",
		]);

		// Expected public key (from CIRCOM)
		let expected_public_key: Vec<Fq> = parse_vec(vec![
			"0x07a1f74bf9feda741e1e9099012079df28b504fc7a19a02288435b8e02ae21fa",
		]);

		let input = private_key[0].into_repr().to_bytes_le();

		let computed_public_key = PoseidonCircomCRH2::evaluate(&parameters2, &input).unwrap();

		assert_eq!(
			expected_public_key[0], computed_public_key,
			"{} != {}",
			expected_public_key[0], computed_public_key
		);

		// Creat Leaf (Commitment)
		let chain_id: Vec<Fq> = parse_vec(vec![
			"0x0000000000000000000000000000000000000000000000000000000000007a69",
		]);
		let amount: Vec<Fq> = parse_vec(vec![
			"0x0000000000000000000000000000000000000000000000000000000000989680",
		]);
		let blinding: Vec<Fq> = parse_vec(vec![
			"0x00a668ba0dcb34960aca597f433d0d3289c753046afa26d97e1613148c05f2c0",
		]);

		// Expected commitment (from CIRCOM)
		let expected_leaf: Vec<Fq> = parse_vec(vec![
			"0x15206d966a7fb3e3fbbb7f4d7b623ca1c7c9b5c6e6d0a3348df428189441a1e4",
		]);

		// Computing the leaf without vanchorleaf
		let mut input = chain_id[0].into_repr().to_bytes_le();
		let mut tmp = amount[0].into_repr().to_bytes_le();
		input.append(&mut tmp);
		let mut tmp = expected_public_key[0].into_repr().to_bytes_le();
		input.append(&mut tmp);
		let mut tmp = blinding[0].into_repr().to_bytes_le();
		input.append(&mut tmp);
		let computed_leaf_without_vanchorleaf = PoseidonCircomCRH5::evaluate(&parameters5, &input).unwrap();

		// Computing the leaf with vanchorleaf
		let private = Private::new(&amount[0], &blinding[0]);
		let public = Public::new(chain_id[0]);
		let leaf_from_vanchorleaf =
			LeafCircom::create_leaf(&private, &computed_public_key, &public, &parameters5).unwrap();

		assert_eq!(
			expected_leaf[0], computed_leaf_without_vanchorleaf,
			"{} != {}",
			expected_leaf[0], computed_leaf_without_vanchorleaf
		);

		assert_eq!(
			expected_leaf[0], leaf_from_vanchorleaf,
			"{} != {}",
			expected_leaf[0], leaf_from_vanchorleaf
		);

		let path_index: Vec<Fq> = parse_vec(vec![
			"0x0000000000000000000000000000000000000000000000000000000000000000",
		]);
		// Expected nullifier (from CIRCOM)
		let expected_nullifier: Vec<Fq> = parse_vec(vec![
			"0x21423c7374ce5b3574f04f92243449359ae3865bb8e34cb2b7b5e4187ba01fca",
		]);

		// Computing the nullifier without vanchorleaf
		let mut input = expected_leaf[0].into_repr().to_bytes_le();
		let mut tmp = path_index[0].into_repr().to_bytes_le();
		input.append(&mut tmp);

		let mut tmp = private_key[0].into_repr().to_bytes_le();
		input.append(&mut tmp);

		let computed_nullifier_without_vanchorleaf = PoseidonCircomCRH4::evaluate(&parameters4, &input).unwrap();

		// Computing the nullifier with vanchorleaf
		let nullifier_from_vanchorleaf = LeafCircom::create_nullifier(
			&private_key,
			&leaf_from_vanchorleaf,
			&parameters4,
			&path_index[0],
		)
		.unwrap();

		assert_eq!(
			expected_nullifier[0], computed_nullifier_without_vanchorleaf,
			"{} != {}",
			expected_nullifier[0], computed_nullifier_without_vanchorleaf
		);

		assert_eq!(
			expected_nullifier[0], nullifier_from_vanchorleaf,
			"{} != {}",
			expected_nullifier[0], nullifier_from_vanchorleaf
		);
	}
}
