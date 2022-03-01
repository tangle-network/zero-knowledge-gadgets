use ark_crypto_primitives::{crh::CRH, Error};
use ark_ff::{fields::PrimeField, to_bytes, ToBytes};

use ark_r1cs_std::fields::fp::FpVar;
use ark_std::{marker::PhantomData, rand::Rng};
use arkworks_utils::poseidon::PoseidonError;

use crate::poseidon::field_hasher::FieldHasher;

#[cfg(feature = "r1cs")]
pub mod constraints;

#[derive(Clone, Debug, Copy, Default)]
pub struct Private<F: PrimeField> {
	pub amount: F,
	blinding: F,
}

#[derive(Default, Clone, Copy, Debug)]
pub struct Public<F: PrimeField> {
	pub chain_id: F,
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

	pub fn new(amount: F, blinding: F) -> Self {
		Self { amount, blinding }
	}
}

pub struct VAnchorLeaf<F: PrimeField, H: FieldHasher<F>> {
	field: PhantomData<F>,
	hasher: PhantomData<H>,
}

impl<F: PrimeField, H: FieldHasher<F>> VAnchorLeaf<F, H> {
	// Commits to the values = hash(chain_id, amount, pubKey, blinding)
	pub fn create_leaf(
		private: &Private<F>,
		public: &Public<F>,
		public_key: &F,
		h_w5: &H,
	) -> Result<F, PoseidonError> {
		h_w5.hash(&[
			public.chain_id,
			private.amount,
			*public_key,
			private.blinding,
		])
	}

	// Computes the nullifier = hash(commitment, pathIndices, signature)
	pub fn create_nullifier(
		signature: &F,
		commitment: &F,
		index: &F,
		h_w4: &H,
	) -> Result<F, PoseidonError> {
		h_w4.hash(&[*commitment, *index, *signature])
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::{
		ark_std::{UniformRand, Zero},
		poseidon::{field_hasher::Poseidon, CRH},
	};
	use ark_std::vec::Vec;

	use arkworks_utils::utils::{
		common::{setup_params_x5_2, setup_params_x5_4, setup_params_x5_5, Curve},
		parse_vec,
	};

	use ark_ed_on_bn254::Fq;

	use ark_crypto_primitives::crh::CRH as CRHTrait;
	use ark_ff::{to_bytes, BigInteger};
	use ark_std::test_rng;

	type PoseidonCRH = CRH<Fq>;

	type Leaf = VAnchorLeaf<Fq, Poseidon<Fq>>;
	#[test]
	fn should_create_leaf() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;

		let secrets = Private::generate(rng);
		let publics = Public::default();
		let private_key = Fq::rand(rng);

		let params2 = setup_params_x5_2(curve);
		let params5 = setup_params_x5_5(curve);
		let hasher2 = Poseidon::<Fq>::new(params2);
		let hasher5 = Poseidon::<Fq>::new(params5);

		let pubkey = hasher2.hash(&[private_key]).unwrap();
		// Commitment = hash(chainID, amount, blinding, pubKey)
		let ev_res = hasher5
			.hash(&[publics.chain_id, secrets.amount, pubkey, secrets.blinding])
			.unwrap();

		let leaf = Leaf::create_leaf(&secrets, &publics, &pubkey, &hasher5).unwrap();
		assert_eq!(ev_res, leaf);
	}
	#[test]
	fn should_create_nullifier() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;

		let secrets = Private::generate(rng);
		let chain_id = Fq::zero();
		let publics = Public::new(chain_id);
		let index = Fq::zero();
		let private_key = Fq::rand(rng);

		let params2 = setup_params_x5_2(curve);
		let params4 = setup_params_x5_4(curve);
		let params5 = setup_params_x5_5(curve);
		let hasher2 = Poseidon::<Fq>::new(params2);
		let hasher4 = Poseidon::<Fq>::new(params4);
		let hasher5 = Poseidon::<Fq>::new(params5);

		let pubkey = hasher2.hash(&[private_key]).unwrap();
		// Since Commitment = hash(chainID, amount, blinding, pubKey)
		let inputs_leaf =
			to_bytes![publics.chain_id, secrets.amount, pubkey, secrets.blinding].unwrap();
		let commitment = hasher5
			.hash(&[publics.chain_id, secrets.amount, pubkey, secrets.blinding])
			.unwrap();

		let leaf = Leaf::create_leaf(&secrets, &publics, &pubkey, &hasher5).unwrap();
		assert_eq!(leaf, commitment);

		// Since Nullifier = hash(commitment, pathIndices, privKey)
		let signature = Fq::rand(rng);
		let ev_res = hasher4.hash(&[commitment, index, signature]).unwrap();
		let nullifier = Leaf::create_nullifier(&signature, &commitment, &index, &hasher4).unwrap();
		assert_eq!(ev_res, nullifier);
	}

	type LeafCircom = VAnchorLeaf<Fq, Poseidon<Fq>>;

	#[test]
	fn should_be_the_same_as_circom() {
		let curve = Curve::Bn254;

		let parameters2 = setup_params_x5_2(curve);
		let parameters4 = setup_params_x5_4(curve);
		let parameters5 = setup_params_x5_5(curve);
		let hasher2 = Poseidon::<Fq>::new(parameters2);
		let hasher4 = Poseidon::<Fq>::new(parameters4);
		let hasher5 = Poseidon::<Fq>::new(parameters5);

		let private_key: Vec<Fq> = parse_vec(vec![
			"0xb2ac10dccfb5a5712d632464a359668bb513e80e9d145ab5a88381de83af1046",
		]);

		// Expected public key (from CIRCOM)
		let expected_public_key: Vec<Fq> = parse_vec(vec![
			"0x07a1f74bf9feda741e1e9099012079df28b504fc7a19a02288435b8e02ae21fa",
		]);

		let input = private_key[0].into_repr().to_bytes_le();

		let computed_public_key = hasher2.hash(&[private_key[0]]).unwrap();

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
		let computed_leaf_without_vanchorleaf = hasher5
			.hash(&[chain_id[0], amount[0], expected_public_key[0], blinding[0]])
			.unwrap();

		// Computing the leaf with vanchorleaf
		let private = Private::new(amount[0], blinding[0]);
		let public = Public::new(chain_id[0]);
		let leaf_from_vanchorleaf =
			LeafCircom::create_leaf(&private, &public, &computed_public_key, &hasher5).unwrap();

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

		let computed_nullifier_without_vanchorleaf = hasher4
			.hash(&[
				expected_leaf[0],
				path_index[0],
				// TODO: Change to signature
				private_key[0],
			])
			.unwrap();

		// Computing the nullifier with vanchorleaf
		let nullifier_from_vanchorleaf = LeafCircom::create_nullifier(
			// TODO: Change to signature
			&private_key[0],
			&leaf_from_vanchorleaf,
			&path_index[0],
			&hasher4,
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
