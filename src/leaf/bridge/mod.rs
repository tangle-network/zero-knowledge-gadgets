use crate::leaf::LeafCreation;
use ark_ff::{fields::PrimeField, to_bytes, ToBytes};
use ark_std::{
	io::{Result as IoResult, Write},
	marker::PhantomData,
	rand::Rng,
};
use webb_crypto_primitives::{
	crh::{poseidon::to_field_bytes, FixedLengthCRH},
	Error,
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

impl<F: PrimeField> Output<F> {
	pub fn new(leaf: F, nullifier_hash: F) -> Self {
		Self {
			leaf,
			nullifier_hash,
		}
	}
}

impl<F: PrimeField> ToBytes for Output<F> {
	fn write<W: Write>(&self, mut writer: W) -> IoResult<()> {
		writer.write(&to_bytes![self.leaf].unwrap())?;
		writer.write(&to_bytes![self.nullifier_hash].unwrap())?;
		Ok(())
	}
}

#[derive(Clone)]
pub struct BridgeLeaf<F: PrimeField, H: FixedLengthCRH> {
	field: PhantomData<F>,
	hasher: PhantomData<H>,
}

impl<F: PrimeField, H: FixedLengthCRH> LeafCreation<H> for BridgeLeaf<F, H> {
	type Output = Output<F>;
	type Private = Private<F>;
	type Public = Public<F>;

	fn generate_secrets<R: Rng>(r: &mut R) -> Result<Self::Private, Error> {
		Ok(Self::Private::generate(r))
	}

	fn create(
		s: &Self::Private,
		p: &Self::Public,
		h: &H::Parameters,
	) -> Result<Self::Output, Error> {
		// Leaf hash
		let mut leaf_buffer = vec![0u8; H::INPUT_SIZE_BITS / 8];
		let input_bytes = to_field_bytes(&[s.r, s.nullifier, s.rho, p.chain_id]);
		leaf_buffer
			.iter_mut()
			.zip(input_bytes)
			.for_each(|(b, l_b)| *b = l_b);
		let leaf_res = H::evaluate(h, &leaf_buffer)?;
		let leaf_bytes = to_bytes![leaf_res]?;
		let leaf = F::from_le_bytes_mod_order(&leaf_bytes[..32]);

		// Nullifier hash
		let mut nullifier_hash_buffer = vec![0u8; H::INPUT_SIZE_BITS / 8];
		let nullifier_bytes = to_field_bytes(&[s.nullifier]);
		nullifier_hash_buffer
			.iter_mut()
			.zip(nullifier_bytes)
			.for_each(|(b, l_b)| *b = l_b);
		let nullifier_hash_res = H::evaluate(h, &nullifier_hash_buffer)?;

		let nullifier_hash_bytes = to_bytes![nullifier_hash_res]?;
		let nullifier_hash = F::from_le_bytes_mod_order(&nullifier_hash_bytes[..32]);

		Ok(Self::Output::new(leaf, nullifier_hash))
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::test_data::{get_mds_5, get_rounds_5};
	use ark_ed_on_bn254::Fq;
	use ark_ff::{to_bytes, One, Zero};
	use ark_std::test_rng;
	use webb_crypto_primitives::crh::poseidon::{
		sbox::PoseidonSbox, to_field_bytes, PoseidonParameters, Rounds, CRH,
	};

	#[derive(Default, Clone)]
	struct PoseidonRounds5;

	impl Rounds for PoseidonRounds5 {
		const FULL_ROUNDS: usize = 8;
		const PARTIAL_ROUNDS: usize = 57;
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
			to_field_bytes(&[secrets.r, secrets.nullifier, secrets.rho, publics.chain_id]);

		let nullifier_inputs = to_field_bytes(&[secrets.nullifier]);

		let rounds = get_rounds_5::<Fq>();
		let mds = get_mds_5::<Fq>();
		let params = PoseidonParameters::<Fq>::new(rounds, mds);
		let leaf_res = PoseidonCRH5::evaluate(&params, &leaf_inputs).unwrap();
		let nullifier_res = PoseidonCRH5::evaluate(&params, &nullifier_inputs).unwrap();

		let res = Leaf::create(&secrets, &publics, &params).unwrap();
		assert_eq!(leaf_res, res.leaf);
		assert_eq!(nullifier_res, res.nullifier_hash);
	}
}
