use crate::leaf::LeafCreation;
use ark_ff::{fields::PrimeField, to_bytes};
use ark_std::{marker::PhantomData, rand::Rng};
use webb_crypto_primitives::{crh::FixedLengthCRH, Error};

#[cfg(feature = "r1cs")]
pub mod constraints;

#[derive(Default, Clone)]
pub struct Private<F: PrimeField> {
	r: F,
	nullifier: F,
}

#[derive(Default, Clone)]
pub struct Public<F: PrimeField> {
	f: PhantomData<F>,
}

impl<F: PrimeField> Private<F> {
	pub fn generate<R: Rng>(rng: &mut R) -> Self {
		Self {
			r: F::rand(rng),
			nullifier: F::rand(rng),
		}
	}
}

struct BasicLeaf<F: PrimeField, H: FixedLengthCRH> {
	field: PhantomData<F>,
	hasher: PhantomData<H>,
}

impl<F: PrimeField, H: FixedLengthCRH> LeafCreation<H> for BasicLeaf<F, H> {
	type Output = H::Output;
	type Private = Private<F>;
	type Public = Public<F>;

	fn generate_secrets<R: Rng>(r: &mut R) -> Result<Self::Private, Error> {
		Ok(Self::Private::generate(r))
	}

	fn create(
		s: &Self::Private,
		_: &Self::Public,
		h: &H::Parameters,
	) -> Result<Self::Output, Error> {
		let mut buffer = vec![0u8; H::INPUT_SIZE_BITS / 8];
		let bytes = to_bytes![s.r, s.nullifier].unwrap();
		buffer.iter_mut().zip(bytes).for_each(|(b, l_b)| *b = l_b);
		H::evaluate(h, &buffer)
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::test_data::{get_mds_3, get_rounds_3};
	use ark_ed_on_bn254::Fq;
	use ark_ff::{to_bytes, Zero};
	use ark_std::test_rng;
	use webb_crypto_primitives::crh::poseidon::{
		sbox::PoseidonSbox, PoseidonParameters, Rounds, CRH,
	};

	#[derive(Default, Clone)]
	struct PoseidonRounds3;

	impl Rounds for PoseidonRounds3 {
		const FULL_ROUNDS: usize = 8;
		const PARTIAL_ROUNDS: usize = 57;
		const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
		const WIDTH: usize = 3;
	}

	type PoseidonCRH3 = CRH<Fq, PoseidonRounds3>;

	type Leaf = BasicLeaf<Fq, PoseidonCRH3>;
	#[test]
	fn should_create_leaf() {
		let rng = &mut test_rng();
		let secrets = Leaf::generate_secrets(rng).unwrap();
		let publics = Public::default();

		let inputs = to_bytes![secrets.r, secrets.nullifier, Fq::zero()].unwrap();

		let rounds = get_rounds_3::<Fq>();
		let mds = get_mds_3::<Fq>();
		let params = PoseidonParameters::<Fq>::new(rounds, mds);
		let ev_res = PoseidonCRH3::evaluate(&params, &inputs).unwrap();

		let res = Leaf::create(&secrets, &publics, &params).unwrap();
		assert_eq!(ev_res, res);
	}
}
