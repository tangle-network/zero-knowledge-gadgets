use super::Set;
use crate::Vec;
use ark_crypto_primitives::Error;
use ark_ff::{bytes::ToBytes, fields::PrimeField, to_bytes};
use ark_std::marker::PhantomData;

#[cfg(feature = "r1cs")]
pub mod constraints;

#[derive(Clone)]
pub struct Private<F: PrimeField, const M: usize> {
	pub diffs: [F; M],
}

impl<F: PrimeField, const M: usize> Default for Private<F, M> {
	#[inline]
	fn default() -> Self {
		Self {
			diffs: [F::default(); M],
		}
	}
}

impl<F: PrimeField, const M: usize> Private<F, M> {
	pub fn new(diffs: &[F; M]) -> Self {
		Self { diffs: *diffs }
	}
}

#[derive(Clone)]
pub struct SetMembership<F: PrimeField, const M: usize> {
	field: PhantomData<F>,
}

impl<F: PrimeField, const M: usize> Set<F, M> for SetMembership<F, M> {
	type Private = Private<F, M>;

	fn generate_secrets<T: ToBytes>(target: &T, set: &[F; M]) -> Result<Self::Private, Error> {
		let target_bytes = to_bytes![target]?;
		let t = F::read(target_bytes.as_slice())?;
		let mut diffs = [F::default(); M];
		for (i, elem) in set.iter().enumerate() {
			diffs[i] = *elem - t;
		}
		Ok(Private::new(&diffs))
	}

	fn check<T: ToBytes>(target: &T, set: &[F; M], s: &Self::Private) -> Result<bool, Error> {
		let target_bytes = to_bytes![target]?;
		let target = F::read(target_bytes.as_slice())?;
		let mut product = target.clone();

		for (diff, real) in s.diffs.iter().zip(set.iter()) {
			if *real != (*diff + target) {
				return Ok(false);
			}
			product *= diff;
		}

		Ok(product == F::zero())
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use ark_bls12_381::Fq;
	use ark_ff::UniformRand;
	use ark_std::test_rng;

	pub const TEST_M: usize = 5;
	type TestSetMembership = SetMembership<Fq, TEST_M>;
	#[test]
	fn should_test_membership() {
		let rng = &mut test_rng();
		let root = Fq::rand(rng);
		let mut set = [Fq::rand(rng); TEST_M];
		set[0] = root;

		let s = TestSetMembership::generate_secrets(&root, &set).unwrap();
		let is_member = TestSetMembership::check(&root, &set, &s).unwrap();

		assert!(is_member);
	}

	#[test]
	fn should_not_test_membership() {
		let rng = &mut test_rng();
		let root = Fq::rand(rng);
		let mut set = [Fq::rand(rng); TEST_M];
		set[0] = root;

		let s = TestSetMembership::generate_secrets(&root, &set).unwrap();
		let random_element = Fq::rand(rng);
		let is_member = TestSetMembership::check(&random_element, &set, &s).unwrap();

		assert!(!is_member);
	}
}
