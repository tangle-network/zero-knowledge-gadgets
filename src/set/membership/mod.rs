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

impl<F: PrimeField, const M: usize> SetMembership<F, M> {
	pub fn generate_secrets<T: ToBytes>(target: &T, set: &[F; M]) -> Result<Private<F, M>, Error> {
		let target_bytes = to_bytes![target]?;
		let t = F::read(target_bytes.as_slice())?;
		let mut diffs = [F::default(); M];
		for (i, elem) in set.iter().enumerate() {
			diffs[i] = *elem - t;
		}
		Ok(Private::new(&diffs))
	}

	pub fn check<T: ToBytes>(target: &T, set: &[F; M], s: &Private<F, M>) -> Result<bool, Error> {
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

	fn check_is_enabled<T: ToBytes>(
		target: &T,
		set: &[F; M],
		s: &Self::Private,
		enabled: &F,
	) -> Result<bool, Error> {
		let target_bytes = to_bytes![target]?;
		let target = F::read(target_bytes.as_slice())?;
		let mut product = target.clone();
		let z = F::zero();
		for (diff, real) in s.diffs.iter().zip(set.iter()) {
			if z != ((*real - *diff - target) * enabled) {
				return Ok(false);
			}
			product *= diff;
		}
		let result = product * enabled;
		Ok(result == F::zero())
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
	use crate::ark_std::Zero;
	#[test]
	fn should_test_membership_with_is_enabled() {
		let rng = &mut test_rng();
		let root = Fq::rand(rng);
		let mut set = [Fq::rand(rng); TEST_M];
		set[0] = root;
		let not_enabled = Fq::zero();
		let random_element = Fq::rand(rng);

		let s = TestSetMembership::generate_secrets(&root, &set).unwrap();
		let is_member =
			TestSetMembership::check_is_enabled(&random_element, &set, &s, &not_enabled).unwrap();

		assert!(is_member);

		let is_enabled = Fq::rand(rng);
		let is_member = TestSetMembership::check_is_enabled(&root, &set, &s, &is_enabled).unwrap();

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

	#[test]
	fn should_not_test_membership_is_enabled() {
		let rng = &mut test_rng();
		let root = Fq::rand(rng);
		let mut set = [Fq::rand(rng); TEST_M];
		set[0] = root;

		//let not_enabled = Fq::zero();
		let is_enabled = Fq::rand(rng);

		let s = TestSetMembership::generate_secrets(&root, &set).unwrap();
		let random_element = Fq::rand(rng);
		let is_member =
			TestSetMembership::check_is_enabled(&random_element, &set, &s, &is_enabled).unwrap();

		assert!(!is_member);
	}
}
