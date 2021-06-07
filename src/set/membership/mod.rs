use super::Set;
use crate::Vec;
use ark_crypto_primitives::Error;
use ark_ff::{bytes::ToBytes, fields::PrimeField, to_bytes};
use ark_std::marker::PhantomData;

#[cfg(feature = "r1cs")]
pub mod constraints;

#[derive(Default, Clone)]
pub struct Private<F: PrimeField> {
	pub diffs: Vec<F>,
}

impl<F: PrimeField> Private<F> {
	pub fn new(diffs: Vec<F>) -> Self {
		Self { diffs }
	}
}

#[derive(Clone)]
pub struct SetMembership<F: PrimeField> {
	field: PhantomData<F>,
}

impl<F: PrimeField> Set<F> for SetMembership<F> {
	type Private = Private<F>;

	fn generate_secrets<T: ToBytes>(target: &T, set: &Vec<F>) -> Result<Self::Private, Error> {
		let target_bytes = to_bytes![target]?;
		let t = F::read(target_bytes.as_slice())?;
		let diffs = set.iter().map(|x| *x - t).collect();
		Ok(Private::new(diffs))
	}

	fn check<T: ToBytes>(target: &T, s: &Self::Private) -> Result<bool, Error> {
		let target_bytes = to_bytes![target]?;
		let mut product = F::read(target_bytes.as_slice())?;
		for item in &s.diffs {
			product *= item;
		}

		Ok(product == F::zero())
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use ark_ed_on_bn254::Fq;
	use ark_ff::UniformRand;
	use ark_std::test_rng;

	type TestSetMembership = SetMembership<Fq>;
	#[test]
	fn should_test_product() {
		let rng = &mut test_rng();
		let root = Fq::rand(rng);
		let mut set = vec![Fq::rand(rng); 5];
		set.push(root);

		let s = TestSetMembership::generate_secrets(&root, &set).unwrap();
		let is_member = TestSetMembership::check(&root, &s).unwrap();

		assert!(is_member);
	}
}
