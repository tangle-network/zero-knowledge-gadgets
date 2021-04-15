use super::Set;
use ark_ff::{bytes::ToBytes, fields::PrimeField, to_bytes};
use ark_std::marker::PhantomData;
use webb_crypto_primitives::Error;

#[cfg(feature = "r1cs")]
pub mod constraints;

#[derive(Default, Clone)]
pub struct Public<F: PrimeField> {
	pub target: F,
	pub set: Vec<F>,
}

impl<F: PrimeField> Public<F> {
	pub fn new(target: F, set: Vec<F>) -> Self {
		Self { target, set }
	}
}

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
	type Public = Public<F>;

	fn generate_secrets<T: ToBytes, I: IntoIterator<Item = F>>(
		target: &T,
		set: I,
	) -> Self::Private {
		let target_bytes = to_bytes![target].unwrap();
		let target = F::from_le_bytes_mod_order(&target_bytes);
		let arr: Vec<F> = set.into_iter().collect();
		let diffs = arr.iter().map(|x| *x - target).collect();
		Private::new(diffs)
	}

	fn check_membership(p: &Self::Public, s: &Self::Private) -> Result<bool, Error> {
		let mut product = p.target;
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

		let p = Public::new(root, set.clone());
		let s = TestSetMembership::generate_secrets(&root, set);
		let is_member = TestSetMembership::check_membership(&p, &s).unwrap();

		assert!(is_member);
	}
}
