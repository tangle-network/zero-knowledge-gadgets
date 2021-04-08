use super::Set;
use ark_ff::{bytes::ToBytes, fields::PrimeField, to_bytes};
use ark_std::marker::PhantomData;
use webb_crypto_primitives::Error;

#[cfg(feature = "r1cs")]
pub mod constraints;

#[derive(Default, Clone)]
pub struct Input<F: PrimeField> {
	pub diffs: Vec<F>,
	pub target: F,
	pub set: Vec<F>,
}

impl<F: PrimeField> Input<F> {
	pub fn new(target: F, diffs: Vec<F>, set: Vec<F>) -> Self {
		Self { target, diffs, set }
	}
}

#[derive(Clone)]
pub struct SetMembership<F: PrimeField> {
	field: PhantomData<F>,
}

impl<F: PrimeField> Set<F> for SetMembership<F> {
	type Input = Input<F>;

	fn generate_inputs<T: ToBytes, I: IntoIterator<Item = F>>(target: &T, set: I) -> Self::Input {
		let target_bytes = to_bytes![target].unwrap();
		let target = F::from_le_bytes_mod_order(&target_bytes);
		let arr: Vec<F> = set.into_iter().collect();
		let diffs = arr.iter().map(|x| *x - target).collect();
		Self::Input::new(target, diffs, arr)
	}

	fn check_membership(input: &Self::Input) -> Result<bool, Error> {
		let mut product = F::zero();
		for item in &input.diffs {
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

		let input = TestSetMembership::generate_inputs(&root, set);
		let is_member = TestSetMembership::check_membership(&input).unwrap();

		assert!(is_member);
	}
}
