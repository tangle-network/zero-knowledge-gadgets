use super::Set;
use ark_ff::fields::PrimeField;
use ark_std::marker::PhantomData;
use webb_crypto_primitives::Error;

#[cfg(feature = "r1cs")]
pub mod constraints;

#[derive(Default, Clone)]
pub struct Input<F: PrimeField> {
	diffs: Vec<F>,
	target: F,
	set: Vec<F>,
}

impl<F: PrimeField> Input<F> {
	pub fn new(target: F, diffs: Vec<F>, set: Vec<F>) -> Self {
		Self { target, diffs, set }
	}
}

struct SetMembership<F: PrimeField> {
	field: PhantomData<F>,
}

impl<F: PrimeField> Set<F> for SetMembership<F> {
	type Input = Input<F>;
	type Output = F;

	fn generate_inputs<I: IntoIterator<Item = F>>(target: F, set: I) -> Self::Input {
		let arr: Vec<F> = set.into_iter().collect();
		let diffs = arr.iter().map(|x| *x - target).collect();
		Self::Input::new(target, diffs, arr)
	}

	fn product(input: &Self::Input) -> Result<Self::Output, Error> {
		let mut product = F::zero();
		for item in &input.diffs {
			product *= item;
		}

		Ok(product)
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use ark_ed_on_bn254::Fq;
	use ark_ff::{UniformRand, Zero};
	use ark_std::test_rng;

	type TestSetMembership = SetMembership<Fq>;
	#[test]
	fn should_test_product() {
		let rng = &mut test_rng();
		let root = Fq::rand(rng);
		let mut set = vec![Fq::rand(rng); 5];
		set.push(root);

		let input = TestSetMembership::generate_inputs(root, set);
		let product = TestSetMembership::product(&input).unwrap();

		assert_eq!(product, Fq::zero());
	}
}
