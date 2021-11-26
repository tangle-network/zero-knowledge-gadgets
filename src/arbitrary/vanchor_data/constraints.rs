use ark_ff::fields::PrimeField;
use ark_r1cs_std::{
	fields::fp::FpVar,
	prelude::{AllocVar, AllocationMode},
};
use ark_relations::r1cs::{Namespace, SynthesisError};
use core::borrow::Borrow;

use super::VAnchorArbitraryData;

#[derive(Clone)]
pub struct VAnchorArbitraryDataVar<F: PrimeField> {
	ext_data: FpVar<F>,
}

impl<F: PrimeField> VAnchorArbitraryDataVar<F> {
	pub fn new(ext_data: FpVar<F>) -> Self {
		Self { ext_data }
	}

	pub fn constrain(&self) -> Result<(), SynthesisError> {
		let _ = &self.ext_data * &self.ext_data;
		Ok(())
	}
}

impl<F: PrimeField> AllocVar<VAnchorArbitraryData<F>, F> for VAnchorArbitraryDataVar<F> {
	fn new_variable<T: Borrow<VAnchorArbitraryData<F>>>(
		into_ns: impl Into<Namespace<F>>,
		f: impl FnOnce() -> Result<T, SynthesisError>,
		mode: AllocationMode,
	) -> Result<Self, SynthesisError> {
		let input = f()?.borrow().clone();
		let ns = into_ns.into();
		let cs = ns.cs();

		let ext_data = input.ext_data.clone();

		let ext_data = FpVar::new_variable(cs.clone(), || Ok(&ext_data), mode)?;

		Ok(VAnchorArbitraryDataVar::new(ext_data))
	}
}

#[cfg(test)]
mod test {

	use crate::arbitrary::vanchor_data::VAnchorArbitraryData;

	use ark_relations::r1cs::ConstraintSystem;
	use ark_std::test_rng;

	use super::VAnchorArbitraryDataVar;
	use crate::ark_std::UniformRand;
	use ark_bn254::Fq;
	use ark_r1cs_std::alloc::AllocVar;
	#[test]
	fn should_enforce_constraints() {
		let rng = &mut test_rng();
		let cs = ConstraintSystem::<Fq>::new_ref();

		let ext_data = Fq::rand(rng);

		let data = VAnchorArbitraryData::new(ext_data);
		let data_var = VAnchorArbitraryDataVar::new_input(cs.clone(), || Ok(&data)).unwrap();

		data_var.constrain().unwrap();

		assert!(cs.is_satisfied().unwrap());
	}
}
