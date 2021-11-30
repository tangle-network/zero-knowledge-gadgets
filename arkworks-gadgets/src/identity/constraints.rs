use super::CRH;
use ark_crypto_primitives::crh::constraints::CRHGadget as CRHGadgetTrait;
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, prelude::*, uint8::UInt8};
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::{marker::PhantomData, vec::Vec};
use arkworks_utils::utils::to_field_var_elements;
use core::borrow::Borrow;

pub struct CRHGadget<F: PrimeField> {
	field: PhantomData<F>,
}

#[derive(Clone, Default)]
pub struct Params<F: PrimeField> {
	field: PhantomData<F>,
}

impl<F: PrimeField> CRHGadgetTrait<CRH<F>, F> for CRHGadget<F> {
	type OutputVar = FpVar<F>;
	type ParametersVar = Params<F>;

	fn evaluate(
		_: &Self::ParametersVar,
		input: &[UInt8<F>],
	) -> Result<Self::OutputVar, SynthesisError> {
		let f_var_inputs: Vec<FpVar<F>> = to_field_var_elements(input)?;
		assert!(f_var_inputs.len() == 1);
		f_var_inputs
			.get(0)
			.cloned()
			.ok_or(SynthesisError::AssignmentMissing)
	}
}

impl<F: PrimeField> AllocVar<(), F> for Params<F> {
	fn new_variable<T: Borrow<()>>(
		_: impl Into<Namespace<F>>,
		_: impl FnOnce() -> Result<T, SynthesisError>,
		_: AllocationMode,
	) -> Result<Self, SynthesisError> {
		Ok(Params { field: PhantomData })
	}
}

#[cfg(test)]
mod test {
	use super::{CRHGadget, FpVar, Params};
	use ark_crypto_primitives::crh::constraints::CRHGadget as CRHGadgetTrait;
	use ark_ed_on_bn254::Fq;
	use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, R1CSVar, ToBytesGadget};
	use ark_relations::r1cs::ConstraintSystem;

	type IdentityCRHGadget = CRHGadget<Fq>;
	#[test]
	fn should_return_same_data() {
		let val = Fq::from(4u64);

		let cs = ConstraintSystem::<Fq>::new_ref();
		let val_var = FpVar::<Fq>::new_input(cs, || Ok(val)).unwrap();

		let bytes_var = val_var.to_bytes().unwrap();
		let res_var = IdentityCRHGadget::evaluate(&Params::default(), &bytes_var).unwrap();

		assert!(res_var.is_eq(&val_var).unwrap().value().unwrap());
	}
}
