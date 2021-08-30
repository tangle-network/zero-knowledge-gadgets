use super::{BridgeData, Input};
use crate::arbitrary::constraints::ArbitraryGadget;
use ark_ff::fields::PrimeField;
use ark_r1cs_std::{
	fields::fp::FpVar,
	prelude::{AllocVar, AllocationMode},
};
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::marker::PhantomData;
use core::borrow::Borrow;

#[derive(Clone)]
pub struct InputVar<F: PrimeField> {
	recipient: FpVar<F>,
	relayer: FpVar<F>,
	fee: FpVar<F>,
	refund: FpVar<F>,
}

impl<F: PrimeField> InputVar<F> {
	pub fn new(recipient: FpVar<F>, relayer: FpVar<F>, fee: FpVar<F>, refund: FpVar<F>) -> Self {
		Self {
			recipient,
			relayer,
			fee,
			refund,
		}
	}
}

pub struct BridgeDataGadget<F: PrimeField> {
	field: PhantomData<F>,
}

impl<F: PrimeField> ArbitraryGadget<F, BridgeData<F>> for BridgeDataGadget<F> {
	type InputVar = InputVar<F>;

	fn constrain(inputs: &Self::InputVar) -> Result<(), SynthesisError> {
		let _ = &inputs.recipient * &inputs.recipient;
		let _ = &inputs.relayer * &inputs.relayer;
		let _ = &inputs.fee * &inputs.fee;
		let _ = &inputs.refund * &inputs.refund;
		Ok(())
	}
}

impl<F: PrimeField> AllocVar<Input<F>, F> for InputVar<F> {
	fn new_variable<T: Borrow<Input<F>>>(
		into_ns: impl Into<Namespace<F>>,
		f: impl FnOnce() -> Result<T, SynthesisError>,
		mode: AllocationMode,
	) -> Result<Self, SynthesisError> {
		let input = f()?.borrow().clone();
		let ns = into_ns.into();
		let cs = ns.cs();

		let recipient = input.recipient;
		let relayer = input.relayer;
		let fee = input.fee;
		let refund = input.refund;

		let recipient_var = FpVar::new_variable(cs.clone(), || Ok(&recipient), mode)?;
		let relayer_var = FpVar::new_variable(cs.clone(), || Ok(&relayer), mode)?;
		let fee_var = FpVar::new_variable(cs.clone(), || Ok(&fee), mode)?;
		let refund_var = FpVar::new_variable(cs, || Ok(&refund), mode)?;

		Ok(InputVar::new(
			recipient_var,
			relayer_var,
			fee_var,
			refund_var,
		))
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use ark_ed_on_bn254::Fq;
	use ark_ff::UniformRand;
	use ark_relations::r1cs::ConstraintSystem;
	use ark_std::test_rng;

	type TestBridgeDataGadget = BridgeDataGadget<Fq>;
	#[test]
	fn should_enforce_constraints() {
		let rng = &mut test_rng();
		let cs = ConstraintSystem::<Fq>::new_ref();

		let recipient = Fq::rand(rng);
		let relayer = Fq::rand(rng);
		let fee = Fq::rand(rng);
		let refund = Fq::rand(rng);

		let input = Input::new(recipient, relayer, fee, refund);
		let input_var = InputVar::new_input(cs.clone(), || Ok(&input)).unwrap();

		TestBridgeDataGadget::constrain(&input_var).unwrap();

		assert!(cs.is_satisfied().unwrap());
	}
}
