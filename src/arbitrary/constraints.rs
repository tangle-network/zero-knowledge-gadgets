use super::Arbitrary;
use ark_ff::fields::Field;
use ark_r1cs_std::prelude::AllocVar;
use ark_relations::r1cs::SynthesisError;

pub trait ArbitraryGadget<F: Field, A: Arbitrary> {
	type InputVar: AllocVar<A::Input, F> + Clone;
	fn constrain(inputs: &Self::InputVar) -> Result<(), SynthesisError>;
}
