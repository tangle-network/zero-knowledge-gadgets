use super::Arbitrary;
use ark_ff::fields::Field;
use ark_r1cs_std::prelude::AllocVar;
use ark_relations::r1cs::SynthesisError;
use webb_crypto_primitives::Error;

pub trait ArbitraryGadget<F: Field, A: Arbitrary> {
	type InputVar: AllocVar<A::Input, F> + Clone;
	fn constrain(inputs: &Self::InputVar) -> Result<(), SynthesisError>;
}
