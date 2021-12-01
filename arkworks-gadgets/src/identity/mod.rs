use ark_crypto_primitives::{CryptoError, Error, CRH as CRHTrait};
use ark_ff::{fields::PrimeField, BigInteger};
use ark_std::{marker::PhantomData, rand::Rng, vec::Vec};
use arkworks_utils::utils::to_field_elements;

#[cfg(feature = "r1cs")]
pub mod constraints;

pub struct CRH<F: PrimeField> {
	field: PhantomData<F>,
}

impl<F: PrimeField> CRHTrait for CRH<F> {
	type Output = F;
	type Parameters = ();

	const INPUT_SIZE_BITS: usize = F::BigInt::NUM_LIMBS * 64;

	fn setup<R: Rng>(_: &mut R) -> Result<Self::Parameters, Error> {
		Ok(())
	}

	fn evaluate(_: &Self::Parameters, input: &[u8]) -> Result<Self::Output, Error> {
		let f_inputs: Vec<F> = to_field_elements(input)?;

		assert!(f_inputs.len() == 1);

		Ok(f_inputs
			.get(0)
			.cloned()
			.ok_or_else(|| CryptoError::IncorrectInputLength(f_inputs.len()))?)
	}
}

#[cfg(test)]
mod test {
	use super::CRH;
	use ark_crypto_primitives::crh::CRH as CRHTrait;
	use ark_ed_on_bn254::Fq;
	use ark_ff::to_bytes;

	type IdentityCRH = CRH<Fq>;
	#[test]
	fn should_return_same_data() {
		let val = Fq::from(4u64);

		let bytes = to_bytes![val].unwrap();
		let res = IdentityCRH::evaluate(&(), &bytes).unwrap();

		assert_eq!(res, val);
	}
}
