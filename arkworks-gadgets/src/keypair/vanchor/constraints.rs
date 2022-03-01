use ark_crypto_primitives::{crh::CRHGadget, CRH};
use ark_ff::fields::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};

use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::{marker::PhantomData, vec::Vec};
use core::borrow::Borrow;

use crate::poseidon::{field_hasher::FieldHasher, field_hasher_constraints::FieldHasherGadget};

use super::Keypair;

#[derive(Clone)]
pub struct KeypairVar<F: PrimeField, PHG: FieldHasherGadget<F>, SHG: FieldHasherGadget<F>> {
	pub private_key: FpVar<F>,
	_hg: PhantomData<(PHG, SHG)>,
}

impl<F: PrimeField, PHG: FieldHasherGadget<F>, SHG: FieldHasherGadget<F>> KeypairVar<F, PHG, SHG> {
	pub fn new(private_key_in: &FpVar<F>) -> Result<Self, SynthesisError> {
		let private_key = private_key_in.clone();
		Ok(Self {
			private_key,
			_hg: PhantomData,
		})
	}

	pub fn public_key(&self, h: &PHG) -> Result<FpVar<F>, SynthesisError> {
		h.hash(&[self.private_key.clone()])
	}

	pub fn signature(
		&self,
		commitment: &FpVar<F>,
		index: &FpVar<F>,
		h_w4: &SHG,
	) -> Result<FpVar<F>, SynthesisError> {
		h_w4.hash(&[self.private_key.clone(), commitment.clone(), index.clone()])
	}
}

impl<
		F: PrimeField,
		PH: FieldHasher<F>,
		SH: FieldHasher<F>,
		PHG: FieldHasherGadget<F>,
		SHG: FieldHasherGadget<F>,
	> AllocVar<Keypair<F, PH, SH>, F> for KeypairVar<F, PHG, SHG>
{
	fn new_variable<T: Borrow<Keypair<F, PH, SH>>>(
		into_ns: impl Into<Namespace<F>>,
		f: impl FnOnce() -> Result<T, SynthesisError>,
		mode: AllocationMode,
	) -> Result<Self, SynthesisError> {
		let inp = f()?.borrow().clone();
		let private_key_in = FpVar::<F>::new_variable(into_ns, || Ok(inp.private_key), mode)?;
		KeypairVar::new(&private_key_in)
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::{
		ark_std::Zero,
		poseidon::{
			field_hasher::Poseidon,
			field_hasher_constraints::{PoseidonGadget, PoseidonParametersVar},
			CRH,
		},
	};
	use ark_crypto_primitives::crh::{constraints::CRHGadget as CRHGadgetTrait, CRH as CRHTrait};
	use ark_ed_on_bn254::Fq;
	use ark_ff::to_bytes;
	use ark_r1cs_std::{
		alloc::{AllocVar, AllocationMode},
		prelude::EqGadget,
		R1CSVar,
	};
	use ark_relations::r1cs::ConstraintSystem;
	use ark_std::test_rng;
	use arkworks_utils::utils::common::{setup_params_x5_2, setup_params_x5_4, Curve};

	use crate::ark_std::UniformRand;
	#[test]
	fn should_crate_new_public_key_var() {
		let rng = &mut test_rng();
		let cs = ConstraintSystem::<Fq>::new_ref();
		let curve = Curve::Bn254;

		// Native version
		let params = setup_params_x5_2(curve);
		let hasher2 = Poseidon::<Fq>::new(params.clone());

		let private_key = Fq::rand(rng);
		let pubkey = hasher2.hash(&[private_key]).unwrap();

		// Constraints version
		let privkey_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(private_key)).unwrap();
		let params_var = PoseidonParametersVar::new_variable(
			cs.clone(),
			|| Ok(&params),
			AllocationMode::Constant,
		)
		.unwrap();
		let hasher_gadget = PoseidonGadget::<Fq> {
			params: params_var.clone(),
		};

		let pubkey_var = hasher_gadget.hash(&[privkey_var]).unwrap();
		let privkey_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(private_key)).unwrap();
		let keypair_var =
			KeypairVar::<Fq, PoseidonGadget<Fq>, PoseidonGadget<Fq>>::new(&privkey_var).unwrap();

		let new_pubkey_var = keypair_var.public_key(&hasher_gadget).unwrap();
		let res = pubkey_var.is_eq(&new_pubkey_var).unwrap();

		// Check equality
		assert!(res.value().unwrap());
		assert_eq!(pubkey, new_pubkey_var.value().unwrap());
		assert!(res.cs().is_satisfied().unwrap());

		let new_private_key = keypair_var.private_key;
		let res2 = new_private_key.is_eq(&privkey_var).unwrap();
		assert!(res2.value().unwrap());
		assert_eq!(private_key, new_private_key.value().unwrap());
		assert!(res2.cs().is_satisfied().unwrap());
	}

	#[test]
	fn should_crate_new_signature_var() {
		let rng = &mut test_rng();
		let cs = ConstraintSystem::<Fq>::new_ref();
		let curve = Curve::Bn254;
		// Native version
		let params = setup_params_x5_4(curve);
		let hasher = Poseidon::<Fq>::new(params.clone());
		let private_key = Fq::rand(rng);
		let commitment = Fq::rand(rng);
		let index = Fq::zero();

		let keypair = Keypair::<Fq, Poseidon<Fq>, Poseidon<Fq>>::new(private_key.clone());
		let signature = keypair.signature(&commitment, &index, &hasher).unwrap();

		// Constraints version
		let params_var = PoseidonParametersVar::new_variable(
			cs.clone(),
			|| Ok(&params),
			AllocationMode::Constant,
		)
		.unwrap();
		let hasher_gadget = PoseidonGadget::<Fq> {
			params: params_var.clone(),
		};
		let privkey_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(private_key)).unwrap();
		let commitment_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(commitment)).unwrap();
		let index_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(index)).unwrap();

		let keypair_var =
			KeypairVar::<Fq, PoseidonGadget<Fq>, PoseidonGadget<Fq>>::new(&privkey_var).unwrap();

		let signature_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(signature)).unwrap();
		let new_signature_var = keypair_var
			.signature(&commitment_var, &index_var, &hasher_gadget)
			.unwrap();

		// Check equality
		let res = new_signature_var.is_eq(&signature_var).unwrap();
		assert!(res.value().unwrap());
		assert_eq!(signature, new_signature_var.value().unwrap());
		assert!(res.cs().is_satisfied().unwrap());
	}
}
