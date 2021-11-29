use ark_crypto_primitives::{crh::CRHGadget, CRH};
use ark_ff::fields::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};

use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::{marker::PhantomData, vec::Vec};
use core::borrow::Borrow;

use super::Keypair;

#[derive(Clone)]
pub struct KeypairVar<F: PrimeField, H: CRH, HG: CRHGadget<H, F>> {
	pub private_key: FpVar<F>,

	_h: PhantomData<H>,
	_hg: PhantomData<HG>,
}

impl<F: PrimeField, H: CRH, HG: CRHGadget<H, F>> KeypairVar<F, H, HG> {
	pub fn new(private_key_in: &FpVar<F>) -> Result<Self, SynthesisError> {
		let private_key = private_key_in.clone();
		Ok(Self {
			private_key,
			_h: PhantomData,
			_hg: PhantomData,
		})
	}

	pub fn public_key(
		&self,
		parameters2: &HG::ParametersVar,
	) -> Result<<HG as CRHGadget<H, F>>::OutputVar, SynthesisError> {
		let mut bytes = Vec::<UInt8<F>>::new();
		bytes.extend(self.private_key.to_bytes()?);
		HG::evaluate(&parameters2, &bytes)
	}

	pub fn signature(
		&self,
		commitment: &HG::OutputVar,
		index: &FpVar<F>,
		h_w4: &HG::ParametersVar,
	) -> Result<HG::OutputVar, SynthesisError> {
		let mut bytes = Vec::new();
		bytes.extend(self.private_key.clone().to_bytes()?);
		bytes.extend(commitment.to_bytes()?);
		bytes.extend(index.to_bytes()?);
		HG::evaluate(h_w4, &bytes)
	}
}

impl<F: PrimeField, H2: CRH, HG2: CRHGadget<H2, F>> AllocVar<Keypair<F, H2>, F>
	for KeypairVar<F, H2, HG2>
{
	fn new_variable<T: Borrow<Keypair<F, H2>>>(
		into_ns: impl Into<Namespace<F>>,
		f: impl FnOnce() -> Result<T, SynthesisError>,
		mode: AllocationMode,
	) -> Result<Self, SynthesisError> {
		let inp = f()?.borrow().clone();
		let private_key_in = FpVar::<F>::new_variable(into_ns, || Ok(inp.private_key), mode)?;
		Ok(KeypairVar::new(&private_key_in)?)
	}
}

#[cfg(feature = "default_poseidon")]
#[cfg(test)]
mod test {
	use super::*;
	use crate::{
		ark_std::Zero,
		poseidon::{
			constraints::{CRHGadget, PoseidonParametersVar},
			CRH,
		},
	};
	use ark_bn254::Fq;
	use ark_crypto_primitives::crh::{constraints::CRHGadget as CRHGadgetTrait, CRH as CRHTrait};
	use ark_ff::to_bytes;
	use ark_r1cs_std::{
		alloc::{AllocVar, AllocationMode},
		prelude::EqGadget,
		R1CSVar,
	};
	use ark_relations::r1cs::ConstraintSystem;
	use ark_std::test_rng;
	use arkworks_utils::utils::common::{setup_params_x5_2, setup_params_x5_4, Curve};

	type PoseidonCRH = CRH<Fq>;
	type PoseidonCRHGadget = CRHGadget<Fq>;

	use crate::ark_std::UniformRand;
	#[test]
	fn should_crate_new_public_key_var() {
		let rng = &mut test_rng();
		let cs = ConstraintSystem::<Fq>::new_ref();
		let curve = Curve::Bn254;

		// Native version
		let params = setup_params_x5_2(curve);

		let private_key = Fq::rand(rng);

		let privkey = to_bytes![private_key].unwrap();
		let pubkey = PoseidonCRH::evaluate(&params, &privkey).unwrap();

		// Constraints version
		let bytes = to_bytes![private_key].unwrap();
		let privkey_var = Vec::<UInt8<Fq>>::new_witness(cs.clone(), || Ok(bytes)).unwrap();
		let params_var = PoseidonParametersVar::new_variable(
			cs.clone(),
			|| Ok(&params),
			AllocationMode::Constant,
		)
		.unwrap();

		let pubkey_var = PoseidonCRHGadget::evaluate(&params_var, &privkey_var).unwrap();
		let privkey_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(private_key)).unwrap();
		let keypair_var =
			KeypairVar::<Fq, PoseidonCRH, PoseidonCRHGadget>::new(&privkey_var).unwrap();

		let new_pubkey_var = keypair_var.public_key(&params_var).unwrap();
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
		let private_key = Fq::rand(rng);
		let commitment = Fq::rand(rng);
		let index = Fq::zero();

		let keypair = Keypair::<Fq, PoseidonCRH>::new(private_key.clone());
		let signature = keypair.signature(&commitment, &index, &params).unwrap();

		// Constraints version
		let params_var = PoseidonParametersVar::new_variable(
			cs.clone(),
			|| Ok(&params),
			AllocationMode::Constant,
		)
		.unwrap();
		let privkey_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(private_key)).unwrap();
		let commitment_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(commitment)).unwrap();
		let index_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(index)).unwrap();

		let keypair_var =
			KeypairVar::<Fq, PoseidonCRH, PoseidonCRHGadget>::new(&privkey_var).unwrap();

		let signature_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(signature)).unwrap();
		let new_signature_var = keypair_var
			.signature(&commitment_var, &index_var, &params_var)
			.unwrap();

		// Check equality
		let res = new_signature_var.is_eq(&signature_var).unwrap();
		assert!(res.value().unwrap());
		assert_eq!(signature, new_signature_var.value().unwrap());
		assert!(res.cs().is_satisfied().unwrap());
	}
}
