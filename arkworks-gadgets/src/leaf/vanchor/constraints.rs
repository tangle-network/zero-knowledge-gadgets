use super::{Private, Public};
use crate::Vec;
use ark_crypto_primitives::{crh::CRHGadget, CRH};
use ark_ff::fields::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::marker::PhantomData;
use core::borrow::Borrow;

#[derive(Clone)]
pub struct PrivateVar<F: PrimeField> {
	pub amount: FpVar<F>,
	blinding: FpVar<F>,
}

#[derive(Clone)]
pub struct PublicVar<F: PrimeField> {
	chain_id: FpVar<F>,
}

impl<F: PrimeField> PublicVar<F> {
	pub fn default() -> Self {
		let chain_id = F::zero();

		Self {
			chain_id: FpVar::Constant(chain_id),
		}
	}

	pub fn new(chain_id: FpVar<F>) -> Self {
		Self { chain_id }
	}
}

impl<F: PrimeField> PrivateVar<F> {
	pub fn new(amount: FpVar<F>, blinding: FpVar<F>) -> Self {
		Self { amount, blinding }
	}
}

pub struct VAnchorLeafGadget<
	F: PrimeField,
	H: CRH,
	HG: CRHGadget<H, F>,
> {
	field: PhantomData<F>,
	hasher: PhantomData<H>,
	hasher_gadget: PhantomData<HG>,
}

impl<F: PrimeField, H: CRH, HG: CRHGadget<H, F>,>
	VAnchorLeafGadget<F, H, HG>
{
	pub fn create_leaf<BG: ToBytesGadget<F>>(
		private: &PrivateVar<F>,
		public: &PublicVar<F>,
		public_key: &BG,
		h_w5: &HG::ParametersVar,
	) -> Result<HG::OutputVar, SynthesisError> {
		let pubkey = public_key;

		let mut bytes = Vec::new();
		bytes.extend(public.chain_id.to_bytes()?);
		bytes.extend(private.amount.to_bytes()?);
		bytes.extend(pubkey.to_bytes()?);
		bytes.extend(private.blinding.to_bytes()?);
		HG::evaluate(h_w5, &bytes)
	}

	pub fn create_nullifier<BG: ToBytesGadget<F>>(
		signature: &BG,
		commitment: &HG::OutputVar,
		h_w4: &HG::ParametersVar,
		index: &FpVar<F>,
	) -> Result<HG::OutputVar, SynthesisError> {
		let mut bytes = Vec::new();
		bytes.extend(commitment.to_bytes()?);
		bytes.extend(index.to_bytes()?);
		bytes.extend(signature.to_bytes()?);
		HG::evaluate(h_w4, &bytes)
	}
}

impl<F: PrimeField> AllocVar<Private<F>, F> for PrivateVar<F> {
	fn new_variable<T: Borrow<Private<F>>>(
		into_ns: impl Into<Namespace<F>>,
		f: impl FnOnce() -> Result<T, SynthesisError>,
		mode: AllocationMode,
	) -> Result<Self, SynthesisError> {
		let secrets = f()?.borrow().clone();
		let ns = into_ns.into();
		let cs = ns.cs();

		let amount = secrets.amount;
		let blinding = secrets.blinding;

		let amount_var = FpVar::new_variable(cs.clone(), || Ok(amount), mode)?;
		let blinding_var = FpVar::new_variable(cs.clone(), || Ok(blinding), mode)?;
		Ok(PrivateVar::new(amount_var, blinding_var))
	}
}

impl<F: PrimeField> AllocVar<Public<F>, F> for PublicVar<F> {
	fn new_variable<T: Borrow<Public<F>>>(
		into_ns: impl Into<Namespace<F>>,
		f: impl FnOnce() -> Result<T, SynthesisError>,
		mode: AllocationMode,
	) -> Result<Self, SynthesisError> {
		let public = f()?.borrow().clone();
		let ns = into_ns.into();
		let cs = ns.cs();
		let chain_id = FpVar::new_variable(cs.clone(), || Ok(public.chain_id), mode)?;
		Ok(PublicVar::new(chain_id))
	}
}

#[cfg(feature = "default_poseidon")]
#[cfg(test)]
mod test {
	use super::*;
	use crate::{
		leaf::vanchor::VAnchorLeaf,
		poseidon::{
			constraints::{CRHGadget, PoseidonParametersVar},
			CRH,
		},
		setup::common::{setup_params_x5_2, setup_params_x5_4, setup_params_x5_5, Curve},
	};
	//use ark_bls12_381::Fq;
	use ark_bn254::Fq;

	use ark_crypto_primitives::crh::{CRHGadget as CRHGadgetTrait, CRH as CRHTrait};
	use ark_ff::to_bytes;
	use ark_relations::r1cs::ConstraintSystem;
	use ark_std::test_rng;

	type PoseidonCRH = CRH<Fq>;
	
	type PoseidonCRHGadget = CRHGadget<Fq>;

	type Leaf = VAnchorLeaf<Fq, PoseidonCRH>;
	type LeafGadget =
		VAnchorLeafGadget<Fq, PoseidonCRH, PoseidonCRHGadget,>;
	use crate::ark_std::{One, UniformRand};
	#[test]
	fn should_crate_new_leaf_constraints() {
		let rng = &mut test_rng();
		let cs = ConstraintSystem::<Fq>::new_ref();
		let curve = Curve::Bn254;

		// Native version

		let params5_2 = setup_params_x5_2(curve);
		let params5_5 = setup_params_x5_5(curve);

		let chain_id = Fq::one();
		let index = Fq::one();
		let public = Public::new(chain_id);
		let secrets = Private::generate(rng);
		let private_key = Fq::rand(rng);
		let privkey = to_bytes![private_key].unwrap();
		let public_key = PoseidonCRH::evaluate(&params5_2, &privkey).unwrap();
		let leaf = Leaf::create_leaf(&secrets, &public, &public_key, &params5_5).unwrap();

		// Constraints version
		let index_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(index)).unwrap();
		let public_var = PublicVar::new_input(cs.clone(), || Ok(&public)).unwrap();
		let secrets_var = PrivateVar::new_witness(cs.clone(), || Ok(&secrets)).unwrap();
		let private_key_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(&private_key)).unwrap();
		let params_var5_5 = PoseidonParametersVar::new_variable(
			cs.clone(),
			|| Ok(&params5_5),
			AllocationMode::Constant,
		)
		.unwrap();
		let params_var5_2 = PoseidonParametersVar::new_variable(
			cs.clone(),
			|| Ok(&params5_2),
			AllocationMode::Constant,
		)
		.unwrap();

		let mut bytes = Vec::new();
		bytes.extend(private_key_var.to_bytes().unwrap());
		let public_key_var = PoseidonCRHGadget::evaluate(&params_var5_2, &bytes).unwrap();

		let leaf_var =
			LeafGadget::create_leaf(&secrets_var, &public_var, &public_key_var, &params_var5_5)
				.unwrap();

		// Check equality
		let leaf_new_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(leaf)).unwrap();
		let res = leaf_var.is_eq(&leaf_new_var).unwrap();
		assert!(res.value().unwrap());
		assert!(res.cs().is_satisfied().unwrap());

		// Test Nullifier
		// Native version
		let params5_4 = setup_params_x5_4(curve);
		let params_var5_4 = PoseidonParametersVar::new_variable(
			cs.clone(),
			|| Ok(&params5_4),
			AllocationMode::Constant,
		)
		.unwrap();
		let signature = Fq::rand(rng);
		let nullifier = Leaf::create_nullifier(&signature, &leaf, &params5_4, &index).unwrap();

		// Constraints version
		let signature_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(&signature)).unwrap();
		let nullifier_var =
			LeafGadget::create_nullifier(&signature_var, &leaf_var, &params_var5_4, &index_var)
				.unwrap();

		// Check equality
		let nullifier_new_var =
			FpVar::<Fq>::new_witness(nullifier_var.cs(), || Ok(nullifier)).unwrap();
		let res_nul = nullifier_var.is_eq(&nullifier_new_var).unwrap();
		assert!(res_nul.value().unwrap());
		assert!(res_nul.cs().is_satisfied().unwrap());
	}
}
