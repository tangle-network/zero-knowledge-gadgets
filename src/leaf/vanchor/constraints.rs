use super::{Private, Public, VanchorLeaf};
use crate::{
	leaf::{VanchorLeafCreation, VanchorLeafCreationGadget},
	Vec,
};
use ark_crypto_primitives::{crh::CRHGadget, CRH};
use ark_ff::fields::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::marker::PhantomData;
use core::borrow::Borrow;

#[derive(Clone)]
pub struct PrivateVar<F: PrimeField> {
	amount: FpVar<F>,
	blinding: FpVar<F>,
	priv_key: FpVar<F>,
}

#[derive(Clone)]
pub struct PublicVar<F: PrimeField> {
	chain_id: FpVar<F>,
}

impl<F: PrimeField> PublicVar<F> {
	pub fn default() -> Self {
		let chain_id = F::zero();

		Self {
			chain_id: ark_r1cs_std::fields::fp::FpVar::Constant(chain_id),
		}
	}

	pub fn new(chain_id: FpVar<F>) -> Self {
		Self { chain_id }
	}
}

impl<F: PrimeField> PrivateVar<F> {
	pub fn new(amount: FpVar<F>, blinding: FpVar<F>, priv_key: FpVar<F>) -> Self {
		Self {
			amount,
			blinding,
			priv_key,
		}
	}
}

pub struct VanchorLeafGadget<
	F: PrimeField,
	H1: CRH,
	HG1: CRHGadget<H1, F>,
	L: VanchorLeafCreation<H1, F>,
> {
	field: PhantomData<F>,
	hasher1: PhantomData<H1>,
	hasher_gadget1: PhantomData<HG1>,
	leaf_creation: PhantomData<L>,
}

impl<F: PrimeField, H: CRH, HG: CRHGadget<H, F>>
	VanchorLeafCreationGadget<F, H, HG, VanchorLeaf<F, H>>
	for VanchorLeafGadget<F, H, HG, VanchorLeaf<F, H>>
{
	type LeafVar = HG::OutputVar;
	type NullifierVar = HG::OutputVar;
	type PrivateVar = PrivateVar<F>;
	type PublicVar = PublicVar<F>;

	fn create_leaf(
		s: &Self::PrivateVar,
		p: &Self::PublicVar,
		h_w2: &HG::ParametersVar,
		h_w5: &HG::ParametersVar,
	) -> Result<Self::LeafVar, SynthesisError> {
		let mut bytes_p = Vec::new();
		bytes_p.extend(s.priv_key.to_bytes()?);
		let pubkey = HG::evaluate(h_w2, &bytes_p)?;

		let mut bytes = Vec::new();
		bytes.extend(p.chain_id.to_bytes()?);
		bytes.extend(s.amount.to_bytes()?);
		bytes.extend(pubkey.to_bytes()?);
		bytes.extend(s.blinding.to_bytes()?);
		HG::evaluate(h_w5, &bytes)
	}

	fn create_nullifier(
		s: &Self::PrivateVar,
		c: &Self::LeafVar,
		h_w4: &HG::ParametersVar,
		i: &FpVar<F>,
	) -> Result<Self::NullifierVar, SynthesisError> {
		let mut bytes = Vec::new();
		bytes.extend(c.to_bytes()?);
		bytes.extend(i.to_bytes()?);
		bytes.extend(s.priv_key.to_bytes()?);
		HG::evaluate(h_w4, &bytes)
	}

	fn get_private_key(s: &Self::PrivateVar) -> Result<FpVar<F>, SynthesisError> {
		Ok(s.priv_key.clone())
	}

	fn gen_public_key(
		s: &Self::PrivateVar,
		h_w2: &HG::ParametersVar,
	) -> Result<HG::OutputVar, SynthesisError> {
		let mut bytes = Vec::new();
		bytes.extend(s.priv_key.to_bytes()?);
		HG::evaluate(h_w2, &bytes)
	}

	fn get_amount(s: &Self::PrivateVar) -> Result<FpVar<F>, SynthesisError> {
		Ok(s.amount.clone())
	}

	fn get_blinding(s: &Self::PrivateVar) -> Result<FpVar<F>, SynthesisError> {
		Ok(s.blinding.clone())
	}

	fn get_chain_id(p: &Self::PublicVar) -> Result<FpVar<F>, SynthesisError> {
		Ok(p.chain_id.clone())
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
		let priv_key = secrets.priv_key;

		let amount_var = FpVar::new_variable(cs.clone(), || Ok(amount), mode)?;
		let blinding_var = FpVar::new_variable(cs.clone(), || Ok(blinding), mode)?;
		let priv_key_var = FpVar::new_variable(cs.clone(), || Ok(priv_key), mode)?;
		Ok(PrivateVar::new(amount_var, blinding_var, priv_key_var))
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
		poseidon::{
			constraints::{CRHGadget, PoseidonParametersVar},
			sbox::PoseidonSbox,
			PoseidonParameters, Rounds, CRH,
		},
		utils::{get_mds_poseidon_bls381_x5_5, get_rounds_poseidon_bls381_x5_5},
	};
	use ark_bls12_381::Fq;
	use ark_relations::r1cs::ConstraintSystem;
	use ark_std::test_rng;
	#[derive(Default, Clone)]
	struct PoseidonRounds3;

	impl Rounds for PoseidonRounds3 {
		const FULL_ROUNDS: usize = 8;
		const PARTIAL_ROUNDS: usize = 57;
		const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
		const WIDTH: usize = 4;
	}

	type PoseidonCRH3 = CRH<Fq, PoseidonRounds3>;
	type PoseidonCRH3Gadget = CRHGadget<Fq, PoseidonRounds3>;

	type Leaf = VanchorLeaf<Fq, PoseidonCRH3>;
	type LeafGadget = VanchorLeafGadget<Fq, PoseidonCRH3, PoseidonCRH3Gadget, Leaf>;
	use crate::ark_std::One;
	#[test]
	fn should_crate_new_leaf_constraints() {
		let rng = &mut test_rng();
		let cs = ConstraintSystem::<Fq>::new_ref();

		// Native version
		let rounds = get_rounds_poseidon_bls381_x5_5::<Fq>();
		let mds = get_mds_poseidon_bls381_x5_5::<Fq>();
		let params = PoseidonParameters::<Fq>::new(rounds, mds);
		let chain_id = Fq::one();
		let index = Fq::one();
		let public = Public::new(chain_id);
		let secrets = Leaf::generate_secrets(rng).unwrap();

		//TODO Change the parameters
		let leaf = Leaf::create_leaf(&secrets, &public, &params, &params).unwrap();

		// Constraints version
		let index_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(index)).unwrap();
		let public_var = PublicVar::new_input(cs.clone(), || Ok(&public)).unwrap();
		let secrets_var = PrivateVar::new_witness(cs.clone(), || Ok(&secrets)).unwrap();
		let params_var =
			PoseidonParametersVar::new_variable(cs, || Ok(&params), AllocationMode::Constant)
				.unwrap();

		//TODO Change the parameters
		let leaf_var =
			LeafGadget::create_leaf(&secrets_var, &public_var, &params_var, &params_var).unwrap();

		// Check equality
		let leaf_new_var = FpVar::<Fq>::new_witness(leaf_var.cs(), || Ok(leaf)).unwrap();
		let res = leaf_var.is_eq(&leaf_new_var).unwrap();
		assert!(res.value().unwrap());
		assert!(res.cs().is_satisfied().unwrap());

		// Test Nullifier
		// Native version
		let nullifier = Leaf::create_nullifier(&secrets, &leaf, &params, &index).unwrap();

		// Constraints version
		let nullifier_var =
			LeafGadget::create_nullifier(&secrets_var, &leaf_var, &params_var, &index_var).unwrap();

		// Check equality
		let nullifier_new_var =
			FpVar::<Fq>::new_witness(nullifier_var.cs(), || Ok(nullifier)).unwrap();
		let res_nul = nullifier_var.is_eq(&nullifier_new_var).unwrap();
		assert!(res_nul.value().unwrap());
		assert!(res_nul.cs().is_satisfied().unwrap());
	}
}
