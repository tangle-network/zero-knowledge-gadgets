use super::{BridgeLeaf, Output, Private, Public};
use crate::{
	leaf::{LeafCreation, LeafCreationGadget},
	Vec,
};
use ark_crypto_primitives::{crh::CRHGadget, CRH};
use ark_ff::fields::PrimeField;
use ark_r1cs_std::{eq::EqGadget, fields::fp::FpVar, prelude::*, R1CSVar};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::marker::PhantomData;
use core::borrow::Borrow;

#[derive(Clone)]
pub struct PrivateVar<F: PrimeField> {
	r: FpVar<F>,
	nullifier: FpVar<F>,
	rho: FpVar<F>,
}

impl<F: PrimeField> PrivateVar<F> {
	pub fn new(r: FpVar<F>, nullifier: FpVar<F>, rho: FpVar<F>) -> Self {
		Self { r, nullifier, rho }
	}
}

#[derive(Clone)]
pub struct PublicVar<F: PrimeField> {
	chain_id: FpVar<F>,
}

impl<F: PrimeField> PublicVar<F> {
	pub fn new(chain_id: FpVar<F>) -> Self {
		Self { chain_id }
	}
}

#[derive(Clone, Debug)]
pub struct OutputVar<F: PrimeField> {
	leaf: FpVar<F>,
	nullifier_hash: FpVar<F>,
}

impl<F: PrimeField> OutputVar<F> {
	pub fn new(leaf: FpVar<F>, nullifier_hash: FpVar<F>) -> Self {
		Self {
			leaf,
			nullifier_hash,
		}
	}
}

impl<F: PrimeField> R1CSVar<F> for OutputVar<F> {
	type Value = Output<F>;

	fn cs(&self) -> ConstraintSystemRef<F> {
		self.to_bytes().unwrap().cs()
	}

	fn value(&self) -> Result<Self::Value, SynthesisError> {
		Ok(Output {
			leaf: self.leaf.value()?,
			nullifier_hash: self.nullifier_hash.value()?,
		})
	}
}

impl<F: PrimeField> CondSelectGadget<F> for OutputVar<F> {
	fn conditionally_select(
		cond: &Boolean<F>,
		true_val: &Self,
		false_val: &Self,
	) -> Result<Self, SynthesisError> {
		match cond.value()? {
			true => Ok(true_val.clone()),
			false => Ok(false_val.clone()),
		}
	}
}

impl<F: PrimeField> EqGadget<F> for OutputVar<F> {
	fn is_eq(&self, other: &Self) -> Result<Boolean<F>, SynthesisError> {
		self.leaf
			.is_eq(&other.leaf)
			.and(self.nullifier_hash.is_eq(&other.nullifier_hash))
	}
}

impl<F: PrimeField> ToBytesGadget<F> for OutputVar<F> {
	fn to_bytes(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
		let mut bytes = Vec::new();
		bytes.extend(self.leaf.to_bytes()?);
		bytes.extend(self.nullifier_hash.to_bytes()?);
		Ok(bytes)
	}
}

pub struct BridgeLeafGadget<F: PrimeField, H: CRH, HG: CRHGadget<H, F>, L: LeafCreation<H>> {
	field: PhantomData<F>,
	hasher: PhantomData<H>,
	hasher_gadget: PhantomData<HG>,
	leaf_creation: PhantomData<L>,
}

impl<F: PrimeField, H: CRH, HG: CRHGadget<H, F>> LeafCreationGadget<F, H, HG, BridgeLeaf<F, H>>
	for BridgeLeafGadget<F, H, HG, BridgeLeaf<F, H>>
{
	type LeafVar = HG::OutputVar;
	type NullifierVar = HG::OutputVar;
	type PrivateVar = PrivateVar<F>;
	type PublicVar = PublicVar<F>;

	fn create_leaf(
		s: &Self::PrivateVar,
		p: &Self::PublicVar,
		h: &HG::ParametersVar,
	) -> Result<Self::LeafVar, SynthesisError> {
		// leaf
		let mut leaf_bytes = Vec::new();
		leaf_bytes.extend(s.r.to_bytes()?);
		leaf_bytes.extend(s.nullifier.to_bytes()?);
		leaf_bytes.extend(s.rho.to_bytes()?);
		leaf_bytes.extend(p.chain_id.to_bytes()?);
		HG::evaluate(h, &leaf_bytes)
	}

	fn create_nullifier(
		s: &Self::PrivateVar,
		h: &HG::ParametersVar,
	) -> Result<Self::NullifierVar, SynthesisError> {
		let mut nullifier_hash_bytes = Vec::new();
		nullifier_hash_bytes.extend(s.nullifier.to_bytes()?);
		nullifier_hash_bytes.extend(s.nullifier.to_bytes()?);
		HG::evaluate(h, &nullifier_hash_bytes)
	}
}

impl<F: PrimeField> AllocVar<Private<F>, F> for PrivateVar<F> {
	fn new_variable<T: Borrow<Private<F>>>(
		into_ns: impl Into<Namespace<F>>,
		f: impl FnOnce() -> Result<T, SynthesisError>,
		mode: AllocationMode,
	) -> Result<Self, SynthesisError> {
		let private = f()?.borrow().clone();
		let ns = into_ns.into();
		let cs = ns.cs();

		let r = private.r;
		let nullifier = private.nullifier;
		let rho = private.rho;

		let r_var = FpVar::new_variable(cs.clone(), || Ok(r), mode)?;
		let nullifier_var = FpVar::new_variable(cs.clone(), || Ok(nullifier), mode)?;
		let rho_var = FpVar::new_variable(cs.clone(), || Ok(rho), mode)?;

		Ok(PrivateVar::new(r_var, nullifier_var, rho_var))
	}
}

impl<F: PrimeField> AllocVar<Public<F>, F> for PublicVar<F> {
	fn new_variable<T: Borrow<Public<F>>>(
		cs: impl Into<Namespace<F>>,
		f: impl FnOnce() -> Result<T, SynthesisError>,
		mode: AllocationMode,
	) -> Result<Self, SynthesisError> {
		let public = f()?.borrow().clone();
		let chain_id = FpVar::new_variable(cs, || Ok(public.chain_id), mode)?;
		Ok(PublicVar::new(chain_id))
	}
}

impl<F: PrimeField> AllocVar<Output<F>, F> for OutputVar<F> {
	fn new_variable<T: Borrow<Output<F>>>(
		cs: impl Into<Namespace<F>>,
		f: impl FnOnce() -> Result<T, SynthesisError>,
		_: AllocationMode,
	) -> Result<Self, SynthesisError> {
		let output = f()?.borrow().clone();
		let leaf = FpVar::new_witness(cs, || Ok(output.leaf))?;
		let nullifier_hash = FpVar::new_input(leaf.cs(), || Ok(output.nullifier_hash))?;
		Ok(OutputVar::new(leaf, nullifier_hash))
	}
}

#[cfg(feature = "poseidon_x5_bn254_5")]
#[cfg(feature = "poseidon_x5_bn254_3")]
#[cfg(test)]
mod test {
	use super::*;
	use crate::{
		poseidon::{
			constraints::{CRHGadget, PoseidonParametersVar},
			sbox::PoseidonSbox,
			PoseidonParameters, Rounds, CRH,
		},
		utils::{get_mds_5, get_rounds_5},
	};
	use ark_ed_on_bn254::Fq;
	use ark_ff::One;
	use ark_r1cs_std::R1CSVar;
	use ark_relations::r1cs::ConstraintSystem;
	use ark_std::test_rng;

	#[derive(Default, Clone)]
	struct PoseidonRounds5;

	impl Rounds for PoseidonRounds5 {
		const FULL_ROUNDS: usize = 8;
		const PARTIAL_ROUNDS: usize = 57;
		const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
		const WIDTH: usize = 5;
	}

	type PoseidonCRH5 = CRH<Fq, PoseidonRounds5>;
	type PoseidonCRH5Gadget = CRHGadget<Fq, PoseidonRounds5>;

	type Leaf = BridgeLeaf<Fq, PoseidonCRH5>;
	type LeafGadget = BridgeLeafGadget<Fq, PoseidonCRH5, PoseidonCRH5Gadget, Leaf>;
	#[test]
	fn should_create_bridge_leaf_constraints() {
		let rng = &mut test_rng();

		let cs = ConstraintSystem::<Fq>::new_ref();

		// Native version
		let rounds = get_rounds_5::<Fq>();
		let mds = get_mds_5::<Fq>();
		let params = PoseidonParameters::<Fq>::new(rounds, mds);
		let chain_id = Fq::one();

		let public = Public::new(chain_id);
		let secrets = Leaf::generate_secrets(rng).unwrap();
		let leaf = Leaf::create_leaf(&secrets, &public, &params).unwrap();
		let nullifier = Leaf::create_nullifier(&secrets, &params).unwrap();

		// Constraints version
		let params_var = PoseidonParametersVar::new_variable(
			cs.clone(),
			|| Ok(&params),
			AllocationMode::Constant,
		)
		.unwrap();

		let public_var = PublicVar::new_input(cs.clone(), || Ok(&public)).unwrap();
		let secrets_var = PrivateVar::new_witness(cs.clone(), || Ok(&secrets)).unwrap();
		let leaf_var = LeafGadget::create_leaf(&secrets_var, &public_var, &params_var).unwrap();
		let nullifier_var = LeafGadget::create_nullifier(&secrets_var, &params_var).unwrap();

		// Checking equality
		let leaf_new_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(&leaf)).unwrap();
		let nullifier_new_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(&nullifier)).unwrap();
		let leaf_res = leaf_var.is_eq(&leaf_new_var).unwrap();
		let nullifier_res = nullifier_var.is_eq(&nullifier_new_var).unwrap();
		assert!(leaf_res.value().unwrap());
		assert!(leaf_res.cs().is_satisfied().unwrap());
		assert!(nullifier_res.value().unwrap());
		assert!(nullifier_res.cs().is_satisfied().unwrap());
	}
}
