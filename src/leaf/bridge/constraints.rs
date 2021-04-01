use super::{BridgeLeaf, Output, Private, Public};
use crate::leaf::{LeafCreation, LeafCreationGadget};
use ark_ff::{fields::PrimeField, to_bytes};
use ark_r1cs_std::{
	eq::EqGadget,
	fields::fp::{AllocatedFp, FpVar},
	prelude::*,
};
use ark_relations::r1cs::{
	ConstraintSystemRef, LinearCombination, Namespace, SynthesisError, Variable,
};
use ark_std::marker::PhantomData;
use core::borrow::Borrow;
use webb_crypto_primitives::{crh::FixedLengthCRHGadget, FixedLengthCRH};

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
		self.cs()
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
		match cond {
			Boolean::Constant(true) => Ok(true_val.clone()),
			Boolean::Constant(false) => Ok(false_val.clone()),
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

pub struct BridgeLeafGadget<
	F: PrimeField,
	H: FixedLengthCRH,
	HG: FixedLengthCRHGadget<H, F>,
	L: LeafCreation<H>,
> {
	field: PhantomData<F>,
	hasher: PhantomData<H>,
	hasher_gadget: PhantomData<HG>,
	leaf_creation: PhantomData<L>,
}

impl<F: PrimeField, H: FixedLengthCRH, HG: FixedLengthCRHGadget<H, F>>
	LeafCreationGadget<F, H, HG, BridgeLeaf<F, H>> for BridgeLeafGadget<F, H, HG, BridgeLeaf<F, H>>
{
	type OutputVar = OutputVar<F>;
	type PrivateVar = PrivateVar<F>;
	type PublicVar = PublicVar<F>;

	fn create(
		s: &Self::PrivateVar,
		p: &Self::PublicVar,
		h: &HG::ParametersVar,
	) -> Result<Self::OutputVar, SynthesisError> {
		let leaf_bytes = Vec::new();
		leaf_bytes.extend(s.r.to_bytes()?);
		leaf_bytes.extend(s.nullifier.to_bytes()?);
		leaf_bytes.extend(s.rho.to_bytes()?);
		leaf_bytes.extend(p.chain_id.to_bytes()?);

		let leaf_bits = vec![Boolean::new_witness(leaf_bytes.cs(), || Ok(false))?; 8];
		let mut leaf_buffer = vec![UInt8::from_bits_le(&leaf_bits); H::INPUT_SIZE_BITS / 8];

		leaf_buffer
			.iter_mut()
			.zip(leaf_bytes)
			.for_each(|(b, l_b)| *b = l_b);
		let leaf_res = HG::evaluate(h, &leaf_buffer)?;

		let mut nullifier_hash_bytes = Vec::new();
		nullifier_hash_bytes.extend(s.nullifier.to_bytes()?);
		let nullifier_hash_bits =
			vec![Boolean::new_witness(nullifier_hash_bytes.cs(), || Ok(false))?; 8];
		let mut nullifier_hash_buffer =
			vec![UInt8::from_bits_le(&nullifier_hash_bits); H::INPUT_SIZE_BITS / 8];
		nullifier_hash_buffer
			.iter_mut()
			.zip(nullifier_hash_bytes)
			.for_each(|(b, l_b)| *b = l_b);
		let leaf_res = HG::evaluate(h, &nullifier_hash_buffer)?;
		let nullifier_hash_res = HG::evaluate(h, &nullifier_hash_buffer)?;

		let a = F::from_le_bytes_mod_order(&to_bytes![leaf_res].unwrap());
		let b = F::from_le_bytes_mod_order(&to_bytes![nullifier_hash_res].unwrap());

		Self::OutputVar::new_witness(nullifier_hash_bytes.cs(), || {
			Ok(Output {
				leaf: a,
				nullifier_hash: b,
			})
		})
	}
}

impl<F: PrimeField> AllocVar<Private<F>, F> for PrivateVar<F> {
	fn new_variable<T: Borrow<Private<F>>>(
		cs: impl Into<Namespace<F>>,
		f: impl FnOnce() -> Result<T, SynthesisError>,
		_: AllocationMode,
	) -> Result<Self, SynthesisError> {
		let private = f()?.borrow().clone();
		let r = private.r;
		let nullifier = private.nullifier;
		let rho = private.rho;
		let r_var = FpVar::new_variable(cs, || Ok(r), AllocationMode::Witness)?;
		let nullifier_var =
			FpVar::new_variable(r_var.cs(), || Ok(nullifier), AllocationMode::Witness)?;
		let rho_var = FpVar::new_variable(nullifier_var.cs(), || Ok(rho), AllocationMode::Witness)?;
		Ok(PrivateVar::new(r_var, nullifier_var, rho_var))
	}
}

impl<F: PrimeField> AllocVar<Public<F>, F> for PublicVar<F> {
	fn new_variable<T: Borrow<Public<F>>>(
		cs: impl Into<Namespace<F>>,
		f: impl FnOnce() -> Result<T, SynthesisError>,
		_: AllocationMode,
	) -> Result<Self, SynthesisError> {
		let public = f()?.borrow().clone();
		let chain_id = FpVar::new_variable(cs, || Ok(public.chain_id), AllocationMode::Input)?;
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
		let nullifier_hash = FpVar::new_witness(cs, || Ok(output.nullifier_hash))?;
		Ok(OutputVar::new(leaf, nullifier_hash))
	}
}

// #[cfg(test)]
// mod test {
// 	use super::*;
// 	use crate::test_data::{get_mds_5, get_rounds_5};
// 	use ark_ed_on_bn254::Fq;
// 	use ark_ff::One;
// 	use ark_r1cs_std::R1CSVar;
// 	use ark_relations::r1cs::ConstraintSystem;
// 	use ark_std::test_rng;
// 	use webb_crypto_primitives::crh::poseidon::{
// 		constraints::{CRHGadget, PoseidonParametersVar},
// 		sbox::PoseidonSbox,
// 		PoseidonParameters, Rounds, CRH,
// 	};

// 	#[derive(Default, Clone)]
// 	struct PoseidonRounds5;

// 	impl Rounds for PoseidonRounds5 {
// 		const FULL_ROUNDS: usize = 8;
// 		const PARTIAL_ROUNDS: usize = 57;
// 		const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
// 		const WIDTH: usize = 5;
// 	}

// 	type PoseidonCRH5 = CRH<Fq, PoseidonRounds5>;
// 	type PoseidonCRH5Gadget = CRHGadget<Fq, PoseidonRounds5>;

// 	type Leaf = BridgeLeaf<Fq, PoseidonCRH5>;
// 	type LeafGadget = BridgeLeafGadget<Fq, PoseidonCRH5, PoseidonCRH5Gadget,
// Leaf>; 	#[test]
// 	fn should_crate_leaf_constraints() {
// 		let rng = &mut test_rng();

// 		let cs = ConstraintSystem::<Fq>::new_ref();

// 		let rounds = get_rounds_5::<Fq>();
// 		let mds = get_mds_5::<Fq>();
// 		let params = PoseidonParameters::<Fq>::new(rounds, mds);
// 		let params_var = PoseidonParametersVar::new_variable(
// 			cs.clone(),
// 			|| Ok(&params),
// 			AllocationMode::Constant,
// 		)
// 		.unwrap();

// 		let chain_id = Fq::one();
// 		let public = Public::new(chain_id);
// 		let public_var = PublicVar::new_input(cs.clone(), || Ok(&public)).unwrap();
// 		let secrets = Leaf::generate_secrets(rng).unwrap();
// 		let secrets_var = PrivateVar::new_witness(cs.clone(), ||
// Ok(&secrets)).unwrap();

// 		let leaf = Leaf::create(&secrets, &public, &params).unwrap();
// 		let leaf_var = LeafGadget::create(&secrets_var, &public_var,
// &params_var).unwrap();

// 		let leaf_new_var = FpVar::<Fq>::new_witness(leaf_var.cs(), ||
// Ok(leaf)).unwrap(); 		let res = leaf_var.is_eq(&leaf_new_var).unwrap();
// 		assert!(res.value().unwrap());
// 		assert!(res.cs().is_satisfied().unwrap());
// 	}
// }
