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

pub struct NewLeafGadget<F: PrimeField, H: CRH, HG: CRHGadget<H, F>> {
	private: PrivateVar<F>,
	public: PublicVar<F>,
	hasher: PhantomData<H>,
	hasher_gadget: PhantomData<HG>,
}

impl<F: PrimeField, H: CRH, HG: CRHGadget<H, F>> NewLeafGadget<F, H, HG> {
	pub fn new(private: PrivateVar<F>, public: PublicVar<F>) -> Self {
		Self {
			private,
			public,
			hasher: PhantomData,
			hasher_gadget: PhantomData,
		}
	}

	pub fn create_leaf(
		&self,
		pubkey: &HG::OutputVar,
		h: &HG::ParametersVar,
	) -> Result<HG::OutputVar, SynthesisError> {
		let mut bytes = Vec::new();
		bytes.extend(self.public.chain_id.to_bytes()?);
		bytes.extend(self.private.amount.to_bytes()?);
		bytes.extend(pubkey.to_bytes()?);
		bytes.extend(self.private.blinding.to_bytes()?);
		HG::evaluate(h, &bytes)
	}

	pub fn create_nullifier(
		&self,
		leaf: &HG::OutputVar,
		h: &HG::ParametersVar,
		index: &FpVar<F>,
	) -> Result<HG::OutputVar, SynthesisError> {
		let mut bytes = Vec::new();
		bytes.extend(leaf.to_bytes()?);
		bytes.extend(index.to_bytes()?);
		bytes.extend(self.private.priv_key.to_bytes()?);
		HG::evaluate(h, &bytes)
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
		leaf::newleaf::NewLeaf,
		poseidon::{
			constraints::{CRHGadget, PoseidonParametersVar},
			sbox::PoseidonSbox,
			PoseidonParameters, Rounds, CRH,
		},
		utils::{get_mds_poseidon_bls381_x5_5, get_rounds_poseidon_bls381_x5_5},
	};
	use ark_bls12_381::Fq;
	use ark_crypto_primitives::crh::{constraints::CRHGadget as CRHGadgetTrait, CRH as CRHTrait};
	use ark_ff::to_bytes;
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

	type Leaf = NewLeaf<Fq, PoseidonCRH3>;
	type LeafGadget = NewLeafGadget<Fq, PoseidonCRH3, PoseidonCRH3Gadget>;
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
		let private = Private::generate(rng);
		let privkey = to_bytes![private.priv_key].unwrap();
		let pubkey = PoseidonCRH3::evaluate(&params, &privkey).unwrap();

		let leaf_hash = Leaf::create_leaf(&private, &public, &pubkey, &params).unwrap();

		// Constraints version
		let index_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(index)).unwrap();
		let public_var = PublicVar::new_input(cs.clone(), || Ok(&public)).unwrap();
		let private_var = PrivateVar::new_witness(cs.clone(), || Ok(&private)).unwrap();
		let bytes = to_bytes![private.priv_key].unwrap();
		let privkey_var = Vec::<UInt8<Fq>>::new_witness(cs.clone(), || Ok(bytes)).unwrap();
		let params_var = PoseidonParametersVar::new_variable(
			cs.clone(),
			|| Ok(&params),
			AllocationMode::Constant,
		)
		.unwrap();
		let pubkey_var = PoseidonCRH3Gadget::evaluate(&params_var, &privkey_var).unwrap();

		let leaf_var = LeafGadget::new(private_var, public_var);
		let leaf_hash_var = leaf_var.create_leaf(&pubkey_var, &params_var).unwrap();

		// Check equality
		let leaf_new_hash_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(leaf_hash)).unwrap();
		let res = leaf_hash_var.is_eq(&leaf_new_hash_var).unwrap();
		assert!(res.value().unwrap());
		assert!(res.cs().is_satisfied().unwrap());

		// Test Nullifier
		// Native version
		let nullifier = Leaf::create_nullifier(&private, &leaf_hash, &params, &index).unwrap();

		// Constraints version
		let nullifier_var = leaf_var
			.create_nullifier(&leaf_hash_var, &params_var, &index_var)
			.unwrap();

		// Check equality
		let nullifier_new_var =
			FpVar::<Fq>::new_witness(nullifier_var.cs(), || Ok(nullifier)).unwrap();
		let res_nul = nullifier_var.is_eq(&nullifier_new_var).unwrap();
		assert!(res_nul.value().unwrap());
		assert!(res_nul.cs().is_satisfied().unwrap());
	}
}
