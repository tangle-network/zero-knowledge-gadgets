use ark_crypto_primitives::{crh::CRHGadget, CRH};
use ark_ff::fields::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};

use ark_relations::r1cs::SynthesisError;
use ark_std::marker::PhantomData;

use crate::leaf::{NewLeafCreation, NewLeafCreationGadget};

#[derive(Clone)]
pub struct KeypairsVar<
	H: CRH,
	HG: CRHGadget<H, F>,
	L: NewLeafCreation<H>,
	LG: NewLeafCreationGadget<F, H, HG, L>,
	F: PrimeField,
> {
	pubkey_var: <HG as CRHGadget<H, F>>::OutputVar,
	privkey_var: FpVar<F>,
	_leaf_creation: PhantomData<L>,
	_leaf_creation_gadget: PhantomData<LG>,
}

pub trait KeypairsCreationGadget<H: CRH, HG: CRHGadget<H, F>, F: PrimeField, L: NewLeafCreation<H>, LG: NewLeafCreationGadget<F, H, HG, L>>: Sized {
	fn public_key_var(
		h: &HG::ParametersVar,
		secrets: &<LG as NewLeafCreationGadget<F, H, HG, L>>::PrivateVar,
	) -> Result<Self, SynthesisError>;
}

impl<
		H: CRH,
		HG: CRHGadget<H, F>,
		F: PrimeField,
		L: NewLeafCreation<H>,
		LG: NewLeafCreationGadget<F, H, HG, L>,
	> KeypairsCreationGadget<H, HG, F, L, LG> for KeypairsVar<H, HG, L, LG, F>
{
	fn public_key_var(
		h: &HG::ParametersVar,
		secrets: &<LG as NewLeafCreationGadget<F, H, HG, L>>::PrivateVar,
	) -> Result<Self, SynthesisError> {
		let privkey_var = LG::get_privat_key(&secrets).unwrap();
		let mut bytes = Vec::<UInt8<F>>::new();
		bytes.extend(privkey_var.to_bytes().unwrap());
		let pubkey_var = HG::evaluate(&h, &bytes).unwrap();
		Ok(Self {
			pubkey_var,
			privkey_var,
			_leaf_creation: PhantomData,
			_leaf_creation_gadget: PhantomData,
		})
		
	}
}

#[cfg(feature = "default_poseidon")]
#[cfg(test)]
mod test {
	use super::*;
	use crate::{
		leaf::newleaf::{
			constraints::{NewLeafGadget, PrivateVar},
			NewLeaf,
		},
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
	use ark_r1cs_std::{
		alloc::{AllocVar, AllocationMode},
		prelude::EqGadget,
		R1CSVar,
	};
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
	type LeafGadget = NewLeafGadget<Fq, PoseidonCRH3, PoseidonCRH3Gadget, Leaf>;
	#[test]
	fn should_crate_new_public_key() {
		let rng = &mut test_rng();
		let cs = ConstraintSystem::<Fq>::new_ref();

		// Native version
		let rounds = get_rounds_poseidon_bls381_x5_5::<Fq>();
		let mds = get_mds_poseidon_bls381_x5_5::<Fq>();
		let params = PoseidonParameters::<Fq>::new(rounds, mds);
		let secrets = Leaf::generate_secrets(rng).unwrap();
		let privkey = to_bytes![secrets.priv_key].unwrap();
		let pubkey = PoseidonCRH3::evaluate(&params, &privkey).unwrap();

		// Constraints version
		let secrets_var = PrivateVar::new_witness(cs.clone(), || Ok(&secrets)).unwrap();
		let bytes = to_bytes![secrets.priv_key].unwrap();
		let privkey_var = Vec::<UInt8<Fq>>::new_witness(cs.clone(), || Ok(bytes)).unwrap();
		let params_var =
			PoseidonParametersVar::new_variable(cs, || Ok(&params), AllocationMode::Constant)
				.unwrap();
		let pubkey_var = PoseidonCRH3Gadget::evaluate(&params_var, &privkey_var).unwrap();
		let keypairs =
			KeypairsVar::<PoseidonCRH3, PoseidonCRH3Gadget, Leaf, LeafGadget, Fq>::public_key_var(
				&params_var,
				&secrets_var,
			).unwrap();
		let new_pubkey_var = keypairs.pubkey_var;
		let res = pubkey_var.is_eq(&new_pubkey_var).unwrap();

		// Check equality
		assert!(res.value().unwrap());
		assert_eq!(pubkey, new_pubkey_var.value().unwrap());
		assert!(res.cs().is_satisfied().unwrap());
	}
}
