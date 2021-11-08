use ark_crypto_primitives::{crh::CRHGadget, CRH};
use ark_ff::fields::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};

use ark_relations::r1cs::SynthesisError;
use ark_std::marker::PhantomData;

use crate::leaf::{VanchorLeafCreation, VanchorLeafCreationGadget};

#[derive(Clone)]
pub struct KeypairVar<
	H: CRH,
	HG: CRHGadget<H, F>,
	L: VanchorLeafCreation<H, F>,
	LG: VanchorLeafCreationGadget<F, H, HG, L>,
	F: PrimeField,
> {
	pubkey_var: <HG as CRHGadget<H, F>>::OutputVar,
	privkey_var: FpVar<F>,
	_leaf_creation: PhantomData<L>,
	_leaf_creation_gadget: PhantomData<LG>,
}

pub trait KeypairCreationGadget<
	H: CRH,
	HG: CRHGadget<H, F>,
	F: PrimeField,
	L: VanchorLeafCreation<H, F>,
	LG: VanchorLeafCreationGadget<F, H, HG, L>,
>: Sized
{
	fn new(
		h: &HG::ParametersVar,
		secrets: &<LG as VanchorLeafCreationGadget<F, H, HG, L>>::PrivateVar,
	) -> Result<Self, SynthesisError>;
	fn public_key_var(&self) -> Result<<HG as CRHGadget<H, F>>::OutputVar, SynthesisError>;
	fn private_key_var(&self) -> Result<FpVar<F>, SynthesisError>;
}

impl<
		H: CRH,
		HG: CRHGadget<H, F>,
		F: PrimeField,
		L: VanchorLeafCreation<H, F>,
		LG: VanchorLeafCreationGadget<F, H, HG, L>,
	> KeypairCreationGadget<H, HG, F, L, LG> for KeypairVar<H, HG, L, LG, F>
{
	fn new(
		h: &HG::ParametersVar,
		secrets: &<LG as VanchorLeafCreationGadget<F, H, HG, L>>::PrivateVar,
	) -> Result<Self, SynthesisError> {
		let privkey_var = LG::get_private_key(&secrets).unwrap();
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

	fn public_key_var(&self) -> Result<<HG as CRHGadget<H, F>>::OutputVar, SynthesisError> {
		Ok(self.pubkey_var.clone())
	}

	fn private_key_var(&self) -> Result<FpVar<F>, SynthesisError> {
		Ok(self.privkey_var.clone())
	}
}

#[cfg(feature = "default_poseidon")]
#[cfg(test)]
mod test {
	use super::*;
	use crate::{
		leaf::vanchor::{
			constraints::{PrivateVar, VanchorLeafGadget},
			VanchorLeaf,
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

	type Leaf = VanchorLeaf<Fq, PoseidonCRH3>;
	type LeafGadget = VanchorLeafGadget<Fq, PoseidonCRH3, PoseidonCRH3Gadget, Leaf>;
	#[test]
	fn should_crate_new_public_key_var() {
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
		let keypair = KeypairVar::<PoseidonCRH3, PoseidonCRH3Gadget, Leaf, LeafGadget, Fq>::new(
			&params_var,
			&secrets_var,
		)
		.unwrap();
		let new_pubkey_var = keypair.pubkey_var;
		let res = pubkey_var.is_eq(&new_pubkey_var).unwrap();

		// Check equality
		assert!(res.value().unwrap());
		assert_eq!(pubkey, new_pubkey_var.value().unwrap());
		assert!(res.cs().is_satisfied().unwrap());
	}
}
