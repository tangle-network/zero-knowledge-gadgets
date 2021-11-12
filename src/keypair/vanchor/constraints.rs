use ark_crypto_primitives::{crh::CRHGadget, CRH};
use ark_ff::fields::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};

use ark_relations::r1cs::SynthesisError;
use ark_std::marker::PhantomData;

use crate::{
	keypair::constraints::KeypairCreationGadget,
	leaf::{VanchorLeafCreation, VanchorLeafCreationGadget},
};

#[derive(Clone)]
pub struct KeypairVar<
	F: PrimeField,
	H2: CRH,
	HG2: CRHGadget<H2, F>,
	H4: CRH,
	HG4: CRHGadget<H4, F>,
	H5: CRH,
	HG5: CRHGadget<H5, F>,
	L: VanchorLeafCreation<F, H2, H4, H5>,
	LG: VanchorLeafCreationGadget<F, H2, HG2, H4, HG4, H5, HG5, L>,
> {
	pubkey_var: <HG2 as CRHGadget<H2, F>>::OutputVar,
	privkey_var: FpVar<F>,
	_leaf_creation: PhantomData<L>,
	_leaf_creation_gadget: PhantomData<LG>,
	_h4: PhantomData<H4>,
	_hg4: PhantomData<HG4>,
	_h5: PhantomData<H5>,
	_hg5: PhantomData<HG5>,
}

impl<
		F: PrimeField,
		H2: CRH,
		HG2: CRHGadget<H2, F>,
		H4: CRH,
		HG4: CRHGadget<H4, F>,
		H5: CRH,
		HG5: CRHGadget<H5, F>,
		L: VanchorLeafCreation<F, H2, H4, H5>,
		LG: VanchorLeafCreationGadget<F, H2, HG2, H4, HG4, H5, HG5, L>,
	> KeypairCreationGadget<F, H2, HG2, H4, HG4, H5, HG5, L, LG>
	for KeypairVar<F, H2, HG2, H4, HG4, H5, HG5, L, LG>
{
	fn new(
		h: &HG2::ParametersVar,
		secrets: &<LG as VanchorLeafCreationGadget<F, H2, HG2, H4, HG4, H5, HG5, L>>::PrivateVar,
	) -> Result<Self, SynthesisError> {
		let privkey_var = LG::get_private_key(&secrets).unwrap();
		let mut bytes = Vec::<UInt8<F>>::new();
		bytes.extend(privkey_var.to_bytes().unwrap());
		let pubkey_var = HG2::evaluate(&h, &bytes).unwrap();
		Ok(Self {
			pubkey_var,
			privkey_var,
			_leaf_creation: PhantomData,
			_leaf_creation_gadget: PhantomData,
			_h4: PhantomData,
			_hg4: PhantomData,
			_h5: PhantomData,
			_hg5: PhantomData,
		})
	}

	fn new_from_key(h: &HG2::ParametersVar, privkey: &FpVar<F>) -> Result<Self, SynthesisError> {
		let privkey_var = privkey.clone();
		let mut bytes = Vec::<UInt8<F>>::new();
		bytes.extend(privkey_var.to_bytes().unwrap());
		let pubkey_var = HG2::evaluate(&h, &bytes).unwrap();
		Ok(Self {
			pubkey_var,
			privkey_var,
			_leaf_creation: PhantomData,
			_leaf_creation_gadget: PhantomData,
			_h4: PhantomData,
			_hg4: PhantomData,
			_h5: PhantomData,
			_hg5: PhantomData,
		})
	}

	fn public_key_var(&self) -> Result<<HG2 as CRHGadget<H2, F>>::OutputVar, SynthesisError> {
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
		utils::{
			get_mds_poseidon_bls381_x5_5, get_mds_poseidon_bn254_x5_2,
			get_rounds_poseidon_bls381_x5_5, get_rounds_poseidon_bn254_x5_2,
		},
	};
	//use ark_bls12_381::Fq;
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

	#[derive(Default, Clone)]
	struct PoseidonRounds2;

	impl Rounds for PoseidonRounds2 {
		const FULL_ROUNDS: usize = 8;
		const PARTIAL_ROUNDS: usize = 56;
		const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
		const WIDTH: usize = 2;
	}

	#[derive(Default, Clone)]
	struct PoseidonRounds4;

	impl Rounds for PoseidonRounds4 {
		const FULL_ROUNDS: usize = 8;
		const PARTIAL_ROUNDS: usize = 56;
		const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
		const WIDTH: usize = 4;
	}

	#[derive(Default, Clone)]
	struct PoseidonRounds5;

	impl Rounds for PoseidonRounds5 {
		const FULL_ROUNDS: usize = 8;
		const PARTIAL_ROUNDS: usize = 60;
		const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
		const WIDTH: usize = 5;
	}

	type PoseidonCRH2 = CRH<Fq, PoseidonRounds2>;
	type PoseidonCRH4 = CRH<Fq, PoseidonRounds4>;
	type PoseidonCRH5 = CRH<Fq, PoseidonRounds5>;

	type PoseidonCRH2Gadget = CRHGadget<Fq, PoseidonRounds2>;
	type PoseidonCRH4Gadget = CRHGadget<Fq, PoseidonRounds4>;
	type PoseidonCRH5Gadget = CRHGadget<Fq, PoseidonRounds5>;

	type Leaf = VanchorLeaf<Fq, PoseidonCRH2, PoseidonCRH4, PoseidonCRH5>;
	type LeafGadget = VanchorLeafGadget<
		Fq,
		PoseidonCRH2,
		PoseidonCRH2Gadget,
		PoseidonCRH4,
		PoseidonCRH4Gadget,
		PoseidonCRH5,
		PoseidonCRH5Gadget,
		Leaf,
	>;
	#[test]
	fn should_crate_new_public_key_var() {
		let rng = &mut test_rng();
		let cs = ConstraintSystem::<Fq>::new_ref();

		// Native version
		let rounds = get_rounds_poseidon_bn254_x5_2::<Fq>();
		let mds = get_mds_poseidon_bn254_x5_2::<Fq>();
		let params = PoseidonParameters::<Fq>::new(rounds, mds);
		let secrets = Leaf::generate_secrets(rng).unwrap();
		let prk = Leaf::get_private_key(&secrets).unwrap();
		let privkey = to_bytes![prk].unwrap();
		let pubkey = PoseidonCRH2::evaluate(&params, &privkey).unwrap();

		// Constraints version
		let secrets_var = PrivateVar::new_witness(cs.clone(), || Ok(&secrets)).unwrap();
		let bytes = to_bytes![Leaf::get_private_key(&secrets).unwrap()].unwrap();
		let privkey_var = Vec::<UInt8<Fq>>::new_witness(cs.clone(), || Ok(bytes)).unwrap();
		let params_var =
			PoseidonParametersVar::new_variable(cs, || Ok(&params), AllocationMode::Constant)
				.unwrap();
		let pubkey_var = PoseidonCRH2Gadget::evaluate(&params_var, &privkey_var).unwrap();
		let keypair = KeypairVar::<
			Fq,
			PoseidonCRH2,
			PoseidonCRH2Gadget,
			PoseidonCRH4,
			PoseidonCRH4Gadget,
			PoseidonCRH5,
			PoseidonCRH5Gadget,
			Leaf,
			LeafGadget,
		>::new(&params_var, &secrets_var)
		.unwrap();
		let new_pubkey_var = keypair.pubkey_var;
		let res = pubkey_var.is_eq(&new_pubkey_var).unwrap();

		// Check equality
		assert!(res.value().unwrap());
		assert_eq!(pubkey, new_pubkey_var.value().unwrap());
		assert!(res.cs().is_satisfied().unwrap());
	}
}
