use ark_crypto_primitives::{crh::CRHGadget, CRH};
use ark_ff::fields::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};

use ark_relations::r1cs::SynthesisError;
use ark_std::marker::PhantomData;

use crate::leaf::vanchor::constraints::{PrivateVar, VAnchorLeafGadget};

#[derive(Clone)]
pub struct KeypairVar<
	F: PrimeField,
	BG: ToBytesGadget<F>+Clone,
	H2: CRH,
	HG2: CRHGadget<H2, F>,
	H4: CRH,
	HG4: CRHGadget<H4, F>,
	H5: CRH,
	HG5: CRHGadget<H5, F>,
> {
	private_key:BG,

	_d: PhantomData<F>,
	_h2: PhantomData<H2>,
	_hg2: PhantomData<HG2>,
	_h4: PhantomData<H4>,
	_hg4: PhantomData<HG4>,
	_h5: PhantomData<H5>,
	_hg5: PhantomData<HG5>,
}

impl<
		F: PrimeField,
		BG:  ToBytesGadget<F> + Clone,
		H2: CRH,
		HG2: CRHGadget<H2, F>,
		H4: CRH,
		HG4: CRHGadget<H4, F>,
		H5: CRH,
		HG5: CRHGadget<H5, F>,
	> KeypairVar<F, BG, H2, HG2, H4, HG4, H5, HG5>
{
	fn new(
		private_key: BG,
	) -> Result<Self, SynthesisError> {
		
		Ok(Self {
			private_key,
			_d: PhantomData,
			_h2: PhantomData,
			_hg2: PhantomData,
			_h4: PhantomData,
			_hg4: PhantomData,
			_h5: PhantomData,
			_hg5: PhantomData,
		})
	}

	fn public_key(&self, hg2: &HG2::ParametersVar) -> Result<<HG2 as CRHGadget<H2, F>>::OutputVar, SynthesisError> {
		let privkey_var = &self.private_key;
		let mut bytes = Vec::<UInt8<F>>::new();
		bytes.extend(privkey_var.to_bytes().unwrap());
		let pubkey_var = HG2::evaluate(&hg2, &bytes).unwrap();
		Ok(pubkey_var)
	}

	fn private_key(&self) -> Result<&BG, SynthesisError> {
		Ok(&self.private_key)
	}
}

#[cfg(feature = "default_poseidon")]
#[cfg(test)]
mod test {
	use super::*;
	use crate::{poseidon::{
			constraints::{CRHGadget, PoseidonParametersVar},
			sbox::PoseidonSbox,
			PoseidonParameters, Rounds, CRH,
		}, utils::{
			 get_mds_poseidon_bn254_x5_2,
			 get_rounds_poseidon_bn254_x5_2,
		}};
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

	use crate::ark_std::UniformRand;
	#[test]
	fn should_crate_new_public_key_var() {
		let rng = &mut test_rng();
		let cs = ConstraintSystem::<Fq>::new_ref();

		// Native version
		let rounds = get_rounds_poseidon_bn254_x5_2::<Fq>();
		let mds = get_mds_poseidon_bn254_x5_2::<Fq>();
		let params = PoseidonParameters::<Fq>::new(rounds, mds);
		let private_key = Fq::rand(rng);

		let privkey = to_bytes![private_key].unwrap();
		let pubkey = PoseidonCRH2::evaluate(&params, &privkey).unwrap();
		// Constraints version
		let bytes = to_bytes![private_key].unwrap();
		let privkey_var = Vec::<UInt8<Fq>>::new_witness(cs.clone(), || Ok(bytes)).unwrap();		
		let params_var =
			PoseidonParametersVar::new_variable(cs.clone(), || Ok(&params), AllocationMode::Constant)
				.unwrap();
		let pubkey_var = PoseidonCRH2Gadget::evaluate(&params_var, &privkey_var).unwrap();
		let privkey_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(private_key)).unwrap();		
		let keypair_var = KeypairVar::<
			Fq,
			FpVar<Fq>,
			PoseidonCRH2,
			PoseidonCRH2Gadget,
			PoseidonCRH4,
			PoseidonCRH4Gadget,
			PoseidonCRH5,
			PoseidonCRH5Gadget,
		>::new( privkey_var.clone())
		.unwrap();
		let new_pubkey_var = keypair_var.public_key(&params_var).unwrap();
		let res = pubkey_var.is_eq(&new_pubkey_var).unwrap();

		// Check equality
		assert!(res.value().unwrap());
		assert_eq!(pubkey, new_pubkey_var.value().unwrap());
		assert!(res.cs().is_satisfied().unwrap());

		let new_private_key = keypair_var.private_key().unwrap();
		let res2 = new_private_key.is_eq(&privkey_var).unwrap();
		assert!(res2.value().unwrap());
		assert_eq!(private_key, new_private_key.value().unwrap());
		assert!(res2.cs().is_satisfied().unwrap());
	}
}
