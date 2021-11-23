use ark_crypto_primitives::{crh::CRHGadget, CRH};
use ark_ff::fields::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};

use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::{marker::PhantomData, vec::Vec};
use core::borrow::Borrow;

use super::Keypair;

#[derive(Clone)]
pub struct KeypairVar<F: PrimeField, H2: CRH, HG2: CRHGadget<H2, F>> {
	pub private_key: FpVar<F>,

	_h2: PhantomData<H2>,
	_hg2: PhantomData<HG2>,
}

impl<F: PrimeField, H2: CRH, HG2: CRHGadget<H2, F>> KeypairVar<F, H2, HG2> {
	pub fn new(private_key_in: &FpVar<F>) -> Result<Self, SynthesisError> {
		let private_key = private_key_in.clone();
		Ok(Self {
			private_key,
			_h2: PhantomData,
			_hg2: PhantomData,
		})
	}

	pub fn public_key(
		&self,
		hg2: &HG2::ParametersVar,
	) -> Result<<HG2 as CRHGadget<H2, F>>::OutputVar, SynthesisError> {
		let mut bytes = Vec::<UInt8<F>>::new();
		bytes.extend(self.private_key.to_bytes()?);
		HG2::evaluate(&hg2, &bytes)
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
		poseidon::{
			constraints::{CRHGadget, PoseidonParametersVar},
			sbox::PoseidonSbox,
			PoseidonParameters, Rounds, CRH,
		},
		utils::{get_mds_poseidon_bn254_x5_2, get_rounds_poseidon_bn254_x5_2},
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

	type PoseidonCRH2 = CRH<Fq, PoseidonRounds2>;
	type PoseidonCRH2Gadget = CRHGadget<Fq, PoseidonRounds2>;

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
		let params_var = PoseidonParametersVar::new_variable(
			cs.clone(),
			|| Ok(&params),
			AllocationMode::Constant,
		)
		.unwrap();
		let pubkey_var = PoseidonCRH2Gadget::evaluate(&params_var, &privkey_var).unwrap();
		let privkey_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(private_key)).unwrap();
		let keypair_var =
			KeypairVar::<Fq, PoseidonCRH2, PoseidonCRH2Gadget>::new(&privkey_var).unwrap();
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
}
