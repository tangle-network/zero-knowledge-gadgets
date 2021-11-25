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

	pub fn signature<
		BG: ToBytesGadget<F>,
		H4: CRH,
		HG4: CRHGadget<H4, F>,
		H5: CRH,
		HG5: CRHGadget<H5, F>,
	>(
		&self,
		commitment: &HG5::OutputVar,
		index: &FpVar<F>,
		h_w4: &HG4::ParametersVar,
	) -> Result<HG4::OutputVar, SynthesisError> {
		let mut bytes = Vec::new();
		bytes.extend(self.private_key.clone().to_bytes()?);
		bytes.extend(commitment.to_bytes()?);
		bytes.extend(index.to_bytes()?);
		HG4::evaluate(h_w4, &bytes)
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
		ark_std::Zero,
		poseidon::{
			constraints::{CRHGadget, PoseidonParametersVar},
			sbox::PoseidonSbox,
			PoseidonParameters, Rounds, CRH,
		},
		utils::{
			get_mds_poseidon_bn254_x5_2, get_mds_poseidon_bn254_x5_4,
			get_rounds_poseidon_bn254_x5_2, get_rounds_poseidon_bn254_x5_4,
		},
	};
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

	#[test]
	fn should_crate_new_signature_var() {
		let rng = &mut test_rng();
		let cs = ConstraintSystem::<Fq>::new_ref();

		// Native version
		let rounds = get_rounds_poseidon_bn254_x5_4::<Fq>();
		let mds = get_mds_poseidon_bn254_x5_4::<Fq>();
		let params = PoseidonParameters::<Fq>::new(rounds, mds);
		let private_key = Fq::rand(rng);
		let commitment = Fq::rand(rng);
		let index = Fq::zero();

		let keypair = Keypair::<Fq, PoseidonCRH2>::new(private_key.clone());
		let signature = keypair
			.signature::<PoseidonCRH4, PoseidonCRH5>(&commitment, &index, &params)
			.unwrap();

		// Constraints version
		let params_var = PoseidonParametersVar::new_variable(
			cs.clone(),
			|| Ok(&params),
			AllocationMode::Constant,
		)
		.unwrap();
		let privkey_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(private_key)).unwrap();
		let commitment_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(commitment)).unwrap();
		let index_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(index)).unwrap();

		let keypair_var =
			KeypairVar::<Fq, PoseidonCRH2, PoseidonCRH2Gadget>::new(&privkey_var).unwrap();

		let signature_var = FpVar::<Fq>::new_witness(cs.clone(), || Ok(signature)).unwrap();
		let new_signature_var = keypair_var
			.signature::<FpVar<Fq>, PoseidonCRH4, PoseidonCRH4Gadget, PoseidonCRH5, PoseidonCRH5Gadget>(
				&commitment_var,
				&index_var,
				&params_var,
			)
			.unwrap();

		// Check equality
		let res = new_signature_var.is_eq(&signature_var).unwrap();
		assert!(res.value().unwrap());
		assert_eq!(signature, new_signature_var.value().unwrap());
		assert!(res.cs().is_satisfied().unwrap());
	}
}
