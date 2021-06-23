use crate::Vec;
use ark_crypto_primitives::crh::{CRHGadget, CRH};
use ark_ff::{to_bytes, PrimeField};
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, uint8::UInt8};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::marker::PhantomData;

#[derive(Copy)]
struct PoseidonCircuit<F: PrimeField, H: CRH, HG: CRHGadget<H, F>> {
	pub a: F,
	pub b: F,
	pub c: H::Output,
	pub params: H::Parameters,
	hasher: PhantomData<H>,
	hasher_gadget: PhantomData<HG>,
}

impl<F: PrimeField, H: CRH, HG: CRHGadget<H, F>> PoseidonCircuit<F, H, HG> {
	pub fn new(a: F, b: F, c: H::Output, params: H::Parameters) -> Self {
		Self {
			a,
			b,
			c,
			params,
			hasher: PhantomData,
			hasher_gadget: PhantomData,
		}
	}
}

impl<F: PrimeField, H: CRH, HG: CRHGadget<H, F>> Clone for PoseidonCircuit<F, H, HG> {
	fn clone(&self) -> Self {
		PoseidonCircuit {
			a: self.a.clone(),
			b: self.b.clone(),
			c: self.c.clone(),
			params: self.params.clone(),
			hasher: PhantomData,
			hasher_gadget: PhantomData,
		}
	}
}

impl<F: PrimeField, H: CRH, HG: CRHGadget<H, F>> ConstraintSynthesizer<F>
	for PoseidonCircuit<F, H, HG>
{
	fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
		let res_target = HG::OutputVar::new_input(cs.clone(), || Ok(&self.c))?;

		let bytes = to_bytes![self.a, self.b].unwrap();
		let input = Vec::<UInt8<F>>::new_witness(cs.clone(), || Ok(bytes))?;

		let params_var = HG::ParametersVar::new_witness(cs.clone(), || Ok(self.params))?;
		let res_var = HG::evaluate(&params_var, &input)?;

		res_var.enforce_equal(&res_target)?;

		Ok(())
	}
}

#[cfg(feature = "default_poseidon")]
#[cfg(test)]
mod test {
	use super::*;
	use crate::{
		poseidon::{constraints::CRHGadget, sbox::PoseidonSbox, PoseidonParameters, Rounds, CRH},
		utils::{get_mds_3, get_rounds_3},
	};
	use ark_bls12_381::{Bls12_381, Fr as BlsFr};
	use ark_crypto_primitives::{crh::CRH as CRHTrait, SNARK};
	use ark_groth16::Groth16;
	use ark_marlin::Marlin;
	use ark_poly::univariate::DensePolynomial;
	use ark_poly_commit::marlin_pc::MarlinKZG10;
	use ark_std::UniformRand;
	use blake2::Blake2s;

	#[derive(Default, Clone)]
	struct PoseidonRounds3;

	impl Rounds for PoseidonRounds3 {
		const FULL_ROUNDS: usize = 8;
		const PARTIAL_ROUNDS: usize = 57;
		const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
		const WIDTH: usize = 3;
	}

	type PoseidonCRH3 = CRH<BlsFr, PoseidonRounds3>;
	type PoseidonCRH3Gadget = CRHGadget<BlsFr, PoseidonRounds3>;
	type PoseidonC = PoseidonCircuit<BlsFr, PoseidonCRH3, PoseidonCRH3Gadget>;

	#[test]
	fn should_verify_poseidon_circuit() {
		let rng = &mut ark_std::test_rng();

		let a = BlsFr::rand(rng);
		let b = BlsFr::rand(rng);
		let bytes = to_bytes![a, b].unwrap();
		let rounds3 = get_rounds_3::<BlsFr>();
		let mds3 = get_mds_3::<BlsFr>();
		let parameters = PoseidonParameters::<BlsFr>::new(rounds3, mds3);
		let c = PoseidonCRH3::evaluate(&parameters, &bytes).unwrap();
		let nc = 3000;
		let nv = 2;
		let circuit = PoseidonC::new(a, b, c, parameters);

		type KZG10 = MarlinKZG10<Bls12_381, DensePolynomial<BlsFr>>;
		type MarlinSetup = Marlin<BlsFr, KZG10, Blake2s>;

		let srs = MarlinSetup::universal_setup(nc, nv, nv, rng).unwrap();
		let (pk, vk) = MarlinSetup::index(&srs, circuit.clone()).unwrap();
		let proof = MarlinSetup::prove(&pk, circuit, rng).unwrap();

		let res = MarlinSetup::verify(&vk, &vec![c], &proof, rng).unwrap();
		assert!(res);
	}

	#[test]
	fn should_verify_poseidon_circuit_groth16() {
		let rng = &mut ark_std::test_rng();

		let a = BlsFr::rand(rng);
		let b = BlsFr::rand(rng);
		let bytes = to_bytes![a, b].unwrap();
		let rounds3 = get_rounds_3::<BlsFr>();
		let mds3 = get_mds_3::<BlsFr>();
		let parameters = PoseidonParameters::<BlsFr>::new(rounds3, mds3);
		let c = PoseidonCRH3::evaluate(&parameters, &bytes).unwrap();
		let circuit = PoseidonC::new(a, b, c, parameters);

		type GrothSetup = Groth16<Bls12_381>;

		let (pk, vk) = GrothSetup::circuit_specific_setup(circuit.clone(), rng).unwrap();
		let proof = GrothSetup::prove(&pk, circuit, rng).unwrap();

		let res = GrothSetup::verify(&vk, &vec![c], &proof).unwrap();
		assert!(res);
	}
}
