use crate::Vec;
use ark_crypto_primitives::crh::{CRHGadget as CRHTraitGadget, CRH as CRHTrait};
use ark_ff::{to_bytes, PrimeField};
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, uint8::UInt8};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::marker::PhantomData;

#[derive(Copy)]
struct PoseidonCircuit<F: PrimeField, H: CRHTrait, HG: CRHTraitGadget<H, F>> {
	pub a: F,
	pub b: F,
	pub c: H::Output,
	pub params: H::Parameters,
	hasher: PhantomData<H>,
	hasher_gadget: PhantomData<HG>,
}

impl<F: PrimeField, H: CRHTrait, HG: CRHTraitGadget<H, F>> PoseidonCircuit<F, H, HG> {
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

impl<F: PrimeField, H: CRHTrait, HG: CRHTraitGadget<H, F>> Clone for PoseidonCircuit<F, H, HG> {
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

impl<F: PrimeField, H: CRHTrait, HG: CRHTraitGadget<H, F>> ConstraintSynthesizer<F>
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
	use ark_bls12_381::{Bls12_381, Fr as BlsFr};
	use ark_crypto_primitives::SNARK;
	use ark_groth16::Groth16;
	use ark_marlin::Marlin;
	use ark_poly::univariate::DensePolynomial;
	use ark_poly_commit::marlin_pc::MarlinKZG10;
	use ark_std::UniformRand;
	use arkworks_gadgets::poseidon::{constraints::CRHGadget, CRH};
	use arkworks_utils::utils::common::{setup_params_x5_3, Curve};
	use blake2::Blake2s;

	type PoseidonCRH = CRH<BlsFr>;
	type PoseidonCRHGadget = CRHGadget<BlsFr>;
	type PoseidonC = PoseidonCircuit<BlsFr, PoseidonCRH, PoseidonCRHGadget>;

	#[test]
	fn should_verify_poseidon_circuit() {
		let rng = &mut ark_std::test_rng();
		let curve = Curve::Bls381;

		let a = BlsFr::rand(rng);
		let b = BlsFr::rand(rng);
		let bytes = to_bytes![a, b].unwrap();
		let parameters = setup_params_x5_3(curve);

		let c = PoseidonCRH::evaluate(&parameters, &bytes).unwrap();
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
		let curve = Curve::Bls381;

		let a = BlsFr::rand(rng);
		let b = BlsFr::rand(rng);
		let bytes = to_bytes![a, b].unwrap();
		let parameters = setup_params_x5_3(curve);

		let c = PoseidonCRH::evaluate(&parameters, &bytes).unwrap();
		let circuit = PoseidonC::new(a, b, c, parameters);

		type GrothSetup = Groth16<Bls12_381>;

		let (pk, vk) = GrothSetup::circuit_specific_setup(circuit.clone(), rng).unwrap();
		let proof = GrothSetup::prove(&pk, circuit, rng).unwrap();

		let res = GrothSetup::verify(&vk, &vec![c], &proof).unwrap();
		assert!(res);
	}
}
