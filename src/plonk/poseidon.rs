// I don't really know yet how to decide what needs to be imported so just copying:
//copied from arkworks-gadgets poseidon.rs
use crate::Vec;
use ark_crypto_primitives::crh::{CRHGadget, CRH};
use ark_ff::{to_bytes, PrimeField};
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, uint8::UInt8};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::marker::PhantomData;

//copied from ark-plonk circuit.rs
use core::marker::PhantomData;

use crate::constraint_system::StandardComposer;
use crate::error::Error;
use crate::proof_system::{
    Proof, Prover, ProverKey, Verifier, VerifierKey as PlonkVerifierKey,
};
use ark_ec::models::TEModelParameters;
use ark_ec::{
    twisted_edwards_extended::{GroupAffine, GroupProjective},
    PairingEngine, ProjectiveCurve,
};
use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::kzg10::{self, Powers, UniversalParams};
use ark_poly_commit::sonic_pc::SonicKZG10;
use ark_poly_commit::PolynomialCommitment;
use ark_serialize::*;

//seems like I can use the same PoseidonCircuit struct
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

//here's where new things are needed

// FROM POSEIDON.RS
// impl<F: PrimeField, H: CRH, HG: CRHGadget<H, F>> ConstraintSynthesizer<F>
// 	for PoseidonCircuit<F, H, HG>
// {
// 	fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
// 		let res_target = HG::OutputVar::new_input(cs.clone(), || Ok(&self.c))?;

// 		let bytes = to_bytes![self.a, self.b].unwrap();
// 		let input = Vec::<UInt8<F>>::new_witness(cs.clone(), || Ok(bytes))?;

// 		let params_var = HG::ParametersVar::new_witness(cs.clone(), || Ok(self.params))?;
// 		let res_var = HG::evaluate(&params_var, &input)?;

// 		res_var.enforce_equal(&res_target)?;

// 		Ok(())
// 	}
// }

//FROM ARK-PLONK TEST
// pub struct TestCircuit<
//         E: PairingEngine,
//         P: TEModelParameters<BaseField = E::Fr>,
//     > {
//         a: E::Fr,
//         b: E::Fr,
//         c: E::Fr,
//         d: E::Fr,
//         e: P::ScalarField,
//         f: GroupAffine<P>,
//     }
//     impl<E: PairingEngine, P: TEModelParameters<BaseField = E::Fr>> Default
//         for TestCircuit<E, P>
//     {
//         fn default() -> Self {
//             Self {
//                 a: E::Fr::zero(),
//                 b: E::Fr::zero(),
//                 c: E::Fr::zero(),
//                 d: E::Fr::zero(),
//                 e: P::ScalarField::zero(),
//                 f: GroupAffine::<P>::zero(),
//             }
//         }
//     }
//     impl<E: PairingEngine, P: TEModelParameters<BaseField = E::Fr>>
//         Circuit<E, P> for TestCircuit<E, P>
//     {
//         const CIRCUIT_ID: [u8; 32] = [0xff; 32];
//         fn gadget(
//             &mut self,
//             composer: &mut StandardComposer<E, P>,
//         ) -> Result<(), Error> {
//             let a = composer.add_input(self.a);
//             let b = composer.add_input(self.b);

//             // Make first constraint a + b = c (as public input)
//             let add_result = composer.add(
//                 (E::Fr::one(), a),
//                 (E::Fr::one(), b),
//                 E::Fr::zero(),
//                 Some(-self.c),
//             );
//             composer.assert_equal(add_result, composer.zero_var());

//             // Check that a and b are in range
//             composer.range_gate(a, 1 << 6);
//             composer.range_gate(b, 1 << 5);
//             // Make second constraint a * b = d
//             let mul_result =
//                 composer.mul(E::Fr::one(), a, b, E::Fr::zero(), Some(-self.d));
//             composer.assert_equal(mul_result, composer.zero_var());

//             let e = composer
//                 .add_input(util::from_embedded_curve_scalar::<E, P>(self.e));
//             let (x, y) = P::AFFINE_GENERATOR_COEFFS;
//             let generator = GroupAffine::new(x, y);
//             let scalar_mul_result =
//                 composer.fixed_base_scalar_mul(e, generator);

//             // Apply the constrain
//             composer.assert_equal_public_point(scalar_mul_result, self.f);
//             Ok(())
//         }
//         fn padded_circuit_size(&self) -> usize {
//             1 << 11
//         }
//     }