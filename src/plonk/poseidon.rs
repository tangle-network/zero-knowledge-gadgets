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

//seems like I cannot use the same PoseidonCircuit struct b/c I need generic types with PairingEngine
// struct PoseidonCircuit<F: PrimeField, H: CRH, HG: CRHGadget<H, F>> {
// 	pub a: F,
// 	pub b: F,
// 	pub c: H::Output,
// 	pub params: H::Parameters,
// 	hasher: PhantomData<H>,
// 	hasher_gadget: PhantomData<HG>,
// }

pub trait PoseidonCRH {
    type Parameters;
    type Output;
}

struct PoseidonCircuit<E: PairingEngine, P: TEModelParameters<BaseField = E::Fr>, H: PoseidonCRH> {
    pub a: E::Fr,
    pub b: E::Fr,
    pub c: H::Output,
    pub params: H::Parameters,
}

//will get rid of H,HG and implement poseidonhash directly in fnc
    impl<E: PairingEngine, P: TEModelParameters<BaseField = E::Fr>, H: PoseidonCRH>
        Circuit<E, P, H> for PoseidonCircuit<E::Fr, P, H>
    {
        const CIRCUIT_ID: [u8; 32] = [0xff; 32];
        fn gadget(
            &mut self,
            composer: &mut StandardComposer<E, P>,
        ) -> Result<(), Error> {
            let a = composer.add_input(self.a);
            let b = composer.add_input(self.b);

            //now come hashing of these
            

        }
    }
