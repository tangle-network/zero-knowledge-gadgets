// I don't really know yet how to decide what needs to be imported so just
// copying: copied from arkworks-gadgets poseidon.rs
use crate::Vec;
use ark_crypto_primitives::crh::{CRHGadget, CRH};
use ark_ff::{to_bytes, PrimeField};
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, uint8::UInt8};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::marker::PhantomData;

use ark_ec::{
	models::TEModelParameters,
	twisted_edwards_extended::{GroupAffine, GroupProjective},
	PairingEngine, ProjectiveCurve,
};
use ark_plonk::circuit::{self, Circuit, PublicInputValue};

use ark_plonk::{
	constraint_system::StandardComposer,
	error::Error,
	prelude::Variable,
	proof_system::{Proof, Prover, ProverKey, Verifier, VerifierKey as PlonkVerifierKey},
};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::{
	kzg10::{self, Powers, UniversalParams},
	sonic_pc::SonicKZG10,
	PolynomialCommitment,
};
use ark_serialize::*;

#[derive(Debug, Default)]
pub struct PoseidonParameters<F: PrimeField> {
	/// The round key constants
	pub round_keys: Vec<F>,
	/// The MDS matrix to apply in the mix layer.
	pub mds_matrix: Vec<Vec<F>>,
}

pub struct PoseidonParametersVar {
	/// The round key constants
	pub round_keys: Vec<Variable>,
	/// The MDS matrix to apply in the mix layer.
	pub mds_matrix: Vec<Vec<Variable>>,
}

#[derive(Debug, Default)]
struct PoseidonCircuit<E: PairingEngine> {
	pub a: E::Fr,
	pub b: E::Fr,
	pub c: E::Fr,
	pub params: PoseidonParameters<E::Fr>,
}

//will get rid of H,HG and implement poseidonhash directly in fnc
impl<E: PairingEngine, P: TEModelParameters<BaseField = E::Fr>> Circuit<E, P>
	for PoseidonCircuit<E>
{
	const CIRCUIT_ID: [u8; 32] = [0xff; 32];

	fn gadget(&mut self, composer: &mut StandardComposer<E, P>) -> Result<(), Error> {
		let a = composer.add_input(self.a);
		let b = composer.add_input(self.b);

		let mut round_key_vars = vec![];
		for i in 0..self.params.round_keys.len() {
			let round_key = composer.add_input(self.params.round_keys[i]);
			round_key_vars.push(round_key);
		}

		let mut mds_matrix_vars = vec![];
		for i in 0..self.params.mds_matrix.len() {
			let mut mds_row_vars = vec![];
			for j in 0..self.params.mds_matrix[i].len() {
				let mds_entry = composer.add_input(self.params.mds_matrix[i][j]);
				mds_row_vars.push(mds_entry);
			}
			mds_matrix_vars.push(mds_row_vars);
		}

		// now come hashing of these

		Ok(())
	}

	fn padded_circuit_size(&self) -> usize {
		1 << 11
	}
}
