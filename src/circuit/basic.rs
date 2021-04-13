use ark_ff::PrimeField;
use ark_relations::{
	lc,
	r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};

#[derive(Copy)]
struct DummyCircuit<F: PrimeField> {
	pub a: Option<F>,
	pub b: Option<F>,
	pub num_variables: usize,
	pub num_constraints: usize,
}

impl<F: PrimeField> Clone for DummyCircuit<F> {
	fn clone(&self) -> Self {
		DummyCircuit {
			a: self.a.clone(),
			b: self.b.clone(),
			num_variables: self.num_variables.clone(),
			num_constraints: self.num_constraints.clone(),
		}
	}
}

impl<F: PrimeField> ConstraintSynthesizer<F> for DummyCircuit<F> {
	fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
		let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
		let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
		let c = cs.new_input_variable(|| {
			let a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
			let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

			Ok(a * b)
		})?;

		for _ in 0..self.num_constraints {
			cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
		}

		Ok(())
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use ark_bls12_381::{Bls12_381, Fr as BlsFr};
	use ark_marlin::Marlin;
	use ark_poly::univariate::DensePolynomial;
	use ark_poly_commit::marlin_pc::MarlinKZG10;
	use ark_std::{ops::Mul, UniformRand};
	use blake2::Blake2s;
	#[test]
	fn should_verify_basic_circuit() {
		let rng = &mut ark_std::test_rng();

		let nc = 3;
		let nv = 3;
		let c = DummyCircuit::<BlsFr> {
			a: Some(BlsFr::rand(rng)),
			b: Some(BlsFr::rand(rng)),
			num_variables: nv,
			num_constraints: nc,
		};

		type KZG10 = MarlinKZG10<Bls12_381, DensePolynomial<BlsFr>>;
		type MarlinSetup = Marlin<BlsFr, KZG10, Blake2s>;

		let srs = MarlinSetup::universal_setup(nc, nc, nc, rng).unwrap();
		let (pk, vk) = MarlinSetup::index(&srs, c).unwrap();
		let proof = MarlinSetup::prove(&pk, c.clone(), rng).unwrap();

		let v = c.a.unwrap().mul(c.b.unwrap());

		let _ = MarlinSetup::verify(&vk, &vec![v], &proof, rng).unwrap();
	}
}
