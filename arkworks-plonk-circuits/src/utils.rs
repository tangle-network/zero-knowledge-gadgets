use ark_ec::{models::TEModelParameters, PairingEngine};
use ark_plonk::{circuit::Circuit, constraint_system::StandardComposer, error::Error};
use ark_std::One;

#[derive(Debug, Default)]
struct IsZero<E: PairingEngine> {
	pub x: E::Fr,
	pub x_inv: E::Fr,
}

impl<E: PairingEngine, P: TEModelParameters<BaseField = E::Fr>> Circuit<E, P> for IsZero<E> {
	const CIRCUIT_ID: [u8; 32] = [0xff; 32];

	fn gadget(&mut self, composer: &mut StandardComposer<E, P>) -> Result<(), Error> {
		let x_var = composer.add_input(self.x);
		let x_inv_var = composer.add_input(self.x_inv);
		let one = composer.add_input(E::Fr::one());

		// x * x_inverse
		// -- should be 1 if x != 0
		// -- should be 0 if x == 0
		let res =
			composer.arithmetic_gate(|gate| gate.witness(x_var, x_inv_var, None).mul(E::Fr::one()));

		// b = 1 - x * x_inverse
		// will be 0 if x != 0
		// will be 1 if x == 0
		let b = composer.arithmetic_gate(|gate| {
			gate.witness(one, res, None)
				.add(E::Fr::one(), -E::Fr::one())
		});

		// ensures that x_inv is actually the inverse of x
		let b_check =
			composer.arithmetic_gate(|gate| gate.witness(x_var, b, None).mul(E::Fr::one()));
		composer.assert_equal(b_check, composer.zero_var());

		// If x is 0, b should be 1
		// If x is 1, b should be zero
		composer.assert_equal(b, one);

		Ok(())
	}

	fn padded_circuit_size(&self) -> usize {
		1 << 11
	}
}

#[cfg(test)]
mod tests {
	//copied from ark-plonk
	use super::*;
	use ark_bn254::Bn254;
	use ark_ed_on_bn254::{EdwardsParameters as JubjubParameters, Fq};
	use ark_ff::Field;
	use ark_plonk::proof_system::{Prover, Verifier};
	use ark_poly::polynomial::univariate::DensePolynomial;
	use ark_poly_commit::{
		kzg10::{self, Powers, KZG10},
		sonic_pc::SonicKZG10,
		PolynomialCommitment,
	};
	use ark_std::test_rng;

	pub(crate) fn gadget_tester<
		E: PairingEngine,
		P: TEModelParameters<BaseField = E::Fr>,
		C: Circuit<E, P>,
	>(
		circuit: &mut C,
		n: usize,
	) -> Result<(), Error> {
		let rng = &mut test_rng();
		// Common View
		let universal_params = KZG10::<E, DensePolynomial<E::Fr>>::setup(2 * n, false, rng)?;
		// Provers View
		let (proof, public_inputs) = {
			// Create a prover struct
			let mut prover = Prover::new(b"demo");

			// Additionally key the transcript
			prover.key_transcript(b"key", b"additional seed information");

			// Add gadgets
			circuit.gadget(&mut prover.mut_cs())?;

			// Commit Key
			let (ck, _) = SonicKZG10::<E, DensePolynomial<E::Fr>>::trim(
				&universal_params,
				prover.circuit_size().next_power_of_two(),
				0,
				None,
			)
			.unwrap();
			let powers = Powers {
				powers_of_g: ck.powers_of_g.into(),
				powers_of_gamma_g: ck.powers_of_gamma_g.into(),
			};
			// Preprocess circuit
			prover.preprocess(&powers)?;

			// Once the prove method is called, the public inputs are cleared
			// So pre-fetch these before calling Prove
			let public_inputs = prover.mut_cs().construct_dense_pi_vec();
			//? let lookup_table = prover.mut_cs().lookup_table.clone();

			// Compute Proof
			(prover.prove(&powers)?, public_inputs)
		};
		// Verifiers view
		//
		// Create a Verifier object
		let mut verifier = Verifier::new(b"demo");

		// Additionally key the transcript
		verifier.key_transcript(b"key", b"additional seed information");

		// Add gadgets
		circuit.gadget(&mut verifier.mut_cs())?;

		// Compute Commit and Verifier Key
		let (sonic_ck, sonic_vk) = SonicKZG10::<E, DensePolynomial<E::Fr>>::trim(
			&universal_params,
			verifier.circuit_size().next_power_of_two(),
			0,
			None,
		)
		.unwrap();
		let powers = Powers {
			powers_of_g: sonic_ck.powers_of_g.into(),
			powers_of_gamma_g: sonic_ck.powers_of_gamma_g.into(),
		};

		let vk = kzg10::VerifierKey {
			g: sonic_vk.g,
			gamma_g: sonic_vk.gamma_g,
			h: sonic_vk.h,
			beta_h: sonic_vk.beta_h,
			prepared_h: sonic_vk.prepared_h,
			prepared_beta_h: sonic_vk.prepared_beta_h,
		};

		// Preprocess circuit
		verifier.preprocess(&powers)?;

		// Verify proof
		Ok(verifier.verify(&proof, &vk, &public_inputs)?)
	}

	#[test]
	fn test_verify_iz_zero() {
		let x = Fq::from(2u32);
		let x_inv = x.inverse().unwrap();
		let mut circuit = IsZero::<Bn254> { x, x_inv };

		let res = gadget_tester::<_, JubjubParameters, _>(&mut circuit, 2000);
		assert!(res.is_ok(), "{:?}", res.err().unwrap());
	}
}
