use ark_ec::{models::TEModelParameters, PairingEngine};
use ark_plonk::{
	circuit::Circuit, constraint_system::StandardComposer, error::Error, prelude::Variable,
};
use ark_std::{marker::PhantomData, vec::Vec, One, Zero};

#[derive(Debug, Default)]
struct SetMembershipCircuit<E: PairingEngine, P: TEModelParameters<BaseField = E::Fr>> {
	pub roots: Vec<E::Fr>,
	pub target: E::Fr,
	pub _te: PhantomData<P>,
}

impl<E: PairingEngine, P: TEModelParameters<BaseField = E::Fr>> Circuit<E, P>
	for SetMembershipCircuit<E, P>
{
	const CIRCUIT_ID: [u8; 32] = [0xff; 32];

	fn gadget(&mut self, composer: &mut StandardComposer<E, P>) -> Result<(), Error> {
		let roots: Vec<Variable> = self.roots.iter().map(|x| composer.add_input(*x)).collect();
		let target = composer.add_input(self.target);

		let mut diffs = Vec::new();
		for x in roots {
			let diff = composer.add(
				(-E::Fr::one(), target),
				(E::Fr::one(), x),
				E::Fr::zero(),
				None,
			);
			diffs.push(diff);
		}

		let mut sum = composer.add_input(E::Fr::one());

		for diff in diffs {
			sum = composer.mul(E::Fr::one(), sum, diff, E::Fr::zero(), None);
		}

		composer.assert_equal(sum, composer.zero_var());

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
	use ark_plonk::proof_system::{Prover, Verifier};
	use ark_poly::polynomial::univariate::DensePolynomial;
	use ark_poly_commit::{
		kzg10::{self, Powers, KZG10},
		sonic_pc::SonicKZG10,
		PolynomialCommitment,
	};

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
		let universal_params = KZG10::<E, DensePolynomial<E::Fr>>::setup(2 * n, false, &mut rng)?;
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
	fn test_verify_set_membership() {
		let roots = vec![Fq::from(1u32), Fq::from(2u32), Fq::from(3u32)];
		let target = Fq::from(2u32);
		let mut circuit = SetMembershipCircuit::<Bn254, JubjubParameters> {
			roots,
			target,
			_te: PhantomData,
		};

		let res = gadget_tester(&mut circuit, 2000);
		assert!(res.is_ok(), "{:?}", res.err().unwrap());
	}

	#[test]
	fn test_fail_to_verify_invalid_set_membership() {
		let roots = vec![Fq::from(1u32), Fq::from(2u32), Fq::from(3u32)];
		// Not in the set
		let target = Fq::from(4u32);
		let mut circuit = SetMembershipCircuit::<Bn254, JubjubParameters> {
			roots,
			target,
			_te: PhantomData,
		};

		let res = gadget_tester(&mut circuit, 2000);
		assert!(res.is_err());
	}
}
