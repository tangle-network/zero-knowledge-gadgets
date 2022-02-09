use ark_ec::{models::TEModelParameters, PairingEngine};
use ark_poly::polynomial::univariate::DensePolynomial;
use ark_poly_commit::{kzg10::{KZG10, self}, sonic_pc::{SonicKZG10, self}, PolynomialCommitment};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_std::{test_rng, vec::Vec};
use plonk_core::{
	prelude::*,
	proof_system::{Prover, Verifier},
};

// A helper function to prove/verify plonk circuits
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
		let mut prover: Prover<E, P> =
			Prover::new(b"demo");

		// Additionally key the transcript
		prover.key_transcript(b"key", b"additional seed information");

		// Add gadgets
		circuit.gadget(&mut prover.mut_cs())?;

		// Commit Key
		let (ck, _) = SonicKZG10::<E, DensePolynomial<E::Fr>>::trim(
			&universal_params,
			prover.circuit_size().next_power_of_two() + 6,
			0,
			None,
		)
		.unwrap();
		// Preprocess circuit
		prover.preprocess(&ck.powers())?;

		// Once the prove method is called, the public inputs are cleared
		// So pre-fetch these before calling Prove
		let public_inputs = prover.mut_cs().construct_dense_pi_vec();
		//? let lookup_table = prover.mut_cs().lookup_table.clone();

		// Compute Proof
		(prover.prove(&ck.powers())?, public_inputs)
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

	// Preprocess circuit
	verifier.preprocess(&sonic_ck.powers())?;

	let mut vk_bytes = Vec::new();
	sonic_pc::VerifierKey::<E>::serialize(&sonic_vk, &mut vk_bytes).unwrap();
	let kzg_vk = kzg10::VerifierKey::<E>::deserialize(&vk_bytes[..]).unwrap();
	Ok(verifier.verify(&proof, &kzg_vk, &public_inputs)?)
}
