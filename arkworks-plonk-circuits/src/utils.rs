use ark_ec::{models::TEModelParameters, PairingEngine};
use ark_ff::PrimeField;
use ark_poly::polynomial::univariate::DensePolynomial;
use ark_poly_commit::{
	kzg10::{UniversalParams, KZG10},
	sonic_pc::SonicKZG10,
	PolynomialCommitment,
};
use ark_std::test_rng;
use plonk_core::{
	prelude::*,
	proof_system::{Prover, Verifier},
};

// A helper function to prove/verify plonk circuits
pub(crate) fn gadget_tester<
	E: PairingEngine,
	P: TEModelParameters<BaseField = E::Fr>,
	C: Circuit<E::Fr, P>,
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
		let mut prover: Prover<E::Fr, P, SonicKZG10<E, DensePolynomial<<E as PairingEngine>::Fr>>> =
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
		prover.preprocess(&ck)?;

		// Once the prove method is called, the public inputs are cleared
		// So pre-fetch these before calling Prove
		let public_inputs = prover.mut_cs().construct_dense_pi_vec();
		//? let lookup_table = prover.mut_cs().lookup_table.clone();

		// Compute Proof
		(prover.prove(&ck)?, public_inputs)
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
	verifier.preprocess(&sonic_ck)?;

	// Verify proof
	Ok(verifier.verify(&proof, &sonic_vk, &public_inputs)?)
}

/// Helper function that accepts a composer that has already been filled,
/// generates a proof, then verifies it.
/// Probably want it to  accept a public inputs argument (could be optional)
pub(crate) fn prove_then_verify<
	E: PairingEngine,
	P: TEModelParameters<BaseField = E::Fr>,
	T: FnMut(&mut StandardComposer<E::Fr, P>) -> Result<(), Error>,
>(
	// gadget: fn(&mut StandardComposer<E::Fr, P>),
	gadget: &mut T,
	max_degree: usize,
	verifier_public_inputs: Option<Vec<E::Fr>>,
) -> Result<(), Error> {
	let rng = &mut test_rng();

	// Fill a composer to extract the public_inputs
	let mut composer = StandardComposer::<E::Fr, P>::new();
	let _ = gadget(&mut composer);

	// Check for verifier public inputs argument, otherwise
	// verifier uses the same public inputs as the prover
	let public_inputs = match verifier_public_inputs {
		Some(pi) => {
			// The provided values need to be turned into a dense public input vector,
			// which means putting each value in the position corresponding to its gate
			let mut pi_dense = vec![E::Fr::from(0u32); composer.circuit_size()];
			let pi_positions = composer.pi_positions();
			pi_positions.iter().zip(pi).for_each(|(position, value)| {
				pi_dense[*position] = value;
			});
			pi_dense
		}
		None => composer.construct_dense_pi_vec(),
	};

	// Go through proof generation/verification
	let u_params: UniversalParams<E> =
		SonicKZG10::<E, DensePolynomial<E::Fr>>::setup(max_degree, None, rng).unwrap();
	let proof = {
		// Create a prover struct
		let mut prover =
			Prover::<E::Fr, P, SonicKZG10<E, DensePolynomial<E::Fr>>>::new(b"test circuit");
		prover.key_transcript(b"key", b"additional seed information");
		// Add gadgets
		let _ = gadget(prover.mut_cs());
		// Commit Key (being lazy with error)
		let (ck, _) =
			SonicKZG10::<E, DensePolynomial<E::Fr>>::trim(&u_params, max_degree, 0, None).unwrap();
		// Preprocess circuit
		let _ = prover.preprocess(&ck);
		// Compute Proof
		prover.prove(&ck)?
	};

	// Verifier's view

	// Create a Verifier object
	let mut verifier =
		Verifier::<E::Fr, P, SonicKZG10<E, DensePolynomial<E::Fr>>>::new(b"test circuit");
	verifier.key_transcript(b"key", b"additional seed information");
	// Add gadgets
	let _ = gadget(verifier.mut_cs());
	// Compute Commit and Verifier key
	let (ck, vk) =
		SonicKZG10::<E, DensePolynomial<E::Fr>>::trim(&u_params, max_degree, 0, None).unwrap();
	// Preprocess circuit
	verifier.preprocess(&ck)?;
	// Verify proof
	verifier.verify(&proof, &vk, &public_inputs)?;

	Ok(())
}

// I used the MixerCircuit to test the new helper function:
// TODO: Include a more minimal example to show how it's used
#[cfg(test)]
mod test {
	use crate::{
		mixer::MixerCircuit,
		poseidon::poseidon::PoseidonGadget,
		utils::{gadget_tester, prove_then_verify},
	};
	use ark_bn254::Bn254;
	use ark_ec::{PairingEngine, TEModelParameters};
	use ark_ed_on_bn254::{EdwardsParameters as JubjubParameters, Fq};
	use ark_ff::Field;
	use ark_poly::polynomial::univariate::DensePolynomial;
	use ark_poly_commit::{kzg10::UniversalParams, sonic_pc::SonicKZG10, PolynomialCommitment};
	use ark_std::test_rng;
	use arkworks_gadgets::{
		ark_std::UniformRand,
		merkle_tree::simple_merkle::SparseMerkleTree,
		poseidon::field_hasher::{FieldHasher, Poseidon},
	};
	use arkworks_utils::utils::common::{setup_params_x5_3, Curve};
	use plonk_core::{
		prelude::*,
		proof_system::{Prover, Verifier},
	};

	type PoseidonBn254 = Poseidon<Fq>;

	#[test]
	fn check_new_gadget_tester_on_success() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;

		let params = setup_params_x5_3(curve);
		let poseidon_native = PoseidonBn254 { params };

		// Randomly generated secrets
		let secret = Fq::rand(rng);
		let nullifier = Fq::rand(rng);

		// Public data
		let arbitrary_data = Fq::rand(rng);
		let nullifier_hash = poseidon_native.hash_two(&nullifier, &nullifier).unwrap();
		let leaf_hash = poseidon_native.hash_two(&secret, &nullifier).unwrap();

		// Create a tree whose leaves are already populated with 2^HEIGHT - 1 random
		// scalars, then add leaf_hash as the final leaf
		const HEIGHT: usize = 6usize;
		let last_index = 1 << (HEIGHT - 1) - 1;
		let mut leaves = [Fq::from(0u8); 1 << (HEIGHT - 1)];
		for i in 0..last_index {
			leaves[i] = Fq::rand(rng);
		}
		leaves[last_index] = leaf_hash;
		let tree = SparseMerkleTree::<Fq, PoseidonBn254, HEIGHT>::new_sequential(
			&leaves,
			&poseidon_native,
			&[0u8; 32],
		)
		.unwrap();
		let root = tree.root();

		// Path
		let path = tree.generate_membership_proof(last_index as u64);

		// Create MixerCircuit
		let mut mixer = MixerCircuit::<Fq, JubjubParameters, PoseidonGadget, HEIGHT>::new(
			secret,
			nullifier,
			nullifier_hash,
			path,
			root,
			arbitrary_data,
			poseidon_native,
		);

		// Use None argument to give verifier the same public input data
		// Verify proof
		let res = prove_then_verify::<Bn254, JubjubParameters, _>(
			&mut |c| mixer.gadget(c),
			1 << 17,
			None,
		);
		match res {
			Ok(()) => (),
			Err(err) => panic!("Unexpected error: {:?}", err),
		};
	}

	#[test]
	fn check_new_gadget_tester_on_failure() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;

		let params = setup_params_x5_3(curve);
		let poseidon_native = PoseidonBn254 { params };

		// Randomly generated secrets
		let secret = Fq::rand(rng);
		let nullifier = Fq::rand(rng);

		// Public data
		let arbitrary_data = Fq::rand(rng);
		let nullifier_hash = poseidon_native.hash_two(&nullifier, &nullifier).unwrap();
		let leaf_hash = poseidon_native.hash_two(&secret, &nullifier).unwrap();

		// Create a tree whose leaves are already populated with 2^HEIGHT - 1 random
		// scalars, then add leaf_hash as the final leaf
		const HEIGHT: usize = 6usize;
		let last_index = 1 << (HEIGHT - 1) - 1;
		let mut leaves = [Fq::from(0u8); 1 << (HEIGHT - 1)];
		for i in 0..last_index {
			leaves[i] = Fq::rand(rng);
		}
		leaves[last_index] = leaf_hash;
		let tree = SparseMerkleTree::<Fq, PoseidonBn254, HEIGHT>::new_sequential(
			&leaves,
			&poseidon_native,
			&[0u8; 32],
		)
		.unwrap();
		let root = tree.root();

		// Path
		let path = tree.generate_membership_proof(last_index as u64);

		// Create MixerCircuit
		let mut mixer = MixerCircuit::<Fq, JubjubParameters, PoseidonGadget, HEIGHT>::new(
			secret,
			nullifier,
			nullifier_hash,
			path,
			root,
			arbitrary_data,
			poseidon_native,
		);

		// Give verifier different public input data:
		let verifier_public_inputs = vec![nullifier_hash.double(), root, arbitrary_data];

		// Verify proof
		let res = prove_then_verify::<Bn254, JubjubParameters, _>(
			&mut |c| mixer.gadget(c),
			1 << 17,
			Some(verifier_public_inputs),
		);

		match res {
			Err(Error::ProofVerificationError) => (),
			Err(err) => panic!("Unexpected error: {:?}", err),
			Ok(()) => panic!("Proof was successfully verified when error was expected"),
		};
	}

	/// Gadget to use in the tests below.  Takes two numbers a and b and adds
	/// constraints to the composer that show the numbers sum to the given
	/// public input value.
	/// The prove_then_verify function takes the gadget in the form of a
	/// closure, so in this case that looks like
	/// ```&mut | composer | minimal_test_gadget(composer, a, b, public_input)
	/// ```
	/// In the case of a circuit (implementing the Circuit trait) that argument
	/// would look like
	/// ```&mut | composer | circuit.gadget(composer) ```
	fn minimal_test_gadget<E: PairingEngine, P: TEModelParameters<BaseField = E::Fr>>(
		composer: &mut StandardComposer<E::Fr, P>,
		a: E::Fr,
		b: E::Fr,
		public_input: E::Fr,
	) -> Result<(), Error> {
		let a = composer.add_input(a);
		let b = composer.add_input(b);
		let zero = composer.zero_var();
		let _ = composer.arithmetic_gate(|g| {
			g.witness(a, b, Some(zero))
				.add(-E::Fr::from(1u32), -E::Fr::from(1u32))
				.pi(public_input)
		});
		Ok(())
	}

	#[test]
	fn minimal_success_test() {
		// Create a circuit that demonstrates the prover knows two numbers that
		// sum to a given public input value.
		let a = Fq::from(1u32);
		let b = Fq::from(2u32);
		let public_input = Fq::from(3u32);

		// Generate then verify a proof that we know two numbers that add to 3
		// Note that we do not use the optional `verifier_public_inputs` argument
		// because we want the prover and verifier to agree on what the public input
		// value was.
		let res = prove_then_verify::<Bn254, JubjubParameters, _>(
			&mut |c| minimal_test_gadget::<Bn254, JubjubParameters>(c, a, b, public_input),
			1 << 4,
			None,
		);
		// Assert that verification was successful
		match res {
			Ok(()) => (),
			Err(err) => panic!("Unexpected error: {:?}", err),
		};
	}

	#[test]
	fn minimal_failure_test() {
		// Create a circuit that demonstrates the prover knows two numbers that
		// sum to a given public input value.
		let a = Fq::from(1u32);
		let b = Fq::from(2u32);
		let public_input = Fq::from(3u32);

		// This time prover and verifier disagree on what the public input
		// value was.  The verifier will think it was 4:
		let verifier_public_inputs = vec![Fq::from(4u32)];

		// Generate then verify a proof that we know two numbers that add to 4
		// This should fail because the prover is actually using the public
		// input value of 3.
		let res = prove_then_verify::<Bn254, JubjubParameters, _>(
			&mut |c| minimal_test_gadget::<Bn254, JubjubParameters>(c, a, b, public_input),
			1 << 4,
			Some(verifier_public_inputs),
		);
		// Assert that verification failed
		match res {
			Err(Error::ProofVerificationError) => (),
			Err(err) => panic!("Unexpected error: {:?}", err),
			Ok(()) => panic!("Proof was successfully verified when error was expected"),
		};

		// Another possible sort of failure is that prover and verifier
		// agree on the public input value but prover's secret witnesses are
		// invalid.  That looks like this:
		let x = Fq::from(1u32);
		let y = Fq::from(1u32);
		let public_input_two = Fq::from(3u32);

		// Observe that `max_degree` has been increased to 2^5. Otherwise
		// we will have a polynomial commitment error.  This always
		// happens when the prover tries to generate invalid proofs, and
		// I believe it has to do with trying to divide one polynomial
		// by another that does not actually divide it.
		let res = prove_then_verify::<Bn254, JubjubParameters, _>(
			&mut |c| minimal_test_gadget::<Bn254, JubjubParameters>(c, x, y, public_input_two),
			1 << 5,
			None,
		);
		// Assert that verification failed
		match res {
			Err(Error::ProofVerificationError) => (),
			Err(err) => panic!("Unexpected error: {:?}", err),
			Ok(()) => panic!("Proof was successfully verified when error was expected"),
		};
	}
}
