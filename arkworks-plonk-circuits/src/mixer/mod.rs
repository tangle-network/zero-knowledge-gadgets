use crate::{merkle_tree::PathGadget, poseidon::poseidon::FieldHasherGadget};
use ark_ec::{models::TEModelParameters, PairingEngine};
use ark_std::{Zero, One};
use arkworks_gadgets::merkle_tree::simple_merkle::Path;
use plonk_core::{
	circuit::Circuit, constraint_system::StandardComposer, error::Error, prelude::Variable,
};

pub struct MixerCircuit<
	E: PairingEngine,
	P: TEModelParameters<BaseField = E::Fr>,
	HG: FieldHasherGadget<E, P>,
	const N: usize,
> {
	secret: E::Fr,
	nullifier: E::Fr,
	nullifier_hash: E::Fr,
	path: Path<E::Fr, HG::Native, N>,
	root: E::Fr,
	arbitrary_data: E::Fr,
	hasher: HG::Native,
}

impl<E, P, HG, const N: usize> MixerCircuit<E, P, HG, N>
where
	E: PairingEngine,
	P: TEModelParameters<BaseField = E::Fr>,
	HG: FieldHasherGadget<E, P>,
{
	pub fn new(
		secret: E::Fr,
		nullifier: E::Fr,
		nullifier_hash: E::Fr,
		path: Path<E::Fr, HG::Native, N>,
		root: E::Fr,
		arbitrary_data: E::Fr,
		hasher: HG::Native,
	) -> Self {
		Self {
			secret,
			nullifier,
			nullifier_hash,
			path,
			root,
			arbitrary_data,
			hasher,
		}
	}
}

impl<E, P, HG, const N: usize> Circuit<E, P> for MixerCircuit<E, P, HG, N>
where
	E: PairingEngine,
	P: TEModelParameters<BaseField = E::Fr>,
	HG: FieldHasherGadget<E, P>,
{
	const CIRCUIT_ID: [u8; 32] = [0xff; 32];

	fn gadget(&mut self, composer: &mut StandardComposer<E, P>) -> Result<(), Error> {
		// Private Inputs
		let secret = composer.add_input(self.secret);
		let nullifier = composer.add_input(self.nullifier);
		let path_gadget = PathGadget::<E, P, HG, N>::from_native(composer, self.path.clone());

		// Public Inputs
		let nullifier_hash = add_public_input_variable(composer, self.nullifier_hash);
		let root = add_public_input_variable(composer, self.root);
		let arbitrary_data = add_public_input_variable(composer, self.arbitrary_data);

		// Create the hasher_gadget from native
		let hasher_gadget: HG =
			FieldHasherGadget::<E, P>::from_native(composer, self.hasher.clone());

		// Preimage proof of nullifier
		let res_nullifier = hasher_gadget.hash_two(composer, &nullifier, &nullifier)?;
		// TODO: (This has 1 more gate than skipping the nullifier_hash variable and
		// putting this straight in to a poly_gate)
		composer.assert_equal(res_nullifier, nullifier_hash);

		// Preimage proof of leaf hash
		let res_leaf = hasher_gadget.hash_two(composer, &secret, &nullifier)?;

		// Proof of Merkle tree membership
		let is_member = path_gadget.check_membership(composer, &root, &res_leaf, &hasher_gadget)?;
		let one = composer.add_witness_to_circuit_description(E::Fr::one());
		composer.assert_equal(is_member, one);

		// Safety constraint to prevent tampering with arbitrary_data
		let _arbitrary_data_squared = composer.arithmetic_gate(|gate| {
			gate.witness(arbitrary_data, arbitrary_data, None)
				.mul(E::Fr::one())
		});
		Ok(())
	}

	fn padded_circuit_size(&self) -> usize {
		1 << 21
	}
}

/// Add a variable to a circuit and constrain it to a public input value that
/// is expected to be different in each instance of the circuit.
pub fn add_public_input_variable<E, P>(composer: &mut StandardComposer<E, P>, value: E::Fr) -> Variable
where
	E: PairingEngine,
	P: TEModelParameters<BaseField = E::Fr>,
{
	let variable = composer.add_input(value);
	composer.poly_gate(
		variable,
		variable,
		variable,
		E::Fr::zero(),
		-E::Fr::one(),
		E::Fr::zero(),
		E::Fr::zero(),
		E::Fr::zero(),
		Some(value),
	);
	variable
}

#[cfg(test)]
mod test {
	use super::MixerCircuit;
	use crate::{poseidon::poseidon::PoseidonGadget, utils::gadget_tester};
	use ark_bn254::{Bn254, Fr as Bn254Fr};
	use ark_ed_on_bn254::{EdwardsParameters as JubjubParameters, Fq};
	use ark_ff::Field;
	use ark_poly::polynomial::univariate::DensePolynomial;
	use ark_poly_commit::{kzg10::{UniversalParams, self}, sonic_pc::{SonicKZG10, self}, PolynomialCommitment};
	use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
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
	fn should_verify_correct_mixer_plonk() {
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
		let mut mixer = MixerCircuit::<Bn254, JubjubParameters, PoseidonGadget, HEIGHT>::new(
			secret,
			nullifier,
			nullifier_hash,
			path,
			root,
			arbitrary_data,
			poseidon_native,
		);

		let res = gadget_tester::<Bn254, JubjubParameters, _>(&mut mixer, 1 << 17);
		assert!(res.is_ok(), "{:?}", res.err().unwrap());
	}

	#[test]
	fn should_fail_with_invalid_root_plonk() {
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
		let bad_root = root.double();

		// Path
		let path = tree.generate_membership_proof(last_index as u64);

		// Create MixerCircuit
		let mut mixer = MixerCircuit::<Bn254, JubjubParameters, PoseidonGadget, HEIGHT>::new(
			secret,
			nullifier,
			nullifier_hash,
			path,
			bad_root,
			arbitrary_data,
			poseidon_native,
		);

		// Fill a composer to extract the public_inputs
		let mut composer = StandardComposer::<Bn254, JubjubParameters>::new();
		let _ = mixer.gadget(&mut composer);
		let public_inputs = composer.construct_dense_pi_vec();

		// Go through proof generation/verification
		let u_params: UniversalParams<Bn254> =
			SonicKZG10::<Bn254, DensePolynomial<Bn254Fr>>::setup(1 << 18, None, rng).unwrap();
		let proof = {
			// Create a prover struct
			let mut prover =
				Prover::<Bn254, JubjubParameters>::new(
					b"mixer",
				);
			prover.key_transcript(b"key", b"additional seed information");
			// Add gadgets
			let _ = mixer.gadget(prover.mut_cs());
			// Commit Key (being lazy with error)
			let (ck, _) =
				SonicKZG10::<Bn254, DensePolynomial<Bn254Fr>>::trim(&u_params, 1 << 18, 0, None)
					.unwrap();
			// Preprocess circuit
			let _ = prover.preprocess(&ck.powers());
			// Compute Proof
			prover.prove(&ck.powers()).unwrap()
		};

		// Verifier's view

		// Create a Verifier object
		let mut verifier = Verifier::new(b"mixer");
		verifier.key_transcript(b"key", b"additional seed information");
		// Add gadgets
		let _ = mixer.gadget(verifier.mut_cs());
		// Compute Commit and Verifier key
		let (ck, vk) =
			SonicKZG10::<Bn254, DensePolynomial<Bn254Fr>>::trim(&u_params, 1 << 18, 0, None)
				.unwrap();
		// Preprocess circuit
		verifier.preprocess(&ck.powers()).unwrap();

		let mut vk_bytes = Vec::new();
        sonic_pc::VerifierKey::<Bn254>::serialize(&vk, &mut vk_bytes).unwrap();
        let kzg_vk = kzg10::VerifierKey::<Bn254>::deserialize(&vk_bytes[..]).unwrap();
		let res = verifier.verify(&proof, &kzg_vk, &public_inputs).unwrap_err();
		match res {
			Error::ProofVerificationError => (),
			err => panic!("Unexpected error: {:?}", err),
		};
	}

	#[test]
	fn should_fail_with_wrong_secret_plonk() {
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

		// An incorrect secret value to use below
		let bad_secret = secret.double();

		// Create MixerCircuit
		let mut mixer = MixerCircuit::<Bn254, JubjubParameters, PoseidonGadget, HEIGHT>::new(
			bad_secret,
			nullifier,
			nullifier_hash,
			path,
			root,
			arbitrary_data,
			poseidon_native,
		);

		// Fill a composer to extract the public_inputs
		let mut composer = StandardComposer::<Bn254, JubjubParameters>::new();
		let _ = mixer.gadget(&mut composer);
		let public_inputs = composer.construct_dense_pi_vec();

		// Go through proof generation/verification
		let u_params: UniversalParams<Bn254> =
			SonicKZG10::<Bn254, DensePolynomial<Bn254Fr>>::setup(1 << 18, None, rng).unwrap();
		let proof = {
			// Create a prover struct
			let mut prover =
				Prover::<Bn254, JubjubParameters>::new(
					b"mixer",
				);
			prover.key_transcript(b"key", b"additional seed information");
			// Add gadgets
			let _ = mixer.gadget(prover.mut_cs());
			// Commit Key (being lazy with error)
			let (ck, _) =
				SonicKZG10::<Bn254, DensePolynomial<Bn254Fr>>::trim(&u_params, 1 << 18, 0, None)
					.unwrap();
			// Preprocess circuit
			let _ = prover.preprocess(&ck.powers());
			// Compute Proof
			prover.prove(&ck.powers()).unwrap()
		};

		// Verifier's view

		// Create a Verifier object
		let mut verifier = Verifier::new(b"mixer");
		verifier.key_transcript(b"key", b"additional seed information");
		// Add gadgets
		let _ = mixer.gadget(verifier.mut_cs());
		// Compute Commit and Verifier key
		let (ck, vk) =
			SonicKZG10::<Bn254, DensePolynomial<Bn254Fr>>::trim(&u_params, 1 << 18, 0, None)
				.unwrap();
		// Preprocess circuit
		verifier.preprocess(&ck.powers()).unwrap();

		let mut vk_bytes = Vec::new();
        sonic_pc::VerifierKey::<Bn254>::serialize(&vk, &mut vk_bytes).unwrap();
        let kzg_vk = kzg10::VerifierKey::<Bn254>::deserialize(&vk_bytes[..]).unwrap();
		let res = verifier.verify(&proof, &kzg_vk, &public_inputs).unwrap_err();
		match res {
			Error::ProofVerificationError => (),
			err => panic!("Unexpected error: {:?}", err),
		};
	}

	#[test]
	fn should_fail_with_wrong_nullifier_plonk() {
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

		// An incorrect secret value to use below
		let bad_nullifier = nullifier.double();

		// Create MixerCircuit
		let mut mixer = MixerCircuit::<Bn254, JubjubParameters, PoseidonGadget, HEIGHT>::new(
			secret,
			bad_nullifier,
			nullifier_hash,
			path,
			root,
			arbitrary_data,
			poseidon_native,
		);

		// Fill a composer to extract the public_inputs
		let mut composer = StandardComposer::<Bn254, JubjubParameters>::new();
		let _ = mixer.gadget(&mut composer);
		let public_inputs = composer.construct_dense_pi_vec();

		// Go through proof generation/verification
		let u_params: UniversalParams<Bn254> =
			SonicKZG10::<Bn254, DensePolynomial<Bn254Fr>>::setup(1 << 18, None, rng).unwrap();
		let proof = {
			// Create a prover struct
			let mut prover =
				Prover::<Bn254, JubjubParameters>::new(
					b"mixer",
				);
			prover.key_transcript(b"key", b"additional seed information");
			// Add gadgets
			let _ = mixer.gadget(prover.mut_cs());
			// Commit Key (being lazy with error)
			let (ck, _) =
				SonicKZG10::<Bn254, DensePolynomial<Bn254Fr>>::trim(&u_params, 1 << 18, 0, None)
					.unwrap();
			// Preprocess circuit
			let _ = prover.preprocess(&ck.powers());
			// Compute Proof
			prover.prove(&ck.powers()).unwrap()
		};

		// Verifier's view

		// Create a Verifier object
		let mut verifier = Verifier::new(b"mixer");
		verifier.key_transcript(b"key", b"additional seed information");
		// Add gadgets
		let _ = mixer.gadget(verifier.mut_cs());
		// Compute Commit and Verifier key
		let (ck, vk) =
			SonicKZG10::<Bn254, DensePolynomial<Bn254Fr>>::trim(&u_params, 1 << 18, 0, None)
				.unwrap();
		// Preprocess circuit
		verifier.preprocess(&ck.powers()).unwrap();

		let mut vk_bytes = Vec::new();
        sonic_pc::VerifierKey::<Bn254>::serialize(&vk, &mut vk_bytes).unwrap();
        let kzg_vk = kzg10::VerifierKey::<Bn254>::deserialize(&vk_bytes[..]).unwrap();
		let res = verifier.verify(&proof, &kzg_vk, &public_inputs).unwrap_err();
		match res {
			Error::ProofVerificationError => (),
			err => panic!("Unexpected error: {:?}", err),
		};
	}

	#[test]
	fn should_fail_with_wrong_path_plonk() {
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

		// An incorrect path to use below
		let bad_path = tree.generate_membership_proof((last_index as u64) - 1);

		// Create MixerCircuit
		let mut mixer = MixerCircuit::<Bn254, JubjubParameters, PoseidonGadget, HEIGHT>::new(
			secret,
			nullifier,
			nullifier_hash,
			bad_path,
			root,
			arbitrary_data,
			poseidon_native,
		);

		// Fill a composer to extract the public_inputs
		let mut composer = StandardComposer::<Bn254, JubjubParameters>::new();
		let _ = mixer.gadget(&mut composer);
		let public_inputs = composer.construct_dense_pi_vec();

		// Go through proof generation/verification
		let u_params: UniversalParams<Bn254> =
			SonicKZG10::<Bn254, DensePolynomial<Bn254Fr>>::setup(1 << 18, None, rng).unwrap();
		let proof = {
			// Create a prover struct
			let mut prover =
				Prover::<Bn254, JubjubParameters>::new(
					b"mixer",
				);
			prover.key_transcript(b"key", b"additional seed information");
			// Add gadgets
			let _ = mixer.gadget(prover.mut_cs());
			// Commit Key (being lazy with error)
			let (ck, _) =
				SonicKZG10::<Bn254, DensePolynomial<Bn254Fr>>::trim(&u_params, 1 << 18, 0, None)
					.unwrap();
			// Preprocess circuit
			let _ = prover.preprocess(&ck.powers());
			// Compute Proof
			prover.prove(&ck.powers()).unwrap()
		};

		// Verifier's view

		// Create a Verifier object
		let mut verifier = Verifier::new(b"mixer");
		verifier.key_transcript(b"key", b"additional seed information");
		// Add gadgets
		let _ = mixer.gadget(verifier.mut_cs());
		// Compute Commit and Verifier key
		let (ck, vk) =
			SonicKZG10::<Bn254, DensePolynomial<Bn254Fr>>::trim(&u_params, 1 << 18, 0, None)
				.unwrap();
		// Preprocess circuit
		verifier.preprocess(&ck.powers()).unwrap();

		let mut vk_bytes = Vec::new();
        sonic_pc::VerifierKey::<Bn254>::serialize(&vk, &mut vk_bytes).unwrap();
        let kzg_vk = kzg10::VerifierKey::<Bn254>::deserialize(&vk_bytes[..]).unwrap();
		let res = verifier.verify(&proof, &kzg_vk, &public_inputs).unwrap_err();
		match res {
			Error::ProofVerificationError => (),
			err => panic!("Unexpected error: {:?}", err),
		};
	}

	#[test]
	fn should_fail_with_wrong_nullifier_hash_plonk() {
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

		// Incorrect nullifier hash to use below
		let bad_nullifier_hash = nullifier_hash.double();

		// Create MixerCircuit
		let mut mixer = MixerCircuit::<Bn254, JubjubParameters, PoseidonGadget, HEIGHT>::new(
			secret,
			nullifier,
			bad_nullifier_hash,
			path,
			root,
			arbitrary_data,
			poseidon_native,
		);

		// Fill a composer to extract the public_inputs
		let mut composer = StandardComposer::<Bn254, JubjubParameters>::new();
		let _ = mixer.gadget(&mut composer);
		let public_inputs = composer.construct_dense_pi_vec();

		// Go through proof generation/verification
		let u_params: UniversalParams<Bn254> =
			SonicKZG10::<Bn254, DensePolynomial<Bn254Fr>>::setup(1 << 18, None, rng).unwrap();
		let proof = {
			// Create a prover struct
			let mut prover =
				Prover::<Bn254, JubjubParameters>::new(
					b"mixer",
				);
			prover.key_transcript(b"key", b"additional seed information");
			// Add gadgets
			let _ = mixer.gadget(prover.mut_cs());
			// Commit Key (being lazy with error)
			let (ck, _) =
				SonicKZG10::<Bn254, DensePolynomial<Bn254Fr>>::trim(&u_params, 1 << 18, 0, None)
					.unwrap();
			// Preprocess circuit
			let _ = prover.preprocess(&ck.powers());
			// Compute Proof
			prover.prove(&ck.powers()).unwrap()
		};

		// Verifier's view

		// Create a Verifier object
		let mut verifier = Verifier::new(b"mixer");
		verifier.key_transcript(b"key", b"additional seed information");
		// Add gadgets
		let _ = mixer.gadget(verifier.mut_cs());
		// Compute Commit and Verifier key
		let (ck, vk) =
			SonicKZG10::<Bn254, DensePolynomial<Bn254Fr>>::trim(&u_params, 1 << 18, 0, None)
				.unwrap();
		// Preprocess circuit
		verifier.preprocess(&ck.powers()).unwrap();

		let mut vk_bytes = Vec::new();
        sonic_pc::VerifierKey::<Bn254>::serialize(&vk, &mut vk_bytes).unwrap();
        let kzg_vk = kzg10::VerifierKey::<Bn254>::deserialize(&vk_bytes[..]).unwrap();
		let res = verifier.verify(&proof, &kzg_vk, &public_inputs).unwrap_err();
		match res {
			Error::ProofVerificationError => (),
			err => panic!("Unexpected error: {:?}", err),
		};
	}

	#[test]
	fn should_fail_with_wrong_arbitrary_data_plonk() {
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
		let mut mixer = MixerCircuit::<Bn254, JubjubParameters, PoseidonGadget, HEIGHT>::new(
			secret,
			nullifier,
			nullifier_hash,
			path,
			root,
			arbitrary_data,
			poseidon_native,
		);

		// Fill a composer to extract the public_inputs
		let mut composer = StandardComposer::<Bn254, JubjubParameters>::new();
		let _ = mixer.gadget(&mut composer);
		let mut public_inputs = composer.construct_dense_pi_vec();

		// Go through proof generation/verification
		let u_params: UniversalParams<Bn254> =
			SonicKZG10::<Bn254, DensePolynomial<Bn254Fr>>::setup(1 << 18, None, rng).unwrap();
		let proof = {
			// Create a prover struct
			let mut prover =
				Prover::<Bn254, JubjubParameters>::new(
					b"mixer",
				);
			prover.key_transcript(b"key", b"additional seed information");
			// Add gadgets
			let _ = mixer.gadget(prover.mut_cs());
			// Commit Key (being lazy with error)
			let (ck, _) =
				SonicKZG10::<Bn254, DensePolynomial<Bn254Fr>>::trim(&u_params, 1 << 18, 0, None)
					.unwrap();
			// Preprocess circuit
			let _ = prover.preprocess(&ck.powers());
			// Compute Proof
			prover.prove(&ck.powers()).unwrap()
		};

		// Verifier's view

		// Create a Verifier object
		let mut verifier = Verifier::new(b"mixer");
		verifier.key_transcript(b"key", b"additional seed information");
		// Add gadgets
		let _ = mixer.gadget(verifier.mut_cs());
		// Compute Commit and Verifier key
		let (ck, vk) =
			SonicKZG10::<Bn254, DensePolynomial<Bn254Fr>>::trim(&u_params, 1 << 18, 0, None)
				.unwrap();
		// Preprocess circuit
		verifier.preprocess(&ck.powers()).unwrap();

		// The arbitrary data is stored at index 5 of the public input vector:
		assert_eq!(arbitrary_data, public_inputs[5]);
		// Modify the arbitrary data so that prover/verifier disagree
		public_inputs[5].double_in_place();

		let mut vk_bytes = Vec::new();
        sonic_pc::VerifierKey::<Bn254>::serialize(&vk, &mut vk_bytes).unwrap();
        let kzg_vk = kzg10::VerifierKey::<Bn254>::deserialize(&vk_bytes[..]).unwrap();
		let res = verifier.verify(&proof, &kzg_vk, &public_inputs).unwrap_err();
		match res {
			Error::ProofVerificationError => (),
			err => panic!("Unexpected error: {:?}", err),
		};
	}
}
