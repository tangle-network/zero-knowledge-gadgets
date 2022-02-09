use crate::{
	anchor::add_public_input_variable, merkle_tree::PathGadget,
	poseidon::poseidon::FieldHasherGadget, set_membership::check_set_membership,
};
use ark_ec::{models::TEModelParameters, PairingEngine};
use ark_ff::PrimeField;
use ark_std::{One, Zero};
use arkworks_gadgets::merkle_tree::simple_merkle::Path;
use plonk_core::{
	circuit::Circuit, constraint_system::StandardComposer, error::Error, prelude::Variable,
};

pub struct AnchorCircuit<
	F: PrimeField,
	P: TEModelParameters<BaseField = F>,
	HG: FieldHasherGadget<F, P>,
	const N: usize,
	const M: usize,
> {
	chain_id: F,
	secret: F,
	nullifier: F,
	nullifier_hash: F,
	path: Path<F, HG::Native, N>,
	roots: [F; M],
	arbitrary_data: F,
	hasher: HG::Native,
}

impl<F, P, HG, const N: usize, const M: usize> AnchorCircuit<F, P, HG, N, M>
where
	F: PrimeField,
	P: TEModelParameters<BaseField = F>,
	HG: FieldHasherGadget<F, P>,
{
	pub fn new(
		chain_id: F,
		secret: F,
		nullifier: F,
		nullifier_hash: F,
		path: Path<F, HG::Native, N>,
		roots: [F; M],
		arbitrary_data: F,
		hasher: HG::Native,
	) -> Self {
		Self {
			chain_id,
			secret,
			nullifier,
			nullifier_hash,
			path,
			roots,
			arbitrary_data,
			hasher,
		}
	}
}

impl<F, P, HG, const N: usize, const M: usize> Circuit<F, P> for AnchorCircuit<F, P, HG, N, M>
where
	F: PrimeField,
	P: TEModelParameters<BaseField = F>,
	HG: FieldHasherGadget<F, P>,
{
	const CIRCUIT_ID: [u8; 32] = [0xff; 32];

	fn gadget(&mut self, composer: &mut StandardComposer<F, P>) -> Result<(), Error> {
		// Private Inputs
		let secret = composer.add_input(self.secret);
		let nullifier = composer.add_input(self.nullifier);
		let path_gadget = PathGadget::<F, P, HG, N>::from_native(composer, self.path.clone());

		// Public Inputs
		let chain_id = add_public_input_variable(composer, self.chain_id);
		let nullifier_hash = add_public_input_variable(composer, self.nullifier_hash);
		let roots = self
			.roots
			.iter()
			.map(|root| add_public_input_variable(composer, *root))
			.collect::<Vec<Variable>>();
		let arbitrary_data = add_public_input_variable(composer, self.arbitrary_data);

		// Create the hasher_gadget from native
		let hasher_gadget: HG =
			FieldHasherGadget::<F, P>::from_native(composer, self.hasher.clone());

		// Preimage proof of nullifier
		let res_nullifier = hasher_gadget.hash_two(composer, &nullifier, &nullifier)?;
		// TODO: (This has 1 more gate than skipping the nullifier_hash variable and
		// putting this straight in to a poly_gate)
		composer.assert_equal(res_nullifier, nullifier_hash);

		// Preimage proof of leaf hash
		let res_leaf = hasher_gadget.hash_two(composer, &secret, &nullifier)?;

		// Proof of Merkle tree set membership
		let calculated_root = path_gadget.calculate_root(composer, &res_leaf, &hasher_gadget)?;
		let result = check_set_membership(composer, &self.roots.to_vec(), calculated_root);
		let one = composer.add_witness_to_circuit_description(F::one());
		composer.assert_equal(result, one);

		// Safety constraint to prevent tampering with arbitrary_data
		let _arbitrary_data_squared = composer.arithmetic_gate(|gate| {
			gate.witness(arbitrary_data, arbitrary_data, None)
				.mul(F::one())
		});
		Ok(())
	}

	fn padded_circuit_size(&self) -> usize {
		1 << 21
	}
}

#[cfg(test)]
mod test {
	use super::AnchorCircuit;
	use crate::{poseidon::poseidon::PoseidonGadget, utils::gadget_tester};
	use ark_bn254::{Bn254, Fr as Bn254Fr};
	use ark_ed_on_bn254::{EdwardsParameters as JubjubParameters, Fq};
	use ark_ff::Field;
	use ark_poly::polynomial::univariate::DensePolynomial;
	use ark_poly_commit::{
		kzg10::{self, UniversalParams},
		sonic_pc::{self, SonicKZG10},
		PolynomialCommitment,
	};
	use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
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

	const BRIDGE_SIZE: usize = 2;

	#[test]
	fn should_verify_correct_anchor_plonk() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;

		let params = setup_params_x5_3(curve);
		let poseidon_native = PoseidonBn254 { params };

		// Randomly generated secrets
		let secret = Fq::rand(rng);
		let nullifier = Fq::rand(rng);

		// Public data
		let chain_id = Fq::from(1u32);
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

		let mut roots = [Fq::from(0u8); BRIDGE_SIZE];
		roots[0] = tree.root();

		// Path
		let path = tree.generate_membership_proof(last_index as u64);

		// Create AnchorCircuit
		let mut anchor =
			AnchorCircuit::<Bn254Fr, JubjubParameters, PoseidonGadget, HEIGHT, BRIDGE_SIZE>::new(
				chain_id,
				secret,
				nullifier,
				nullifier_hash,
				path,
				roots,
				arbitrary_data,
				poseidon_native,
			);

		let res = gadget_tester::<Bn254, JubjubParameters, _>(&mut anchor, 1 << 17);
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
		let chain_id = Fq::from(1u32);
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
		let mut root = tree.root();
		let bad_root = root.double();
		let mut roots = [Fq::from(0u8); BRIDGE_SIZE];
		roots[0] = bad_root;

		// Path
		let path = tree.generate_membership_proof(last_index as u64);

		// Create AnchorCircuit
		let mut anchor =
			AnchorCircuit::<Bn254Fr, JubjubParameters, PoseidonGadget, HEIGHT, BRIDGE_SIZE>::new(
				chain_id,
				secret,
				nullifier,
				nullifier_hash,
				path,
				roots,
				arbitrary_data,
				poseidon_native,
			);

		// Fill a composer to extract the public_inputs
		let mut composer = StandardComposer::<Bn254Fr, JubjubParameters>::new();
		let _ = anchor.gadget(&mut composer);
		let public_inputs = composer.construct_dense_pi_vec();

		// Go through proof generation/verification
		let u_params: UniversalParams<Bn254> =
			SonicKZG10::<Bn254, DensePolynomial<Bn254Fr>>::setup(1 << 18, None, rng).unwrap();
		let proof = {
			// Create a prover struct
			let mut prover = Prover::<
				Bn254,
				JubjubParameters,
				SonicKZG10<Bn254, DensePolynomial<Bn254Fr>>,
			>::new(b"anchor");
			prover.key_transcript(b"key", b"additional seed information");
			// Add gadgets
			let _ = anchor.gadget(prover.mut_cs());
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
		let mut verifier = Verifier::new(b"anchor");
		verifier.key_transcript(b"key", b"additional seed information");
		// Add gadgets
		let _ = anchor.gadget(verifier.mut_cs());
		// Compute Commit and Verifier key
		let (ck, vk) =
			SonicKZG10::<Bn254, DensePolynomial<Bn254Fr>>::trim(&u_params, 1 << 18, 0, None)
				.unwrap();
		// Preprocess circuit
		verifier.preprocess(&ck.powers()).unwrap();

		// Verify proof
		let res = verifier.verify(&proof, &vk, &public_inputs).unwrap_err();
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
		let chain_id = Fq::from(1u32);
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
		let mut roots = [Fq::from(0u8); BRIDGE_SIZE];
		roots[0] = tree.root();
		// Path
		let path = tree.generate_membership_proof(last_index as u64);

		// An incorrect secret value to use below
		let bad_secret = secret.double();

		// Create AnchorCircuit
		let mut anchor =
			AnchorCircuit::<Bn254Fr, JubjubParameters, PoseidonGadget, HEIGHT, BRIDGE_SIZE>::new(
				chain_id,
				bad_secret,
				nullifier,
				nullifier_hash,
				path,
				roots,
				arbitrary_data,
				poseidon_native,
			);

		// Fill a composer to extract the public_inputs
		let mut composer = StandardComposer::<Bn254Fr, JubjubParameters>::new();
		let _ = anchor.gadget(&mut composer);
		let public_inputs = composer.construct_dense_pi_vec();

		// Go through proof generation/verification
		let u_params: UniversalParams<Bn254Fr> =
			SonicKZG10::<Bn254, DensePolynomial<Bn254Fr>>::setup(1 << 18, None, rng).unwrap();
		let proof = {
			// Create a prover struct
			let mut prover = Prover::<
				Bn254,
				JubjubParameters,
				SonicKZG10<Bn254, DensePolynomial<Bn254Fr>>,
			>::new(b"anchor");
			prover.key_transcript(b"key", b"additional seed information");
			// Add gadgets
			let _ = anchor.gadget(prover.mut_cs());
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
		let mut verifier = Verifier::new(b"anchor");
		verifier.key_transcript(b"key", b"additional seed information");
		// Add gadgets
		let _ = anchor.gadget(verifier.mut_cs());
		// Compute Commit and Verifier key
		let (ck, vk) =
			SonicKZG10::<Bn254, DensePolynomial<Bn254Fr>>::trim(&u_params, 1 << 18, 0, None)
				.unwrap();
		// Preprocess circuit
		verifier.preprocess(&ck.powers()).unwrap();

		// Verify proof
		let mut vk_bytes = Vec::new();
		sonic_pc::VerifierKey::<Bn254Fr>::serialize(&vk, &mut vk_bytes).unwrap();
		let kzg_vk = kzg10::VerifierKey::<Bn254Fr>::deserialize(&vk_bytes[..]).unwrap();
		let res = verifier
			.verify(&proof, &kzg_vk, &public_inputs)
			.unwrap_err();
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
		let chain_id = Fq::from(1u32);
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
		let mut roots = [Fq::from(0u8); BRIDGE_SIZE];
		roots[0] = tree.root();

		// Path
		let path = tree.generate_membership_proof(last_index as u64);

		// An incorrect secret value to use below
		let bad_nullifier = nullifier.double();

		// Create AnchorCircuit
		let mut anchor =
			AnchorCircuit::<Bn254Fr, JubjubParameters, PoseidonGadget, HEIGHT, BRIDGE_SIZE>::new(
				chain_id,
				secret,
				bad_nullifier,
				nullifier_hash,
				path,
				roots,
				arbitrary_data,
				poseidon_native,
			);

		// Fill a composer to extract the public_inputs
		let mut composer = StandardComposer::<Bn254Fr, JubjubParameters>::new();
		let _ = anchor.gadget(&mut composer);
		let public_inputs = composer.construct_dense_pi_vec();

		// Go through proof generation/verification
		let u_params: UniversalParams<Bn254Fr> =
			SonicKZG10::<Bn254, DensePolynomial<Bn254Fr>>::setup(1 << 18, None, rng).unwrap();
		let proof = {
			// Create a prover struct
			let mut prover = Prover::<
				Bn254,
				JubjubParameters,
				SonicKZG10<Bn254, DensePolynomial<Bn254Fr>>,
			>::new(b"anchor");
			prover.key_transcript(b"key", b"additional seed information");
			// Add gadgets
			let _ = anchor.gadget(prover.mut_cs());
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
		let mut verifier = Verifier::new(b"anchor");
		verifier.key_transcript(b"key", b"additional seed information");
		// Add gadgets
		let _ = anchor.gadget(verifier.mut_cs());
		// Compute Commit and Verifier key
		let (ck, vk) =
			SonicKZG10::<Bn254, DensePolynomial<Bn254Fr>>::trim(&u_params, 1 << 18, 0, None)
				.unwrap();
		// Preprocess circuit
		verifier.preprocess(&ck.powers()).unwrap();

		// Verify proof
		let mut vk_bytes = Vec::new();
		sonic_pc::VerifierKey::<Bn254Fr>::serialize(&vk, &mut vk_bytes).unwrap();
		let kzg_vk = kzg10::VerifierKey::<Bn254Fr>::deserialize(&vk_bytes[..]).unwrap();
		let res = verifier
			.verify(&proof, &kzg_vk, &public_inputs)
			.unwrap_err();
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
		let chain_id = Fq::from(1u32);
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
		let mut roots = [Fq::from(0u8); BRIDGE_SIZE];
		roots[0] = tree.root();

		// An incorrect path to use below
		let bad_path = tree.generate_membership_proof((last_index as u64) - 1);

		// Create AnchorCircuit
		let mut anchor =
			AnchorCircuit::<Bn254Fr, JubjubParameters, PoseidonGadget, HEIGHT, BRIDGE_SIZE>::new(
				chain_id,
				secret,
				nullifier,
				nullifier_hash,
				bad_path,
				roots,
				arbitrary_data,
				poseidon_native,
			);

		// Fill a composer to extract the public_inputs
		let mut composer = StandardComposer::<Bn254Fr, JubjubParameters>::new();
		let _ = anchor.gadget(&mut composer);
		let public_inputs = composer.construct_dense_pi_vec();

		// Go through proof generation/verification
		let u_params: UniversalParams<Bn254Fr> =
			SonicKZG10::<Bn254, DensePolynomial<Bn254Fr>>::setup(1 << 18, None, rng).unwrap();
		let proof = {
			// Create a prover struct
			let mut prover = Prover::<
				Bn254,
				JubjubParameters,
				SonicKZG10<Bn254, DensePolynomial<Bn254Fr>>,
			>::new(b"anchor");
			prover.key_transcript(b"key", b"additional seed information");
			// Add gadgets
			let _ = anchor.gadget(prover.mut_cs());
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
		let mut verifier = Verifier::new(b"anchor");
		verifier.key_transcript(b"key", b"additional seed information");
		// Add gadgets
		let _ = anchor.gadget(verifier.mut_cs());
		// Compute Commit and Verifier key
		let (ck, vk) =
			SonicKZG10::<Bn254, DensePolynomial<Bn254Fr>>::trim(&u_params, 1 << 18, 0, None)
				.unwrap();
		// Preprocess circuit
		verifier.preprocess(&ck.powers()).unwrap();

		// Verify proof
		let mut vk_bytes = Vec::new();
		sonic_pc::VerifierKey::<Bn254Fr>::serialize(&vk, &mut vk_bytes).unwrap();
		let kzg_vk = kzg10::VerifierKey::<Bn254Fr>::deserialize(&vk_bytes[..]).unwrap();
		let res = verifier
			.verify(&proof, &kzg_vk, &public_inputs)
			.unwrap_err();
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
		let chain_id = Fq::from(1u32);
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
		let mut roots = [Fq::from(0u8); BRIDGE_SIZE];
		roots[0] = tree.root();

		// Path
		let path = tree.generate_membership_proof(last_index as u64);

		// Incorrect nullifier hash to use below
		let bad_nullifier_hash = nullifier_hash.double();

		// Create AnchorCircuit
		let mut anchor =
			AnchorCircuit::<Bn254Fr, JubjubParameters, PoseidonGadget, HEIGHT, BRIDGE_SIZE>::new(
				chain_id,
				secret,
				nullifier,
				bad_nullifier_hash,
				path,
				roots,
				arbitrary_data,
				poseidon_native,
			);

		// Fill a composer to extract the public_inputs
		let mut composer = StandardComposer::<Bn254Fr, JubjubParameters>::new();
		let _ = anchor.gadget(&mut composer);
		let public_inputs = composer.construct_dense_pi_vec();

		// Go through proof generation/verification
		let u_params: UniversalParams<Bn254Fr> =
			SonicKZG10::<Bn254, DensePolynomial<Bn254Fr>>::setup(1 << 18, None, rng).unwrap();
		let proof = {
			// Create a prover struct
			let mut prover = Prover::<
				Bn254,
				JubjubParameters,
				SonicKZG10<Bn254, DensePolynomial<Bn254Fr>>,
			>::new(b"anchor");
			prover.key_transcript(b"key", b"additional seed information");
			// Add gadgets
			let _ = anchor.gadget(prover.mut_cs());
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
		let mut verifier = Verifier::new(b"anchor");
		verifier.key_transcript(b"key", b"additional seed information");
		// Add gadgets
		let _ = anchor.gadget(verifier.mut_cs());
		// Compute Commit and Verifier key
		let (ck, vk) =
			SonicKZG10::<Bn254, DensePolynomial<Bn254Fr>>::trim(&u_params, 1 << 18, 0, None)
				.unwrap();
		// Preprocess circuit
		verifier.preprocess(&ck.powers()).unwrap();

		// Verify proof
		let mut vk_bytes = Vec::new();
		sonic_pc::VerifierKey::<Bn254Fr>::serialize(&vk, &mut vk_bytes).unwrap();
		let kzg_vk = kzg10::VerifierKey::<Bn254Fr>::deserialize(&vk_bytes[..]).unwrap();
		let res = verifier
			.verify(&proof, &kzg_vk, &public_inputs)
			.unwrap_err();
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
		let chain_id = Fq::from(1u32);
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
		let mut roots = [Fq::from(0u8); BRIDGE_SIZE];
		roots[0] = tree.root();

		// Path
		let path = tree.generate_membership_proof(last_index as u64);

		// Create AnchorCircuit
		let mut anchor =
			AnchorCircuit::<Bn254Fr, JubjubParameters, PoseidonGadget, HEIGHT, BRIDGE_SIZE>::new(
				chain_id,
				secret,
				nullifier,
				nullifier_hash,
				path,
				roots,
				arbitrary_data,
				poseidon_native,
			);

		// Fill a composer to extract the public_inputs
		let mut composer = StandardComposer::<Bn254Fr, JubjubParameters>::new();
		let _ = anchor.gadget(&mut composer);
		let mut public_inputs = composer.construct_dense_pi_vec();

		// Go through proof generation/verification
		let u_params: UniversalParams<Bn254Fr> =
			SonicKZG10::<Bn254, DensePolynomial<Bn254Fr>>::setup(1 << 18, None, rng).unwrap();
		let proof = {
			// Create a prover struct
			let mut prover = Prover::<
				Bn254,
				JubjubParameters,
				SonicKZG10<Bn254, DensePolynomial<Bn254Fr>>,
			>::new(b"anchor");
			prover.key_transcript(b"key", b"additional seed information");
			// Add gadgets
			let _ = anchor.gadget(prover.mut_cs());
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
		let mut verifier = Verifier::new(b"anchor");
		verifier.key_transcript(b"key", b"additional seed information");
		// Add gadgets
		let _ = anchor.gadget(verifier.mut_cs());
		// Compute Commit and Verifier key
		let (ck, vk) =
			SonicKZG10::<Bn254, DensePolynomial<Bn254Fr>>::trim(&u_params, 1 << 18, 0, None)
				.unwrap();
		// Preprocess circuit
		verifier.preprocess(&ck.powers()).unwrap();

		// The arbitrary data is stored at index 5 of the public input vector:
		assert_eq!(arbitrary_data, public_inputs[7]);
		// Modify the arbitrary data so that prover/verifier disagree
		public_inputs[5].double_in_place();

		// Verify proof
		let mut vk_bytes = Vec::new();
		sonic_pc::VerifierKey::<Bn254Fr>::serialize(&vk, &mut vk_bytes).unwrap();
		let kzg_vk = kzg10::VerifierKey::<Bn254Fr>::deserialize(&vk_bytes[..]).unwrap();
		let res = verifier
			.verify(&proof, &kzg_vk, &public_inputs)
			.unwrap_err();
		match res {
			Error::ProofVerificationError => (),
			err => panic!("Unexpected error: {:?}", err),
		};
	}
}
