use crate::{
	merkle_tree::PathGadget,
	poseidon::poseidon::{FieldHasherGadget, PoseidonGadget},
};
use ark_ec::models::TEModelParameters;
use ark_ff::PrimeField;
use ark_std::marker::PhantomData;
use arkworks_gadgets::merkle_tree::simple_merkle::Path;
use plonk_core::{
	circuit::Circuit, constraint_system::StandardComposer, error::Error, prelude::Variable,
};

pub struct MixerCircuit<
	F: PrimeField,
	P: TEModelParameters<BaseField = F>,
	HG: FieldHasherGadget<F, P>,
	const N: usize,
> {
	secret: F,
	nullifier: F,
	nullifier_hash: F,
	path: Path<F, HG::Native, N>,
	root: F,
	arbitrary_data: F,
	hasher: HG::Native,
}

impl<F, P, HG, const N: usize> MixerCircuit<F, P, HG, N>
where
	F: PrimeField,
	P: TEModelParameters<BaseField = F>,
	HG: FieldHasherGadget<F, P>,
{
	pub fn new(
		secret: F,
		nullifier: F,
		nullifier_hash: F,
		path: Path<F, HG::Native, N>,
		root: F,
		arbitrary_data: F,
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

impl<F, P, HG, const N: usize> Circuit<F, P> for MixerCircuit<F, P, HG, N>
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
		let nullifier_hash = add_public_input_variable(composer, self.nullifier_hash);
		let root = add_public_input_variable(composer, self.root);
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

		// Proof of Merkle tree membership
		let is_member = path_gadget.check_membership(composer, &root, &res_leaf, &hasher_gadget)?;
		let one = composer.add_witness_to_circuit_description(F::one());
		composer.assert_equal(is_member, one);

		// Safety constraint to prevent tampering with arbitrary_data
		let _arbitrary_data_squared = composer.arithmetic_gate(|gate| {
			gate.witness(arbitrary_data, arbitrary_data, None)
				.mul(F::one())
		});
		Ok(())
	}

	fn padded_circuit_size(&self) -> usize {
		1 << 17
	}
}

/// Add a variable to a circuit and constrain it to a public input value that
/// is expected to be different in each instance of the circuit.
pub fn add_public_input_variable<F, P>(composer: &mut StandardComposer<F, P>, value: F) -> Variable
where
	F: PrimeField,
	P: TEModelParameters<BaseField = F>,
{
	let variable = composer.add_input(value);
	composer.poly_gate(
		variable,
		variable,
		variable,
		F::zero(),
		-F::one(),
		F::zero(),
		F::zero(),
		F::zero(),
		Some(value),
	);
	variable
}

#[cfg(test)]
mod test {
	use super::MixerCircuit;
	use crate::poseidon::poseidon::{FieldHasherGadget, PoseidonGadget};
	use ark_bn254::{Bn254, Fr as Bn254Fr};
	use ark_ec::TEModelParameters;
	use ark_ed_on_bn254::{EdwardsParameters as JubjubParameters, Fq};
	use ark_ff::PrimeField;
	use ark_poly::polynomial::univariate::DensePolynomial;
	use ark_poly_commit::{kzg10::UniversalParams, sonic_pc::SonicKZG10, PolynomialCommitment};
	use ark_std::test_rng;
	use arkworks_gadgets::{
		arbitrary,
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
	fn should_verify_correct_mixer() {
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
		// This tree has only 1 non-trivial leaf -- maybe more should be randomly
		// generated?
		let tree = SparseMerkleTree::<Fq, PoseidonBn254, 3usize>::new_sequential(
			&[leaf_hash],
			&poseidon_native,
			&[0u8; 32],
		)
		.unwrap();
		let root = tree.root();

		// Path
		let path = tree.generate_membership_proof(0);

		// Create MixerCircuit
		let mut mixer = MixerCircuit::<Fq, JubjubParameters, PoseidonGadget, 3usize>::new(
			secret,
			nullifier,
			nullifier_hash,
			path,
			root,
			arbitrary_data,
			poseidon_native,
		);

		// Fill a composer and check circuit is satisfied
		let mut composer = StandardComposer::<Fq, JubjubParameters>::new();
		let _ = mixer.gadget(&mut composer);
		composer.check_circuit_satisfied();

		// Go through proof generation/verification

		let u_params: UniversalParams<Bn254> =
			SonicKZG10::<Bn254, DensePolynomial<Bn254Fr>>::setup(1 << 18, None, rng).unwrap();

		let proof = {
			// Create a prover struct
			let mut prover =
				Prover::<Fq, JubjubParameters, SonicKZG10<Bn254, DensePolynomial<Bn254Fr>>>::new(
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
			prover.preprocess(&ck);

			// Compute Proof
			prover.prove(&ck).unwrap()
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
		verifier.preprocess(&ck).unwrap();

		// Construct public input vector from composer above
		let public_inputs = composer.construct_dense_pi_vec();

		println!(
			"The length of the public input vector is {:?}",
			public_inputs.len()
		);

		// Verify proof
		let _ = verifier.verify(&proof, &vk, &public_inputs).unwrap();
	}
}
