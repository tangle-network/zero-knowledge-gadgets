use crate::poseidon::poseidon::FieldHasherGadget;
use ark_ec::models::TEModelParameters;
use ark_ff::PrimeField;
use ark_std::marker::PhantomData;
use arkworks_gadgets::merkle_tree::simple_merkle::Path;
use plonk::{constraint_system::StandardComposer, error::Error, prelude::Variable};

#[derive(Clone)]
pub struct PathVar<
	F: PrimeField,
	P: TEModelParameters<BaseField = F>,
	HG: FieldHasherGadget<F, P>,
	const N: usize,
> {
	path: [(Variable, Variable); N],
	_field: PhantomData<F>,
	_te: PhantomData<P>,
	_hg: PhantomData<HG>,
}

impl<
		F: PrimeField,
		P: TEModelParameters<BaseField = F>,
		HG: FieldHasherGadget<F, P>,
		const N: usize,
	> PathVar<F, P, HG, N>
{
	fn from_native(composer: &mut StandardComposer<F, P>, native: Path<F, HG::Native, N>) -> Self {
		// Initialize the array
		let mut path_vars = [(composer.zero_var(), composer.zero_var()); N];

		for i in 0..N {
			path_vars[i] = (
				composer.add_input(native.path[i].0),
				composer.add_input(native.path[i].1),
			);
		}

		PathVar {
			path: path_vars,
			_field: PhantomData,
			_te: PhantomData,
			_hg: PhantomData,
		}
	}

	pub fn check_membership(
		&self,
		composer: &mut StandardComposer<F, P>,
		root_hash: &Variable,
		leaf: &Variable,
		hasher: &HG,
	) -> Result<Variable, Error> {
		let computed_root = self.calculate_root(composer, leaf, hasher)?;

		composer.assert_equal(computed_root, *root_hash);

		Ok(composer.is_eq_with_output(computed_root, *root_hash))
	}

	pub fn calculate_root(
		&self,
		composer: &mut StandardComposer<F, P>,
		leaf: &Variable,
		hash_gadget: &HG,
	) -> Result<Variable, Error> {
		// Check levels between leaf level and root
		let mut previous_hash = *leaf;

		for (left_hash, right_hash) in self.path.iter() {
			// Check if previous_hash matches the correct current hash
			let previous_is_left = composer.is_eq_with_output(previous_hash, *left_hash);
			let left_or_right =
				composer.conditional_select(previous_is_left, *left_hash, *right_hash);
			composer.assert_equal(previous_hash, left_or_right);

			// Update previous_hash
			previous_hash = hash_gadget.hash_two(composer, left_hash, right_hash)?;
		}

		Ok(previous_hash)
	}
}

#[cfg(test)]
mod test {
	use super::PathVar;
	use crate::poseidon::poseidon::{FieldHasherGadget, PoseidonGadget};
	use ark_bn254::{Bn254, Fr as Bn254Fr};
	use ark_ec::TEModelParameters;
	use ark_ed_on_bn254::{EdwardsParameters as JubjubParameters, Fq};
	use ark_ff::PrimeField;
	use ark_poly::polynomial::univariate::DensePolynomial;
	use ark_poly_commit::{kzg10::UniversalParams, sonic_pc::SonicKZG10, PolynomialCommitment};
	use ark_std::test_rng;
	use arkworks_gadgets::{
		ark_std::UniformRand, merkle_tree::simple_merkle::SparseMerkleTree,
		poseidon::field_hasher::Poseidon,
	};
	use arkworks_utils::utils::common::{setup_params_x5_3, Curve};
	use plonk::prelude::*;

	type PoseidonBn254 = Poseidon<Fq>;

	struct TestCircuit<
		'a,
		F: PrimeField,
		P: TEModelParameters<BaseField = F>,
		HG: FieldHasherGadget<F, P>,
		const N: usize,
	> {
		leaves: &'a [F],
		empty_leaf: &'a [u8],
		hasher: &'a HG::Native,
	}

	impl<
			F: PrimeField,
			P: TEModelParameters<BaseField = F>,
			HG: FieldHasherGadget<F, P>,
			const N: usize,
		> Circuit<F, P> for TestCircuit<'_, F, P, HG, N>
	{
		const CIRCUIT_ID: [u8; 32] = [0xfe; 32];

		fn gadget(&mut self, composer: &mut StandardComposer<F, P>) -> Result<(), Error> {
			let hasher_gadget = HG::from_native(composer, self.hasher.clone());

			let smt = SparseMerkleTree::<F, HG::Native, N>::new_sequential(
				self.leaves,
				&self.hasher,
				self.empty_leaf,
			)
			.unwrap();
			let root = smt.root();
			let path = smt.generate_membership_proof(0);

			let path_var = PathVar::<F, P, HG, N>::from_native(composer, path);
			let root_var = composer.add_input(root);
			let leaf_var = composer.add_input(self.leaves[0]);

			let res = path_var.check_membership(composer, &root_var, &leaf_var, &hasher_gadget)?;
			let one = composer.add_input(F::one());
			composer.assert_equal(res, one);

			Ok(())
		}

		fn padded_circuit_size(&self) -> usize {
			1 << 13
		}
	}

	#[test]
	fn should_verify_path() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;

		let params = setup_params_x5_3(curve);
		let poseidon = PoseidonBn254 { params };

		let leaves = [Fq::rand(rng), Fq::rand(rng), Fq::rand(rng)];
		let empty_leaf = [0u8; 32];

		// Create the test circuit
		let mut test_circuit = TestCircuit::<Bn254Fr, JubjubParameters, PoseidonGadget, 3usize> {
			leaves: &leaves,
			empty_leaf: &empty_leaf,
			hasher: &poseidon,
		};

		// Usual prover/verifier flow:
		let u_params: UniversalParams<Bn254> =
			SonicKZG10::<Bn254, DensePolynomial<Bn254Fr>>::setup(1 << 14, None, rng).unwrap();

		let (pk, vd) = test_circuit
			.compile::<SonicKZG10<Bn254, DensePolynomial<Bn254Fr>>>(&u_params)
			.unwrap();

		// PROVER
		let proof = test_circuit.gen_proof(&u_params, pk, b"SMT Test").unwrap();

		// VERIFIER
		let public_inputs: Vec<PublicInputValue<Bn254Fr>> = vec![];

		let VerifierData { key, pi_pos } = vd;

		circuit::verify_proof::<_, JubjubParameters, _>(
			&u_params,
			key,
			&proof,
			&public_inputs,
			&pi_pos,
			b"SMT Test",
		)
		.unwrap();
	}
}
