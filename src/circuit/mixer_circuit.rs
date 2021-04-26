use crate::{
	arbitrary::{constraints::ArbitraryGadget, Arbitrary},
	leaf::{constraints::LeafCreationGadget, LeafCreation},
	set::{Set, SetGadget},
};
use ark_ff::fields::PrimeField;
use ark_r1cs_std::{eq::EqGadget, fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::marker::PhantomData;
use webb_crypto_primitives::{
	crh::FixedLengthCRHGadget,
	merkle_tree::{constraints::PathVar, Config as MerkleConfig, Path},
	FixedLengthCRH,
};

struct MixerCircuit<
	F: PrimeField,
	// Arbitrary data constraints
	A: Arbitrary,
	AG: ArbitraryGadget<F, A>,
	// Hasher for the leaf creation
	H: FixedLengthCRH,
	HG: FixedLengthCRHGadget<H, F>,
	// Merkle config and hasher gadget for the tree
	C: MerkleConfig,
	HGT: FixedLengthCRHGadget<C::H, F>,
	// Type of leaf creation
	L: LeafCreation<H>,
	LG: LeafCreationGadget<F, H, HG, L>,
	// Set of merkle roots
	S: Set<F>,
	SG: SetGadget<F, S>,
> {
	arbitrary_input: A::Input,
	leaf_private_inputs: L::Private,
	leaf_public_inputs: L::Public,
	set_private_inputs: S::Private,
	root_set: Vec<F>,
	hasher_params: H::Parameters,
	tree_hasher_params: <C::H as FixedLengthCRH>::Parameters,
	path: Path<C>,
	root: <C::H as FixedLengthCRH>::Output,
	nullifier_hash: L::Nullifier,
	_arbitrary_gadget: PhantomData<AG>,
	_hasher: PhantomData<H>,
	_hasher_gadget: PhantomData<HG>,
	_tree_hasher_gadget: PhantomData<HGT>,
	_leaf_creation: PhantomData<L>,
	_leaf_creation_gadget: PhantomData<LG>,
	_set: PhantomData<S>,
	_set_gadget: PhantomData<SG>,
	_merkle_config: PhantomData<C>,
}

impl<F, A, AG, H, HG, C, HGT, L, LG, S, SG> MixerCircuit<F, A, AG, H, HG, C, HGT, L, LG, S, SG>
where
	F: PrimeField,
	A: Arbitrary,
	AG: ArbitraryGadget<F, A>,
	H: FixedLengthCRH,
	HG: FixedLengthCRHGadget<H, F>,
	C: MerkleConfig,
	HGT: FixedLengthCRHGadget<C::H, F>,
	L: LeafCreation<H>,
	LG: LeafCreationGadget<F, H, HG, L>,
	S: Set<F>,
	SG: SetGadget<F, S>,
{
	pub fn new(
		arbitrary_input: A::Input,
		leaf_private_inputs: L::Private,
		leaf_public_inputs: L::Public,
		set_private_inputs: S::Private,
		root_set: Vec<F>,
		hasher_params: H::Parameters,
		tree_hasher_params: <C::H as FixedLengthCRH>::Parameters,
		path: Path<C>,
		root: <C::H as FixedLengthCRH>::Output,
		nullifier_hash: L::Nullifier,
	) -> Self {
		Self {
			arbitrary_input,
			leaf_private_inputs,
			leaf_public_inputs,
			set_private_inputs,
			root_set,
			hasher_params,
			tree_hasher_params,
			path,
			root,
			nullifier_hash,
			_arbitrary_gadget: PhantomData,
			_hasher: PhantomData,
			_hasher_gadget: PhantomData,
			_tree_hasher_gadget: PhantomData,
			_leaf_creation: PhantomData,
			_leaf_creation_gadget: PhantomData,
			_set: PhantomData,
			_set_gadget: PhantomData,
			_merkle_config: PhantomData,
		}
	}
}

impl<F, A, AG, H, HG, C, HGT, L, LG, S, SG> Clone
	for MixerCircuit<F, A, AG, H, HG, C, HGT, L, LG, S, SG>
where
	F: PrimeField,
	A: Arbitrary,
	AG: ArbitraryGadget<F, A>,
	H: FixedLengthCRH,
	HG: FixedLengthCRHGadget<H, F>,
	C: MerkleConfig,
	HGT: FixedLengthCRHGadget<C::H, F>,
	L: LeafCreation<H>,
	LG: LeafCreationGadget<F, H, HG, L>,
	S: Set<F>,
	SG: SetGadget<F, S>,
{
	fn clone(&self) -> Self {
		let arbitrary_input = self.arbitrary_input.clone();
		let leaf_private_inputs = self.leaf_private_inputs.clone();
		let leaf_public_inputs = self.leaf_public_inputs.clone();
		let set_private_inputs = self.set_private_inputs.clone();
		let root_set = self.root_set.clone();
		let hasher_params = self.hasher_params.clone();
		let tree_hasher_params = self.tree_hasher_params.clone();
		let path = self.path.clone();
		let root = self.root.clone();
		let nullifier_hash = self.nullifier_hash.clone();
		Self::new(
			arbitrary_input,
			leaf_private_inputs,
			leaf_public_inputs,
			set_private_inputs,
			root_set,
			hasher_params,
			tree_hasher_params,
			path,
			root,
			nullifier_hash,
		)
	}
}

impl<F, A, AG, H, HG, C, HGT, L, LG, S, SG> ConstraintSynthesizer<F>
	for MixerCircuit<F, A, AG, H, HG, C, HGT, L, LG, S, SG>
where
	F: PrimeField,
	A: Arbitrary,
	AG: ArbitraryGadget<F, A>,
	H: FixedLengthCRH,
	HG: FixedLengthCRHGadget<H, F>,
	C: MerkleConfig,
	HGT: FixedLengthCRHGadget<C::H, F>,
	L: LeafCreation<H>,
	LG: LeafCreationGadget<F, H, HG, L>,
	S: Set<F>,
	SG: SetGadget<F, S>,
{
	fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
		let arbitrary_input = self.arbitrary_input;
		let leaf_private = self.leaf_private_inputs;
		let leaf_public = self.leaf_public_inputs;
		let set_private = self.set_private_inputs;
		let root_set = self.root_set;
		let hasher_params = self.hasher_params;
		let path = self.path;
		let root = self.root;
		let tree_hasher_params = self.tree_hasher_params;
		let nullifier_hash = self.nullifier_hash;

		// Generating vars
		// Public inputs
		let leaf_public_var = LG::PublicVar::new_input(cs.clone(), || Ok(leaf_public))?;
		let nullifier_hash_var = LG::NullifierVar::new_input(cs.clone(), || Ok(nullifier_hash))?;
		let root_set_var = Vec::<FpVar<F>>::new_input(cs.clone(), || Ok(root_set))?;
		let root_var = HGT::OutputVar::new_input(cs.clone(), || Ok(root))?;
		let arbitrary_input_var = AG::InputVar::new_input(cs.clone(), || Ok(arbitrary_input))?;

		// Private inputs
		let leaf_private_var = LG::PrivateVar::new_witness(cs.clone(), || Ok(leaf_private))?;
		let set_input_private_var = SG::PrivateVar::new_witness(cs.clone(), || Ok(set_private))?;
		let hasher_params_var = HG::ParametersVar::new_constant(cs.clone(), hasher_params)?;
		let tree_hasher_params_var =
			HGT::ParametersVar::new_constant(cs.clone(), tree_hasher_params)?;
		let path_var = PathVar::<C, HGT, F>::new_witness(cs.clone(), || Ok(path))?;

		// Creating the leaf and checking the membership inside the tree
		let bridge_leaf = LG::create_leaf(&leaf_private_var, &leaf_public_var, &hasher_params_var)?;
		let bridge_nullifier = LG::create_nullifier(&leaf_private_var, &hasher_params_var)?;
		let is_member =
			path_var.check_membership(&tree_hasher_params_var, &root_var, &bridge_leaf)?;
		// Check if target root is in set
		let is_set_member = SG::check(&root_var, &root_set_var, &set_input_private_var)?;
		// Constraining arbitrary inputs
		AG::constrain(&arbitrary_input_var)?;

		// // Enforcing constraints
		is_member.enforce_equal(&Boolean::TRUE)?;
		is_set_member.enforce_equal(&Boolean::TRUE)?;
		bridge_nullifier.enforce_equal(&nullifier_hash_var)?;

		Ok(())
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::{
		arbitrary::mixer_data::{constraints::MixerDataGadget, Input as MixerDataInput, MixerData},
		leaf::bridge::{constraints::BridgeLeafGadget, BridgeLeaf, Public as LeafPublic},
		set::membership::{constraints::SetMembershipGadget, SetMembership},
		test_data::{get_mds_3, get_mds_5, get_rounds_3, get_rounds_5},
	};
	use ark_bls12_381::{Bls12_381, Fr as BlsFr};
	use ark_ff::{One, UniformRand};
	use ark_groth16::Groth16;
	use ark_std::test_rng;
	use webb_crypto_primitives::{
		crh::poseidon::{
			constraints::CRHGadget, sbox::PoseidonSbox, PoseidonParameters, Rounds, CRH,
		},
		merkle_tree::MerkleTree,
		SNARK,
	};

	macro_rules! setup_circuit {
		($test_field:ty) => {{
			type MixerConstraintData = MixerData<$test_field>;
			type MixerConstraintDataGadget = MixerDataGadget<$test_field>;
			#[derive(Default, Clone)]
			struct PoseidonRounds5;

			impl Rounds for PoseidonRounds5 {
				const FULL_ROUNDS: usize = 8;
				const PARTIAL_ROUNDS: usize = 57;
				const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
				const WIDTH: usize = 5;
			}

			type PoseidonCRH5 = CRH<$test_field, PoseidonRounds5>;
			type PoseidonCRH5Gadget = CRHGadget<$test_field, PoseidonRounds5>;

			#[derive(Default, Clone)]
			struct PoseidonRounds3;

			impl Rounds for PoseidonRounds3 {
				const FULL_ROUNDS: usize = 8;
				const PARTIAL_ROUNDS: usize = 57;
				const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
				const WIDTH: usize = 3;
			}

			type PoseidonCRH3 = CRH<$test_field, PoseidonRounds3>;
			type PoseidonCRH3Gadget = CRHGadget<$test_field, PoseidonRounds3>;

			type Leaf = BridgeLeaf<$test_field, PoseidonCRH5>;
			type LeafGadget = BridgeLeafGadget<$test_field, PoseidonCRH5, PoseidonCRH5Gadget, Leaf>;

			#[derive(Clone)]
			struct MixerTreeConfig;
			impl MerkleConfig for MixerTreeConfig {
				type H = PoseidonCRH3;

				const HEIGHT: usize = 10;
			}

			type MixerTree = MerkleTree<MixerTreeConfig>;

			type TestSetMembership = SetMembership<$test_field>;
			type TestSetMembershipGadget = SetMembershipGadget<$test_field>;

			type Circuit = MixerCircuit<
				$test_field,
				MixerConstraintData,
				MixerConstraintDataGadget,
				PoseidonCRH5,
				PoseidonCRH5Gadget,
				MixerTreeConfig,
				PoseidonCRH3Gadget,
				Leaf,
				LeafGadget,
				TestSetMembership,
				TestSetMembershipGadget,
			>;

			let rng = &mut test_rng();

			let fee = <$test_field>::rand(rng);
			let recipient = <$test_field>::rand(rng);
			let relayer = <$test_field>::rand(rng);
			// Arbitrary data
			let arbitrary_input = MixerDataInput::new(recipient, relayer, fee);

			// Secret inputs for the leaf
			let leaf_private = Leaf::generate_secrets(rng).unwrap();
			// Public inputs for the leaf
			let chain_id = <$test_field>::one();
			let leaf_public = LeafPublic::new(chain_id);

			// Round params for the poseidon in leaf creation gadget
			let rounds5 = get_rounds_5::<$test_field>();
			let mds5 = get_mds_5::<$test_field>();
			let params5 = PoseidonParameters::<$test_field>::new(rounds5, mds5);
			// Creating the leaf
			let leaf = Leaf::create_leaf(&leaf_private, &leaf_public, &params5).unwrap();
			let nullifier_hash = Leaf::create_nullifier(&leaf_private, &params5).unwrap();

			// Making params for poseidon in merkle tree
			let rounds3 = get_rounds_3::<$test_field>();
			let mds3 = get_mds_3::<$test_field>();
			let params3 = PoseidonParameters::<$test_field>::new(rounds3, mds3);
			let leaves = vec![
				<$test_field>::rand(rng),
				<$test_field>::rand(rng),
				leaf,
				<$test_field>::rand(rng),
			];
			// Making the merkle tree
			let mt = MixerTree::new(params3.clone(), &leaves).unwrap();
			// Getting the proof path
			let path = mt.generate_proof(2, &leaf).unwrap();
			let root = mt.root();
			let roots = vec![
				<$test_field>::rand(rng),
				<$test_field>::rand(rng),
				<$test_field>::rand(rng),
				root,
			];
			let set_private_inputs = TestSetMembership::generate_secrets(&root, &roots).unwrap();
			let mc = Circuit::new(
				arbitrary_input.clone(),
				leaf_private,
				leaf_public,
				set_private_inputs,
				roots.clone(),
				params5,
				params3,
				path,
				root,
				nullifier_hash,
			);
			(chain_id, root, roots, nullifier_hash, arbitrary_input, mc)
		}};
	}

	#[test]
	fn setup_and_prove_mixer_groth16() {
		let rng = &mut test_rng();
		let (chain_id, root, roots, nullifier_hash, arbitrary_input, circuit) =
			setup_circuit!(BlsFr);

		type GrothSetup = Groth16<Bls12_381>;

		let (pk, vk) = GrothSetup::circuit_specific_setup(circuit.clone(), rng).unwrap();
		let proof = GrothSetup::prove(&pk, circuit, rng).unwrap();

		let mut public_inputs = Vec::new();
		public_inputs.push(chain_id);
		public_inputs.push(nullifier_hash);
		public_inputs.extend(roots);
		public_inputs.push(root);
		public_inputs.push(arbitrary_input.recipient);
		public_inputs.push(arbitrary_input.relayer);
		public_inputs.push(arbitrary_input.fee);
		let res = GrothSetup::verify(&vk, &public_inputs, &proof).unwrap();
		assert!(res);
	}
}
