use crate::{
	leaf::{constraints::LeafCreationGadget, LeafCreation},
	set::{Set, SetGadget},
};
use ark_ff::fields::PrimeField;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::marker::PhantomData;
use webb_crypto_primitives::{
	crh::FixedLengthCRHGadget,
	merkle_tree::{constraints::PathVar, Config as MerkleConfig, Path},
	FixedLengthCRH,
};

struct MixerCircuit<
	F: PrimeField,
	C: MerkleConfig,
	// Hasher for the leaf creation
	H: FixedLengthCRH,
	HG: FixedLengthCRHGadget<H, F>,
	// Different hasher gadget for the tree
	HGT: FixedLengthCRHGadget<C::H, F>,
	// Type of leaf creation
	L: LeafCreation<H>,
	LG: LeafCreationGadget<F, H, HG, L>,
	// Set of merkle roots
	S: Set<F>,
	SG: SetGadget<F, S>,
> {
	// TODO: merge private and public together
	leaf_private_inputs: L::Private,
	leaf_public_inputs: L::Public,
	set_private_inputs: S::Private,
	set_public_inputs: S::Public,
	hasher_params: H::Parameters,
	tree_hasher_params: <C::H as FixedLengthCRH>::Parameters,
	path: Path<C>,
	root: <C::H as FixedLengthCRH>::Output,
	_hasher: PhantomData<H>,
	_hasher_gadget: PhantomData<HG>,
	_tree_hasher_gadget: PhantomData<HGT>,
	_leaf_creation: PhantomData<L>,
	_leaf_creation_gadget: PhantomData<LG>,
	_set: PhantomData<S>,
	_set_gadget: PhantomData<SG>,
	_merkle_config: PhantomData<C>,
}

impl<F, C, H, HG, HGT, L, LG, S, SG> MixerCircuit<F, C, H, HG, HGT, L, LG, S, SG>
where
	F: PrimeField,
	C: MerkleConfig,
	H: FixedLengthCRH,
	HG: FixedLengthCRHGadget<H, F>,
	HGT: FixedLengthCRHGadget<C::H, F>,
	L: LeafCreation<H>,
	LG: LeafCreationGadget<F, H, HG, L>,
	S: Set<F>,
	SG: SetGadget<F, S>,
{
	pub fn new(
		leaf_private_inputs: L::Private,
		leaf_public_inputs: L::Public,
		set_private_inputs: S::Private,
		set_public_inputs: S::Public,
		hasher_params: H::Parameters,
		tree_hasher_params: <C::H as FixedLengthCRH>::Parameters,
		path: Path<C>,
		root: <C::H as FixedLengthCRH>::Output,
	) -> Self {
		Self {
			leaf_private_inputs,
			leaf_public_inputs,
			set_private_inputs,
			set_public_inputs,
			hasher_params,
			tree_hasher_params,
			path,
			root,
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

impl<F, C, H, HG, HGT, L, LG, S, SG> Clone for MixerCircuit<F, C, H, HG, HGT, L, LG, S, SG>
where
	F: PrimeField,
	C: MerkleConfig,
	H: FixedLengthCRH,
	HG: FixedLengthCRHGadget<H, F>,
	HGT: FixedLengthCRHGadget<C::H, F>,
	L: LeafCreation<H>,
	LG: LeafCreationGadget<F, H, HG, L>,
	S: Set<F>,
	SG: SetGadget<F, S>,
{
	fn clone(&self) -> Self {
		let leaf_private_inputs = self.leaf_private_inputs.clone();
		let leaf_public_inputs = self.leaf_public_inputs.clone();
		let set_private_inputs = self.set_private_inputs.clone();
		let set_public_inputs = self.set_public_inputs.clone();
		let hasher_params = self.hasher_params.clone();
		let tree_hasher_params = self.tree_hasher_params.clone();
		let path = self.path.clone();
		let root = self.root.clone();
		Self::new(
			leaf_private_inputs,
			leaf_public_inputs,
			set_private_inputs,
			set_public_inputs,
			hasher_params,
			tree_hasher_params,
			path,
			root,
		)
	}
}

impl<F, C, H, HG, HGT, L, LG, S, SG> ConstraintSynthesizer<F>
	for MixerCircuit<F, C, H, HG, HGT, L, LG, S, SG>
where
	F: PrimeField,
	C: MerkleConfig,
	H: FixedLengthCRH,
	HG: FixedLengthCRHGadget<H, F>,
	HGT: FixedLengthCRHGadget<C::H, F>,
	L: LeafCreation<H>,
	LG: LeafCreationGadget<F, H, HG, L>,
	S: Set<F>,
	SG: SetGadget<F, S>,
{
	fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
		let leaf_private = self.leaf_private_inputs;
		let leaf_public = self.leaf_public_inputs;
		let set_private = self.set_private_inputs;
		let set_public = self.set_public_inputs;
		let hasher_params = self.hasher_params;
		let path = self.path;
		let root = self.root;
		let tree_hasher_params = self.tree_hasher_params;

		// Generating vars
		// Public inputs
		let leaf_public_var = LG::PublicVar::new_input(cs.clone(), || Ok(leaf_public))?;
		let set_input_public_var = SG::PublicVar::new_input(cs.clone(), || Ok(set_public))?;
		let root_var = HGT::OutputVar::new_input(cs.clone(), || Ok(root))?;

		// Private inputs
		let leaf_private_var = LG::PrivateVar::new_witness(cs.clone(), || Ok(leaf_private))?;
		let set_input_private_var = SG::PrivateVar::new_witness(cs.clone(), || Ok(set_private))?;
		let hasher_params_var = HG::ParametersVar::new_constant(cs.clone(), hasher_params)?;
		let tree_hasher_params_var =
			HGT::ParametersVar::new_constant(cs.clone(), tree_hasher_params)?;
		let path_var = PathVar::<C, HGT, F>::new_witness(cs.clone(), || Ok(path))?;

		// Creating the leaf and checking the membership inside the tree
		let bridge_out = LG::create(&leaf_private_var, &leaf_public_var, &hasher_params_var)?;
		let is_member =
			path_var.check_membership(&tree_hasher_params_var, &root_var, &bridge_out)?;
		// Check if target root is in set
		let is_set_member = SG::check_membership(&set_input_public_var, &set_input_private_var)?;

		// Enforcing constraints
		is_member.enforce_equal(&Boolean::TRUE)?;
		is_set_member.enforce_equal(&Boolean::TRUE)?;

		Ok(())
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::{
		leaf::bridge::{constraints::BridgeLeafGadget, BridgeLeaf, Public as LeafPublic},
		set::membership::{
			constraints::SetMembershipGadget, Public as SetPublicInputs, SetMembership,
		},
		test_data::{get_mds_3, get_mds_5, get_rounds_3, get_rounds_5},
	};
	use ark_bls12_381::{Bls12_381, Fr as BlsFr};
	use ark_ed_on_bn254::{EdwardsAffine, Fr as BabyJubJub};
	use ark_ff::{One, UniformRand};
	use ark_marlin::Marlin;
	use ark_poly::univariate::DensePolynomial;
	use ark_poly_commit::{ipa_pc::InnerProductArgPC, marlin_pc::MarlinKZG10};
	use ark_std::test_rng;
	use blake2::Blake2s;
	use webb_crypto_primitives::{
		crh::poseidon::{
			constraints::CRHGadget, sbox::PoseidonSbox, PoseidonParameters, Rounds, CRH,
		},
		merkle_tree::MerkleTree,
	};

	macro_rules! setup_circuit {
		($test_field:ty) => {{
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
				MixerTreeConfig,
				PoseidonCRH5,
				PoseidonCRH5Gadget,
				PoseidonCRH3Gadget,
				Leaf,
				LeafGadget,
				TestSetMembership,
				TestSetMembershipGadget,
			>;

			let rng = &mut test_rng();

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
			let res = Leaf::create(&leaf_private, &leaf_public, &params5).unwrap();

			// Making params for poseidon in merkle tree
			let rounds3 = get_rounds_3::<$test_field>();
			let mds3 = get_mds_3::<$test_field>();
			let params3 = PoseidonParameters::<$test_field>::new(rounds3, mds3);
			let leaves = vec![
				<$test_field>::rand(rng),
				<$test_field>::rand(rng),
				res.leaf,
				<$test_field>::rand(rng),
			];
			// Making the merkle tree
			let mt = MixerTree::new(params3.clone(), &leaves).unwrap();
			// Getting the proof path
			let path = mt.generate_proof(2, &res.leaf).unwrap();
			let root = mt.root();
			let roots = vec![
				<$test_field>::rand(rng),
				<$test_field>::rand(rng),
				<$test_field>::rand(rng),
				root,
			];
			let set_public_inputs = SetPublicInputs::new(root, roots.clone());
			let set_private_inputs = TestSetMembership::generate_secrets(&root, roots);
			let mc = Circuit::new(
				leaf_private,
				leaf_public,
				set_private_inputs,
				set_public_inputs,
				params5,
				params3,
				path,
				root,
			);
			mc
		}};
	}

	#[test]
	fn setup_and_prove_marlin_bls() {
		let rng = &mut test_rng();
		let mc = setup_circuit!(BlsFr);

		type UniPoly = DensePolynomial<BlsFr>;
		type KZG10 = MarlinKZG10<Bls12_381, UniPoly>;
		type MarlinBlsSetup = Marlin<BlsFr, KZG10, Blake2s>;

		let srs = MarlinBlsSetup::universal_setup(33_000, 33_000, 33_000, rng).unwrap();
		let (pk, _sk) = MarlinBlsSetup::index(&srs, mc.clone()).unwrap();
		let _proof = MarlinBlsSetup::prove(&pk, mc, rng).unwrap();
	}

	fn setup_and_prove_marlin_ipa_pc() {
		let rng = &mut test_rng();
		let mc = setup_circuit!(BabyJubJub);

		type UniPoly = DensePolynomial<BabyJubJub>;
		type IPA = InnerProductArgPC<EdwardsAffine, Blake2s, UniPoly>;
		type MarlinIpaSetup = Marlin<BabyJubJub, IPA, Blake2s>;

		let srs = MarlinIpaSetup::universal_setup(10, 10, 300, rng).unwrap();
		let (pk, _) = MarlinIpaSetup::index(&srs, mc.clone()).unwrap();
		let _ = MarlinIpaSetup::prove(&pk, mc, rng).unwrap();
	}
}
