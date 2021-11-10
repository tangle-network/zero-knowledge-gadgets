use super::common::*;
use crate::{
	arbitrary::mixer_data::Input as MixerDataInput,
	circuit::mixer::MixerCircuit,
	leaf::{
		mixer::{constraints::MixerLeafGadget, MixerLeaf, Private as LeafPrivate},
		LeafCreation,
	},
	mimc::MiMCParameters,
	poseidon::PoseidonParameters,
};
use ark_crypto_primitives::SNARK;
use ark_ec::PairingEngine;
use ark_ff::PrimeField;
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_std::{
	rand::{CryptoRng, Rng, RngCore},
	vec::Vec,
};
use paste::paste;

pub type MixerConstraintDataInput<F> = MixerDataInput<F>;

pub type Leaf_x5<F> = MixerLeaf<F, PoseidonCRH_x5_5<F>>;
pub type Leaf_Circomx5<F> = MixerLeaf<F, PoseidonCircomCRH_x5_5<F>>;

pub type LeafGadget_x5<F> =
	MixerLeafGadget<F, PoseidonCRH_x5_5<F>, PoseidonCRH_x5_5Gadget<F>, Leaf_x5<F>>;
pub type LeafGadget_Circomx5<F> = MixerLeafGadget<
	F,
	PoseidonCircomCRH_x5_5<F>,
	PoseidonCircomCRH_x5_5Gadget<F>,
	Leaf_Circomx5<F>,
>;

pub type Circuit_x5<F, const N: usize> = MixerCircuit<
	F,
	PoseidonCRH_x5_5<F>,
	PoseidonCRH_x5_5Gadget<F>,
	TreeConfig_x5<F>,
	LeafCRHGadget<F>,
	PoseidonCRH_x5_3Gadget<F>,
	Leaf_x5<F>,
	LeafGadget_x5<F>,
	N,
>;

pub type Circuit_Circomx5<F, const N: usize> = MixerCircuit<
	F,
	PoseidonCircomCRH_x5_5<F>,
	PoseidonCircomCRH_x5_5Gadget<F>,
	TreeConfig_Circomx5<F>,
	LeafCRHGadget<F>,
	PoseidonCircomCRH_x5_3Gadget<F>,
	Leaf_Circomx5<F>,
	LeafGadget_Circomx5<F>,
	N,
>;

pub type Leaf_x17<F> = MixerLeaf<F, PoseidonCRH_x17_5<F>>;
pub type LeafGadget_x17<F> =
	MixerLeafGadget<F, PoseidonCRH_x17_5<F>, PoseidonCRH_x17_5Gadget<F>, Leaf_x17<F>>;

pub type Circuit_x17<F, const N: usize> = MixerCircuit<
	F,
	PoseidonCRH_x17_5<F>,
	PoseidonCRH_x17_5Gadget<F>,
	TreeConfig_x17<F>,
	LeafCRHGadget<F>,
	PoseidonCRH_x17_3Gadget<F>,
	Leaf_x17<F>,
	LeafGadget_x17<F>,
	N,
>;

pub type Leaf_MiMC220<F> = MixerLeaf<F, MiMCCRH_220<F>>;
pub type LeafGadget_MiMC220<F> =
	MixerLeafGadget<F, MiMCCRH_220<F>, MiMCCRH_220Gadget<F>, Leaf_MiMC220<F>>;

pub type Circuit_MiMC220<F, const N: usize> = MixerCircuit<
	F,
	MiMCCRH_220<F>,
	MiMCCRH_220Gadget<F>,
	TreeConfig_MiMC220<F>,
	LeafCRHGadget<F>,
	MiMCCRH_220Gadget<F>,
	Leaf_MiMC220<F>,
	LeafGadget_MiMC220<F>,
	N,
>;

pub fn setup_arbitrary_data<F: PrimeField>(
	recipient: F,
	relayer: F,
	fee: F,
	refund: F,
) -> MixerConstraintDataInput<F> {
	MixerConstraintDataInput::new(recipient, relayer, fee, refund)
}

pub fn get_public_inputs<F: PrimeField>(
	nullifier_hash: F,
	root: F,
	recipient: F,
	relayer: F,
	fee: F,
	refund: F,
) -> Vec<F> {
	vec![nullifier_hash, root, recipient, relayer, fee, refund]
}

// Generate code for leaf setup function: `setup_<leaf>`
macro_rules! impl_setup_mixer_leaf {
	(
		leaf: $leaf_ty:ident, // leaf type
		crh: $leaf_crh_ty:ident, // crh type
		params: $leaf_crh_param_ty:ident // crh params type
	) => {
		paste! {
			pub fn [<setup_ $leaf_ty:lower>]<R: Rng, F: PrimeField>(
				params: &$leaf_crh_param_ty<F>,
				rng: &mut R,
			) -> (
				LeafPrivate<F>,
				<$leaf_ty<F> as LeafCreation<$leaf_crh_ty<F>>>::Leaf,
				<$leaf_ty<F> as LeafCreation<$leaf_crh_ty<F>>>::Nullifier,
			) {
				// Secret inputs for the leaf
				let leaf_private = $leaf_ty::generate_secrets(rng).unwrap();

				// Creating the leaf
				let leaf = $leaf_ty::create_leaf(&leaf_private, &(), params).unwrap();
				let nullifier_hash = $leaf_ty::create_nullifier_hash(&leaf_private, params).unwrap();
				(leaf_private, leaf, nullifier_hash)
			}
		}
	};
}

impl_setup_mixer_leaf!(
	leaf: Leaf_x5,
	crh: PoseidonCRH_x5_5,
	params: PoseidonParameters
);
impl_setup_mixer_leaf!(
	leaf: Leaf_Circomx5,
	crh: PoseidonCircomCRH_x5_5,
	params: PoseidonParameters
);
impl_setup_mixer_leaf!(
	leaf: Leaf_x17,
	crh: PoseidonCRH_x17_5,
	params: PoseidonParameters
);
impl_setup_mixer_leaf!(leaf: Leaf_MiMC220, crh: MiMCCRH_220, params: MiMCParameters);

// Generate code for mixer circuit setup functions:
//	1. `setup_<circuit>`
//	2. `setup_random_<circuit>`
macro_rules! impl_setup_mixer_circuit {
	(
		circuit: $circuit_ty:ident, // circuit type
		params3_fn: $params3_fn:ident,
		params5_fn: $params5_fn:ident,
		leaf_setup_fn: $leaf_setup_fn:ident,
		tree_setup_fn: $tree_setup_fn:ident
	) => {
		paste! {
			pub fn [<setup_ $circuit_ty:lower>]<R: Rng, F: PrimeField, const N: usize>(
				leaves: &[F],
				index: u64,
				recipient: F,
				relayer: F,
				fee: F,
				refund: F,
				rng: &mut R,
				curve: Curve,
			) -> ($circuit_ty<F, N>, F, F, F, Vec<F>) {
				let params3 = $params3_fn::<F>(curve);
				let params5 = $params5_fn::<F>(curve);

				let arbitrary_input = setup_arbitrary_data::<F>(recipient, relayer, fee, refund);
				let (leaf_private, leaf, nullifier_hash) = $leaf_setup_fn::<R, F>(&params5, rng);
				let mut leaves_new = leaves.to_vec();
				leaves_new.push(leaf);
				let (tree, path) = $tree_setup_fn::<F, N>(&leaves_new, index, &params3);
				let root = tree.root().inner();

				let mc = $circuit_ty::<F, N>::new(
					arbitrary_input,
					leaf_private,
					// leaf public
					(),
					params5,
					path,
					root,
					nullifier_hash,
				);
				let public_inputs = get_public_inputs(nullifier_hash, root, recipient, relayer, fee, refund);
				(mc, leaf, nullifier_hash, root, public_inputs)
			}

			pub fn [<setup_random_ $circuit_ty:lower>]<R: Rng, F: PrimeField, const N: usize>(
				rng: &mut R,
				curve: Curve,
			) -> ($circuit_ty<F, N>, F, F, F, Vec<F>) {
				let leaves = Vec::new();
				let index = 0;
				let recipient = F::rand(rng);
				let relayer = F::rand(rng);
				let fee = F::rand(rng);
				let refund = F::rand(rng);
				[<setup_ $circuit_ty:lower>](&leaves, index, recipient, relayer, fee, refund, rng, curve)
			}


		}
	};
}

impl_setup_mixer_circuit!(
	circuit: Circuit_x5,
	params3_fn: setup_params_x5_3,
	params5_fn: setup_params_x5_5,
	leaf_setup_fn: setup_leaf_x5,
	tree_setup_fn: setup_tree_and_create_path_tree_x5
);
impl_setup_mixer_circuit!(
	circuit: Circuit_Circomx5,
	params3_fn: setup_circom_params_x5_3,
	params5_fn: setup_circom_params_x5_5,
	leaf_setup_fn: setup_leaf_circomx5,
	tree_setup_fn: setup_tree_and_create_path_tree_circomx5
);
impl_setup_mixer_circuit!(
	circuit: Circuit_x17,
	params3_fn: setup_params_x17_3,
	params5_fn: setup_params_x17_5,
	leaf_setup_fn: setup_leaf_x17,
	tree_setup_fn: setup_tree_and_create_path_tree_x17
);
impl_setup_mixer_circuit!(
	circuit: Circuit_MiMC220,
	params3_fn: setup_mimc_220,
	params5_fn: setup_mimc_220, // not a typo, only params5_fn is used
	leaf_setup_fn: setup_leaf_mimc220,
	tree_setup_fn: setup_tree_and_create_path_tree_mimc220
);

macro_rules! impl_groth16_api_wrappers {
	(
		circuit: $circuit_ty:ident // circuit type
	) => {
		paste! {
			pub fn [<prove_groth16_ $circuit_ty:lower>]<
				R: RngCore + CryptoRng,
				E: PairingEngine,
				const N: usize,
			>(
				pk: &ProvingKey<E>,
				c: $circuit_ty<E::Fr, N>,
				rng: &mut R,
			) -> Proof<E> {
				Groth16::<E>::prove(pk, c, rng).unwrap()
				}

			pub fn [<setup_groth16_ $circuit_ty:lower>]<
				R: RngCore + CryptoRng,
				E: PairingEngine,
				const N: usize,
			>(
				rng: &mut R,
				c: $circuit_ty<E::Fr, N>,
			) -> (ProvingKey<E>, VerifyingKey<E>) {
				let (pk, vk) = Groth16::<E>::circuit_specific_setup(c, rng).unwrap();
				(pk, vk)
				}


			pub fn [<setup_groth16_random_ $circuit_ty:lower>]<
				R: RngCore + CryptoRng,
				E: PairingEngine,
				const N: usize,			>(
				rng: &mut R,
				curve: Curve,
			) -> (ProvingKey<E>, VerifyingKey<E>) {
				let (circuit, ..) = [<setup_random_ $circuit_ty:lower>]::<R, E::Fr, N>(rng, curve);
				let (pk, vk) = Groth16::<E>::circuit_specific_setup(circuit.clone(), rng).unwrap();
				(pk, vk)
			}
		}
	};
}

impl_groth16_api_wrappers!(circuit: Circuit_x5);
impl_groth16_api_wrappers!(circuit: Circuit_Circomx5);
impl_groth16_api_wrappers!(circuit: Circuit_x17);
impl_groth16_api_wrappers!(circuit: Circuit_MiMC220);

#[cfg(test)]
mod test {
	use super::*;
	use ark_bls12_381::{Bls12_381, Fr as Bls381};
	use ark_bn254::{Bn254, Fr as Bn254Fr};
	use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
	use ark_std::test_rng;

	// merkle proof path legth
	// TreeConfig_x5, x7 HEIGHT is hardcoded to 30
	pub const LEN: usize = 30;

	fn add_members_mock<F: PrimeField>(_leaves: Vec<F>) {}

	fn verify_zk_mock<F: PrimeField>(
		_root: F,
		_private_inputs: Vec<F>,
		_nullifier_hash: F,
		_proof_bytes: Vec<u8>,
		_path_index_commitments: Vec<F>,
		_path_node_commitments: Vec<F>,
		_recipient: F,
		_relayer: F,
	) {
	}

	#[test]
	fn should_create_setup() {
		let mut rng = test_rng();
		let curve = Curve::Bls381;
		let recipient = Bls381::from(0u8);
		let relayer = Bls381::from(0u8);
		let fee = Bls381::from(0u8);
		let refund = Bls381::from(0u8);
		let leaves = Vec::new();
		let (circuit, leaf, nullifier, root, public_inputs) = setup_circuit_x5::<_, Bls381, LEN>(
			&leaves, 0, recipient, relayer, fee, refund, &mut rng, curve,
		);

		add_members_mock(vec![leaf]);

		// let (pk, vk) = setup_circuit_groth16(&mut rng, circuit.clone());
		let (pk, vk) = setup_groth16_random_circuit_x5::<_, Bls12_381, LEN>(&mut rng, curve);
		let proof = prove_groth16_circuit_x5::<_, Bls12_381, LEN>(&pk, circuit, &mut rng);
		let res = verify_groth16::<Bls12_381>(&vk, &public_inputs, &proof);

		verify_zk_mock(
			root,
			Vec::new(),
			nullifier,
			Vec::new(),
			Vec::new(),
			Vec::new(),
			recipient,
			relayer,
		);

		assert!(res);
	}

	#[test]
	fn should_create_longer_setup() {
		let mut rng = test_rng();
		let curve = Curve::Bls381;
		let recipient = Bls381::from(0u8);
		let relayer = Bls381::from(0u8);
		let fee = Bls381::from(0u8);
		let refund = Bls381::from(0u8);
		let leaves = Vec::new();

		let params3 = setup_params_x5_3::<Bls381>(curve);
		let params5 = setup_params_x5_5::<Bls381>(curve);

		let arbitrary_input = setup_arbitrary_data::<Bls381>(recipient, relayer, fee, refund);
		let (leaf_private, leaf, nullifier_hash) = setup_leaf_x5::<_, Bls381>(&params5, &mut rng);
		let mut leaves_new = leaves.to_vec();
		leaves_new.push(leaf);
		let (tree, path) =
			setup_tree_and_create_path_tree_x5::<Bls381, LEN>(&leaves_new, 0, &params3);
		let root = tree.root().inner();

		let mc = Circuit_x5::<Bls381, LEN>::new(
			arbitrary_input,
			leaf_private,
			(),
			params5,
			path,
			root,
			nullifier_hash,
		);
		let public_inputs =
			get_public_inputs::<Bls381>(nullifier_hash, root, recipient, relayer, fee, refund);

		add_members_mock(vec![leaf]);

		// let (pk, vk) = setup_circuit_groth16(&mut rng, circuit.clone());
		let (pk, vk) = setup_groth16_random_circuit_x5::<_, Bls12_381, LEN>(&mut rng, curve);
		let proof = prove_groth16_circuit_x5::<_, Bls12_381, LEN>(&pk, mc, &mut rng);
		let res = verify_groth16::<Bls12_381>(&vk, &public_inputs, &proof);

		verify_zk_mock(
			root,
			Vec::new(),
			nullifier_hash,
			Vec::new(),
			Vec::new(),
			Vec::new(),
			recipient,
			relayer,
		);

		assert!(res);
	}

	#[test]
	fn should_handle_proof_deserialization() {
		let mut rng = test_rng();
		let curve = Curve::Bls381;
		let recipient = Bls381::from(0u8);
		let relayer = Bls381::from(0u8);
		let fee = Bls381::from(0u8);
		let refund = Bls381::from(0u8);
		let leaves = Vec::new();
		let (circuit, leaf, nullifier, root, public_inputs) =
			setup_circuit_x5(&leaves, 0, recipient, relayer, fee, refund, &mut rng, curve);

		add_members_mock(vec![leaf]);

		// let (pk, vk) = setup_circuit_groth16(&mut rng, circuit.clone());
		let (pk, vk) = setup_groth16_random_circuit_x5::<_, Bls12_381, LEN>(&mut rng, curve);
		let proof = prove_groth16_circuit_x5::<_, Bls12_381, LEN>(&pk, circuit, &mut rng);
		let mut proof_bytes = vec![0u8; proof.serialized_size()];
		proof.serialize(&mut proof_bytes[..]).unwrap();
		let proof_anew = Proof::<Bls12_381>::deserialize(&proof_bytes[..]).unwrap();
		let res = verify_groth16::<Bls12_381>(&vk, &public_inputs, &proof_anew);

		verify_zk_mock(
			root,
			Vec::new(),
			nullifier,
			Vec::new(),
			Vec::new(),
			Vec::new(),
			recipient,
			relayer,
		);

		assert!(res);
	}

	#[test]
	fn should_create_longer_setup_mimc() {
		let mut rng = test_rng();
		let curve = Curve::Bn254;
		let recipient = Bn254Fr::from(0u8);
		let relayer = Bn254Fr::from(0u8);
		let fee = Bn254Fr::from(0u8);
		let refund = Bn254Fr::from(0u8);
		let leaves = Vec::new();

		let params = setup_mimc_220::<Bn254Fr>(curve);

		let arbitrary_input = setup_arbitrary_data::<Bn254Fr>(recipient, relayer, fee, refund);
		let (leaf_private, leaf, nullifier_hash) =
			setup_leaf_mimc220::<_, Bn254Fr>(&params, &mut rng);
		let mut leaves_new = leaves.to_vec();
		leaves_new.push(leaf);
		let (tree, path) =
			setup_tree_and_create_path_tree_mimc220::<Bn254Fr, LEN>(&leaves_new, 0, &params);
		let root = tree.root().inner();

		let mc = Circuit_MiMC220::<Bn254Fr, LEN>::new(
			arbitrary_input,
			leaf_private,
			(),
			params,
			path,
			root,
			nullifier_hash,
		);
		let public_inputs =
			get_public_inputs::<Bn254Fr>(nullifier_hash, root, recipient, relayer, fee, refund);

		add_members_mock(vec![leaf]);

		// let (pk, vk) = setup_circuit_groth16(&mut rng, circuit.clone());
		let (pk, vk) = setup_groth16_random_circuit_mimc220::<_, Bn254, LEN>(&mut rng, curve);
		let proof = prove_groth16_circuit_mimc220::<_, Bn254, LEN>(&pk, mc, &mut rng);
		let res = verify_groth16::<Bn254>(&vk, &public_inputs, &proof);

		verify_zk_mock(
			root,
			Vec::new(),
			nullifier_hash,
			Vec::new(),
			Vec::new(),
			Vec::new(),
			recipient,
			relayer,
		);

		assert!(res);
	}
}
