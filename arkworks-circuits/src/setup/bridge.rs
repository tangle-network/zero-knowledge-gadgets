use super::common::*;
use crate::circuit::bridge::BridgeCircuit;

use arkworks_gadgets::{
	arbitrary::bridge_data::Input as BridgeDataInput,
	leaf::bridge::{
		constraints::BridgeLeafGadget, BridgeLeaf, Private as LeafPrivate, Public as LeafPublic,
	},
	set::membership::{
		constraints::SetMembershipGadget, Private as SetMembershipPrivate, SetMembership,
	},
};
use arkworks_utils::{
	poseidon::PoseidonParameters,
	utils::common::{
		setup_params_x17_3, setup_params_x17_5, setup_params_x5_3, setup_params_x5_5, Curve,
	},
};

use ark_crypto_primitives::{CRH as CRHTrait, SNARK};
use ark_ec::PairingEngine;
use ark_ff::PrimeField;
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_std::{
	rand::{CryptoRng, Rng, RngCore},
	vec::Vec,
};
use paste::paste;

pub type BridgeConstraintDataInput<F> = BridgeDataInput<F>;

pub type Leaf_x5<F> = BridgeLeaf<F, PoseidonCRH_x5_5<F>>;

pub type LeafGadget_x5<F> = BridgeLeafGadget<F, PoseidonCRH_x5_5<F>, PoseidonCRH_x5_5Gadget<F>>;

pub type TestSetMembership<F, const M: usize> = SetMembership<F, M>;
pub type TestSetMembershipGadget<F, const M: usize> = SetMembershipGadget<F, M>;

pub type Circuit_x5<F, const N: usize, const M: usize> = BridgeCircuit<
	F,
	PoseidonCRH_x5_5<F>,
	PoseidonCRH_x5_5Gadget<F>,
	TreeConfig_x5<F>,
	LeafCRHGadget<F>,
	PoseidonCRH_x5_3Gadget<F>,
	N,
	M,
>;

pub type Leaf_x17<F> = BridgeLeaf<F, PoseidonCRH_x17_5<F>>;
pub type LeafGadget_x17<F> = BridgeLeafGadget<F, PoseidonCRH_x17_5<F>, PoseidonCRH_x17_5Gadget<F>>;

pub type Circuit_x17<F, const N: usize, const M: usize> = BridgeCircuit<
	F,
	PoseidonCRH_x17_5<F>,
	PoseidonCRH_x17_5Gadget<F>,
	TreeConfig_x17<F>,
	LeafCRHGadget<F>,
	PoseidonCRH_x17_3Gadget<F>,
	N,
	M,
>;

pub fn setup_set<F: PrimeField, const M: usize>(
	root: &F,
	roots: &[F; M],
) -> SetMembershipPrivate<F, M> {
	TestSetMembership::generate_secrets(root, roots).unwrap()
}

pub fn setup_arbitrary_data<F: PrimeField>(
	recipient: F,
	relayer: F,
	fee: F,
	refund: F,
	commitment: F,
) -> BridgeConstraintDataInput<F> {
	BridgeConstraintDataInput::new(recipient, relayer, fee, refund, commitment)
}

pub fn get_public_inputs<F: PrimeField, const M: usize>(
	chain_id: F,
	nullifier_hash: F,
	roots: [F; M],
	root: F,
	recipient: F,
	relayer: F,
	fee: F,
	refund: F,
	commitment: F,
) -> Vec<F> {
	vec![
		chain_id,
		nullifier_hash,
		roots[M - 2],
		roots[M - 1],
		root,
		recipient,
		relayer,
		fee,
		refund,
		commitment,
	]
}

// Generate code for leaf setup function: `setup_<leaf>`
macro_rules! impl_setup_bridge_leaf {
	(
		name: $leaf_name:ident,
		crh: $leaf_crh_ty:ident, // crh type
		params: $leaf_crh_param_ty:ident // crh params type
	) => {
		paste! {
			pub fn [<setup_leaf_ $leaf_name:lower>]<R: Rng, F: PrimeField>(
				chain_id: F,
				params: &$leaf_crh_param_ty<F>,
				rng: &mut R,
			) -> (
				LeafPrivate<F>,
				LeafPublic<F>,
				<$leaf_crh_ty<F> as CRHTrait>::Output,
				<$leaf_crh_ty<F> as CRHTrait>::Output,
			) {
				// Secret inputs for the leaf
				let leaf_private = LeafPrivate::generate(rng);
				// Public inputs for the leaf
				let leaf_public = LeafPublic::new(chain_id);
				// let leaf = BridgeLeaf::<F, $leaf_crh_ty<F>>::new(leaf_private.clone(), leaf_public.clone());

				// Creating the leaf
				let leaf_hash = BridgeLeaf::<F, $leaf_crh_ty<F>>::create_leaf(
					&leaf_private,
					&leaf_public,
					params
				).unwrap();
				let nullifier_hash = BridgeLeaf::<F, $leaf_crh_ty<F>>::create_nullifier(
					&leaf_private,
					params
				).unwrap();
				(leaf_private, leaf_public, leaf_hash, nullifier_hash)
			}
		}
	};
}

impl_setup_bridge_leaf!(name: x5, crh: PoseidonCRH_x5_5, params: PoseidonParameters);
impl_setup_bridge_leaf!(
	name: x17,
	crh: PoseidonCRH_x17_5,
	params: PoseidonParameters
);

// Generate code for bridge circuit setup functions:
//	1. `setup_<circuit>`
//	2. `setup_random_<circuit>`
macro_rules! impl_setup_bridge_circuit {
	(
		circuit: $circuit_ty:ident, // circuit type
		params3_fn: $params3_fn:ident,
		params5_fn: $params5_fn:ident,
		leaf_setup_fn: $leaf_setup_fn:ident,
		tree_setup_fn: $tree_setup_fn:ident
	) => {
		paste! {
					#[allow(clippy::too_many_arguments)]
					pub fn [<setup_ $circuit_ty:lower>]<R: Rng, F: PrimeField, const N: usize,
		const M: usize>( 				chain_id: F,
						leaves: &[F],
						index: u64,
						roots: &[F], // only first M - 1 member will be used
						recipient: F,
						relayer: F,
						fee: F,
						refund: F,
						commitment: F,
						rng: &mut R,
						curve: Curve,
					) -> ($circuit_ty<F, N, M>, F, F, F, Vec<F>) {
						let params3 = $params3_fn::<F>(curve);
						let params5 = $params5_fn::<F>(curve);

						let arbitrary_input = setup_arbitrary_data(recipient, relayer, fee, refund,
		commitment); 				let (leaf_private, leaf_public, leaf, nullifier_hash) =
		$leaf_setup_fn(chain_id, &params5, rng); 				let mut leaves_new =
		leaves.to_vec(); 				leaves_new.push(leaf);
						let (tree, path) = $tree_setup_fn(&leaves_new, index, &params3);
						let root = tree.root().inner();
						let mut roots_new: [F; M] = [F::default(); M];
						roots_new[0] = root;
						let size_to_copy = if roots.len() > (M - 1) {
							M - 1
						} else {
							roots.len()
						};
						for i in 0..size_to_copy {
							roots_new[i + 1] = roots[i];
						}
						let set_private_inputs = setup_set(&root, &roots_new);

						let mc = $circuit_ty::new(
							arbitrary_input.clone(),
							leaf_private,
							leaf_public,
							set_private_inputs,
							roots_new,
							params5,
							path,
							root.clone(),
							nullifier_hash,
						);
						let public_inputs = get_public_inputs(
							chain_id,
							nullifier_hash,
							roots_new,
							root,
							recipient,
							relayer,
							fee,
							refund,
							commitment,
						);
						(mc, leaf, nullifier_hash, root, public_inputs)
					}

					pub fn [<setup_random_ $circuit_ty:lower>]<R: Rng, F: PrimeField, const N:
		usize, const M: usize>( 				rng: &mut R,
						curve: Curve,
					) -> ($circuit_ty<F, N, M>, F, F, F, Vec<F>) {
						let chain_id = F::rand(rng);
						let leaves = Vec::new();
						let index = 0;
						let roots = Vec::new();
						let recipient = F::rand(rng);
						let relayer = F::rand(rng);
						let fee = F::rand(rng);
						let refund = F::rand(rng);
						let commitment = F::rand(rng);
						[<setup_ $circuit_ty:lower>]::<R, F, N, M>(
							chain_id, &leaves, index, &roots, recipient, relayer, fee, refund,
		commitment, rng, curve, 				)
					}
				}
	};
}

impl_setup_bridge_circuit!(
	circuit: Circuit_x5,
	params3_fn: setup_params_x5_3,
	params5_fn: setup_params_x5_5,
	leaf_setup_fn: setup_leaf_x5,
	tree_setup_fn: setup_tree_and_create_path_tree_x5
);
impl_setup_bridge_circuit!(
	circuit: Circuit_x17,
	params3_fn: setup_params_x17_3,
	params5_fn: setup_params_x17_5,
	leaf_setup_fn: setup_leaf_x17,
	tree_setup_fn: setup_tree_and_create_path_tree_x17
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
						const M: usize,
					>(
						pk: &ProvingKey<E>,
						c: $circuit_ty<E::Fr, N, M>,
						rng: &mut R,
					) -> Proof<E> {
						Groth16::<E>::prove(pk, c, rng).unwrap()
						}

					pub fn [<setup_groth16_ $circuit_ty:lower>]<
						R: RngCore + CryptoRng,
						E: PairingEngine,
						const N: usize,
						const M: usize,
					>(
						rng: &mut R,
						c: $circuit_ty<E::Fr, N, M>,
					) -> (ProvingKey<E>, VerifyingKey<E>) {
						let (pk, vk) = Groth16::<E>::circuit_specific_setup(c, rng).unwrap();
						(pk, vk)
						}

					pub fn [<setup_groth16_random_ $circuit_ty:lower>]<
						R: RngCore + CryptoRng,
						E: PairingEngine,
						const N: usize,
						const M: usize,
					>(
						rng: &mut R,
						curve: Curve,
					) -> (ProvingKey<E>, VerifyingKey<E>) {
						let (circuit, ..) = [<setup_random_ $circuit_ty:lower>]::<R, E::Fr, N,
		M>(rng, curve); 				let (pk, vk) =
		Groth16::<E>::circuit_specific_setup(circuit.clone(), rng).unwrap(); 				(pk, vk)
					}
				}
	};
}

impl_groth16_api_wrappers!(circuit: Circuit_x5);
impl_groth16_api_wrappers!(circuit: Circuit_x17);
#[cfg(test)]
mod test {
	use super::*;
	use ark_bls12_381::{Bls12_381, Fr as Bls381};
	use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
	use ark_std::test_rng;
	use arkworks_utils::utils::common::{setup_params_x5_3, setup_params_x5_5, verify_groth16};

	// merkle proof path legth
	// TreeConfig_x5, x7 HEIGHT is hardcoded to 30
	pub const TEST_N: usize = 30;

	pub const TEST_M: usize = 2;

	fn add_members_mock(_leaves: Vec<Bls381>) {}

	fn verify_zk_mock(
		_root: Bls381,
		_private_inputs: Vec<Bls381>,
		_nullifier_hash: Bls381,
		_proof_bytes: Vec<u8>,
		_path_index_commitments: Vec<Bls381>,
		_path_node_commitments: Vec<Bls381>,
		_recipient: Bls381,
		_relayer: Bls381,
	) {
	}

	#[test]
	fn should_create_setup() {
		let mut rng = test_rng();
		let curve = Curve::Bls381;
		let chain_id = Bls381::from(0u8);
		let recipient = Bls381::from(0u8);
		let relayer = Bls381::from(0u8);
		let fee = Bls381::from(0u8);
		let refund = Bls381::from(0u8);
		let commitment = Bls381::from(0u8);

		let leaves = Vec::new();
		let roots = [Bls381::default(); TEST_M];

		let (circuit, leaf, nullifier, root, public_inputs) =
			setup_circuit_x5::<_, Bls381, TEST_N, TEST_M>(
				chain_id, &leaves, 0, &roots, recipient, relayer, fee, refund, commitment,
				&mut rng, curve,
			);

		add_members_mock(vec![leaf]);

		// let (pk, vk) = setup_circuit_groth16(&mut rng, circuit.clone());
		let (pk, vk) =
			Groth16::<Bls12_381>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();
		// let (pk, vk) = setup_groth16_random_circuit_x5::<_,Bls12_381, TEST_N,
		// TEST_M>(&mut rng, curve);
		let proof = prove_groth16_circuit_x5(&pk, circuit, &mut rng);
		let res = verify_groth16(&vk, &public_inputs, &proof);

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
		let chain_id = Bls381::from(0u8);
		let recipient = Bls381::from(0u8);
		let relayer = Bls381::from(0u8);
		let fee = Bls381::from(0u8);
		let refund = Bls381::from(0u8);
		let commitment = Bls381::from(0u8);
		let leaves = Vec::new();
		let mut roots = [Bls381::default(); TEST_M];

		let params3 = setup_params_x5_3::<Bls381>(curve);
		let params5 = setup_params_x5_5::<Bls381>(curve);

		let arbitrary_input =
			setup_arbitrary_data::<Bls381>(recipient, relayer, fee, refund, commitment);
		let (leaf_private, leaf_public, leaf, nullifier_hash) =
			setup_leaf_x5::<_, Bls381>(chain_id, &params5, &mut rng);
		let mut leaves_new = leaves.to_vec();
		leaves_new.push(leaf);
		let (tree, path) =
			setup_tree_and_create_path_tree_x5::<Bls381, TEST_N>(&leaves_new, 0, &params3);
		let root = tree.root().inner();
		roots[0] = root;
		let set_private_inputs = setup_set::<Bls381, TEST_M>(&root, &roots);

		let mc = Circuit_x5::<Bls381, TEST_N, TEST_M>::new(
			arbitrary_input,
			leaf_private,
			leaf_public,
			set_private_inputs,
			roots,
			params5,
			path,
			root,
			nullifier_hash,
		);
		let public_inputs = get_public_inputs::<Bls381, TEST_M>(
			chain_id,
			nullifier_hash,
			roots,
			root,
			recipient,
			relayer,
			fee,
			refund,
			commitment,
		);

		add_members_mock(vec![leaf]);

		// let (pk, vk) = setup_groth16_random(&mut rng, circuit.clone());
		let (pk, vk) =
			setup_groth16_random_circuit_x5::<_, Bls12_381, TEST_N, TEST_M>(&mut rng, curve);
		let proof = prove_groth16_circuit_x5(&pk, mc, &mut rng);
		let res = verify_groth16(&vk, &public_inputs, &proof);

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
		let chain_id = Bls381::from(0u8);
		let recipient = Bls381::from(0u8);
		let relayer = Bls381::from(0u8);
		let fee = Bls381::from(0u8);
		let commitment = Bls381::from(0u8);
		let refund = Bls381::from(0u8);
		let leaves = Vec::new();
		let roots = [Bls381::default(); TEST_M];

		let (circuit, leaf, nullifier, root, public_inputs) =
			setup_circuit_x5::<_, Bls381, TEST_N, TEST_M>(
				chain_id, &leaves, 0, &roots, recipient, relayer, fee, refund, commitment,
				&mut rng, curve,
			);

		add_members_mock(vec![leaf]);

		// let (pk, vk) = setup_groth16(&mut rng, circuit.clone());
		let (pk, vk) =
			setup_groth16_random_circuit_x5::<_, Bls12_381, TEST_N, TEST_M>(&mut rng, curve);
		let proof =
			prove_groth16_circuit_x5::<_, Bls12_381, TEST_N, TEST_M>(&pk, circuit, &mut rng);
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
}
