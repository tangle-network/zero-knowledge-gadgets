use super::common::*;
use crate::{
	arbitrary::bridge_data::{constraints::BridgeDataGadget, BridgeData, Input as BridgeDataInput},
	circuit::bridge::BridgeCircuit,
	leaf::{
		bridge::{
			constraints::BridgeLeafGadget, BridgeLeaf, Private as LeafPrivate, Public as LeafPublic,
		},
		LeafCreation,
	},
	poseidon::PoseidonParameters,
	set::{
		membership::{constraints::SetMembershipGadget, SetMembership},
		Set,
	},
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

pub type BridgeConstraintData<F> = BridgeData<F>;
pub type BridgeConstraintDataInput<F> = BridgeDataInput<F>;
pub type BridgeConstraintDataGadget<F> = BridgeDataGadget<F>;

pub type Leaf_x5<F> = BridgeLeaf<F, PoseidonCRH_x5_5<F>>;

pub type LeafGadget_x5<F> =
	BridgeLeafGadget<F, PoseidonCRH_x5_5<F>, PoseidonCRH_x5_5Gadget<F>, Leaf_x5<F>>;

pub type TestSetMembership<F, const M: usize> = SetMembership<F, M>;
pub type TestSetMembershipGadget<F, const M: usize> = SetMembershipGadget<F, M>;

pub type Circuit_x5<F, const N: usize, const M: usize> = BridgeCircuit<
	F,
	BridgeConstraintData<F>,
	BridgeConstraintDataGadget<F>,
	PoseidonCRH_x5_5<F>,
	PoseidonCRH_x5_5Gadget<F>,
	TreeConfig_x5<F>,
	LeafCRHGadget<F>,
	PoseidonCRH_x5_3Gadget<F>,
	Leaf_x5<F>,
	LeafGadget_x5<F>,
	TestSetMembership<F, M>,
	TestSetMembershipGadget<F, M>,
	N,
	M,
>;

pub type Leaf_x17<F> = BridgeLeaf<F, PoseidonCRH_x17_5<F>>;
pub type LeafGadget_x17<F> =
	BridgeLeafGadget<F, PoseidonCRH_x17_5<F>, PoseidonCRH_x17_5Gadget<F>, Leaf_x17<F>>;

pub type Circuit_x17<F, const N: usize, const M: usize> = BridgeCircuit<
	F,
	BridgeConstraintData<F>,
	BridgeConstraintDataGadget<F>,
	PoseidonCRH_x17_5<F>,
	PoseidonCRH_x17_5Gadget<F>,
	TreeConfig_x17<F>,
	LeafCRHGadget<F>,
	PoseidonCRH_x17_3Gadget<F>,
	Leaf_x17<F>,
	LeafGadget_x17<F>,
	TestSetMembership<F, M>,
	TestSetMembershipGadget<F, M>,
	N,
	M,
>;

pub fn setup_set<F: PrimeField, const M: usize>(
	root: &F,
	roots: &[F; M],
) -> <TestSetMembership<F, M> as Set<F, M>>::Private {
	TestSetMembership::generate_secrets(root, roots).unwrap()
}

pub fn setup_arbitrary_data<F: PrimeField>(
	recipient: F,
	relayer: F,
	fee: F,
	refund: F,
) -> BridgeConstraintDataInput<F> {
	let arbitrary_input = BridgeConstraintDataInput::new(recipient, relayer, fee, refund);
	arbitrary_input
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
) -> Vec<F> {
	let mut public_inputs = Vec::new();
	public_inputs.push(chain_id);
	public_inputs.push(nullifier_hash);
	public_inputs.extend(&roots);
	public_inputs.push(root);
	public_inputs.push(recipient);
	public_inputs.push(relayer);
	public_inputs.push(fee);
	public_inputs.push(refund);
	public_inputs
}

macro_rules! impl_setup_bridge_leaf {
	(
		$leaf_ty:ident, $leaf_crh_ty:ident, $leaf_crh_param_ty:ident
	) => {
		paste! {
			pub fn [<setup_ $leaf_ty:lower>]<R: Rng, F: PrimeField>(
				chain_id: F,
				params: &$leaf_crh_param_ty<F>,
				rng: &mut R,
			) -> (
				LeafPrivate<F>,
				LeafPublic<F>,
				<$leaf_ty<F> as LeafCreation<$leaf_crh_ty<F>>>::Leaf,
				<$leaf_ty<F> as LeafCreation<$leaf_crh_ty<F>>>::Nullifier,
			) {
				// Secret inputs for the leaf
				let leaf_private = $leaf_ty::generate_secrets(rng).unwrap();
				// Public inputs for the leaf
				let leaf_public = LeafPublic::new(chain_id);

				// Creating the leaf
				let leaf = $leaf_ty::create_leaf(&leaf_private, &leaf_public, params).unwrap();
				let nullifier_hash = $leaf_ty::create_nullifier(&leaf_private, params).unwrap();
				(leaf_private, leaf_public, leaf, nullifier_hash)
			}
		}
	};
}

impl_setup_bridge_leaf!(Leaf_x5, PoseidonCRH_x5_5, PoseidonParameters);
impl_setup_bridge_leaf!(Leaf_x17, PoseidonCRH_x17_5, PoseidonParameters);

macro_rules! impl_setup_bridge_circuit {
	(
		$circuit_ty:ident,
		$param_3_fn:ident,
		$param_5_fn:ident,
		$setup_leaf_fn:ident,
		$tree_setup_fn:ident
	) => {
		paste! {
			pub fn [<setup_ $circuit_ty:lower>]<R: Rng, F: PrimeField, const N: usize, const M: usize>(
				chain_id: F,
				leaves: &[F],
				index: u64,
				roots: &[F], // only first M - 1 member will be used
				recipient: F,
				relayer: F,
				fee: F,
				refund: F,
				rng: &mut R,
				curve: Curve,
			) -> ($circuit_ty<F, N, M>, F, F, F, Vec<F>) {
				let params3 = $param_3_fn::<F>(curve);
				let params5 = $param_5_fn::<F>(curve);

				let arbitrary_input = setup_arbitrary_data(recipient, relayer, fee, refund);
				let (leaf_private, leaf_public, leaf, nullifier_hash) = $setup_leaf_fn(chain_id, &params5, rng);
				let mut leaves_new = leaves.to_vec();
				leaves_new.push(leaf);
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
				);
				(mc, leaf, nullifier_hash, root, public_inputs)
			}

			pub fn [<setup_random_ $circuit_ty:lower>]<R: Rng, F: PrimeField, const N: usize, const M: usize>(
				rng: &mut R,
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
				[<setup_ $circuit_ty:lower>]::<R, F, N, M>(
					chain_id, &leaves, index, &roots, recipient, relayer, fee, refund, rng, curve,
				)
			}
		}
	};
}

impl_setup_bridge_circuit!(
	Circuit_x5,
	setup_params_x5_3,
	setup_params_x5_5,
	setup_leaf_x5,
	setup_tree_and_create_path_tree_x5
);

impl_setup_bridge_circuit!(
	Circuit_x17,
	setup_params_x17_3,
	setup_params_x17_5,
	setup_leaf_x17,
	setup_tree_and_create_path_tree_x17
);

pub fn prove_groth16_x5<
	R: RngCore + CryptoRng,
	E: PairingEngine,
	const N: usize,
	const M: usize,
>(
	pk: &ProvingKey<E>,
	c: Circuit_x5<E::Fr, N, M>,
	rng: &mut R,
) -> Proof<E> {
	Groth16::<E>::prove(pk, c, rng).unwrap()
}

pub fn setup_groth16_x5<
	R: RngCore + CryptoRng,
	E: PairingEngine,
	const N: usize,
	const M: usize,
>(
	rng: &mut R,
	c: Circuit_x5<E::Fr, N, M>,
) -> (ProvingKey<E>, VerifyingKey<E>) {
	let (pk, vk) = Groth16::<E>::circuit_specific_setup(c, rng).unwrap();
	(pk, vk)
}

pub fn prove_groth16_x17<
	R: RngCore + CryptoRng,
	E: PairingEngine,
	const N: usize,
	const M: usize,
>(
	pk: &ProvingKey<E>,
	c: Circuit_x17<E::Fr, N, M>,
	rng: &mut R,
) -> Proof<E> {
	Groth16::<E>::prove(pk, c, rng).unwrap()
}

pub fn setup_groth16_x17<
	R: RngCore + CryptoRng,
	E: PairingEngine,
	const N: usize,
	const M: usize,
>(
	rng: &mut R,
	c: Circuit_x17<E::Fr, N, M>,
) -> (ProvingKey<E>, VerifyingKey<E>) {
	let (pk, vk) = Groth16::<E>::circuit_specific_setup(c, rng).unwrap();
	(pk, vk)
}

pub fn setup_random_groth16_x5<
	R: RngCore + CryptoRng,
	E: PairingEngine,
	const N: usize,
	const M: usize,
>(
	rng: &mut R,
	curve: Curve,
) -> (ProvingKey<E>, VerifyingKey<E>) {
	let (circuit, ..) = setup_random_circuit_x5::<R, E::Fr, N, M>(rng, curve);
	let (pk, vk) = Groth16::<E>::circuit_specific_setup(circuit.clone(), rng).unwrap();
	(pk, vk)
}

pub fn setup_random_groth16_x17<
	R: RngCore + CryptoRng,
	E: PairingEngine,
	const N: usize,
	const M: usize,
>(
	rng: &mut R,
	curve: Curve,
) -> (ProvingKey<E>, VerifyingKey<E>) {
	let (circuit, ..) = setup_random_circuit_x17::<R, E::Fr, N, M>(rng, curve);
	let (pk, vk) = Groth16::<E>::circuit_specific_setup(circuit.clone(), rng).unwrap();
	(pk, vk)
}

#[cfg(test)]
mod test {
	use super::*;
	use ark_bls12_381::{Bls12_381, Fr as Bls381};
	use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
	use ark_std::test_rng;

	// merkle proof path legth
	// TreeConfig_x5, x7 HEIGHT is hardcoded to 30
	pub const TEST_N: usize = 30;

	pub const TEST_M: usize = 10;

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
		let leaves = Vec::new();
		let mut roots = [Bls381::default(); TEST_M];

		let (circuit, leaf, nullifier, root, public_inputs) =
			setup_circuit_x5::<_, Bls381, TEST_N, TEST_M>(
				chain_id, &leaves, 0, &mut roots, recipient, relayer, fee, refund, &mut rng, curve,
			);

		add_members_mock(vec![leaf]);

		// let (pk, vk) = setup_circuit_groth16(&mut rng, circuit.clone());
		let (pk, vk) = setup_random_groth16_x5::<_, Bls12_381, TEST_N, TEST_M>(&mut rng, curve);
		let proof = prove_groth16_x5(&pk, circuit.clone(), &mut rng);
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
		let leaves = Vec::new();
		let mut roots = [Bls381::default(); TEST_M];

		let params3 = setup_params_x5_3::<Bls381>(curve);
		let params5 = setup_params_x5_5::<Bls381>(curve);

		let arbitrary_input = setup_arbitrary_data::<Bls381>(recipient, relayer, fee, refund);
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
			arbitrary_input.clone(),
			leaf_private,
			leaf_public,
			set_private_inputs,
			roots.clone(),
			params5,
			path,
			root.clone(),
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
		);

		add_members_mock(vec![leaf]);

		// let (pk, vk) = setup_random_groth16(&mut rng, circuit.clone());
		let (pk, vk) = setup_random_groth16_x5::<_, Bls12_381, TEST_N, TEST_M>(&mut rng, curve);
		let proof = prove_groth16_x5(&pk, mc.clone(), &mut rng);
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
		let refund = Bls381::from(0u8);
		let leaves = Vec::new();
		let mut roots = [Bls381::default(); TEST_M];

		let (circuit, leaf, nullifier, root, public_inputs) =
			setup_circuit_x5::<_, Bls381, TEST_N, TEST_M>(
				chain_id, &leaves, 0, &mut roots, recipient, relayer, fee, refund, &mut rng, curve,
			);

		add_members_mock(vec![leaf]);

		// let (pk, vk) = setup_groth16(&mut rng, circuit.clone());
		let (pk, vk) = setup_random_groth16_x5::<_, Bls12_381, TEST_N, TEST_M>(&mut rng, curve);
		let proof =
			prove_groth16_x5::<_, Bls12_381, TEST_N, TEST_M>(&pk, circuit.clone(), &mut rng);
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
