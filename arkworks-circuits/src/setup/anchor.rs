use super::common::*;
use crate::circuit::anchor::AnchorCircuit;
use ark_crypto_primitives::Error;
use ark_ec::PairingEngine;
use ark_ff::{BigInteger, PrimeField};
use ark_std::{
	rand::{CryptoRng, Rng, RngCore},
	rc::Rc,
	vec::Vec,
};
use arkworks_gadgets::{
	arbitrary::anchor_data::Input as AnchorDataInput,
	leaf::anchor::{
		constraints::AnchorLeafGadget, AnchorLeaf, Private as LeafPrivate, Public as LeafPublic,
	},
	merkle_tree::Path,
	set::membership::{
		constraints::SetMembershipGadget, Private as SetMembershipPrivate, SetMembership,
	},
};
use arkworks_utils::{
	poseidon::PoseidonParameters,
	utils::common::{setup_params_x5_3, setup_params_x5_4, Curve},
};

pub type AnchorConstraintDataInput<F> = AnchorDataInput<F>;

pub type Leaf_x5<F> = AnchorLeaf<F, PoseidonCRH_x5_4<F>>;

pub type LeafGadget_x5<F> = AnchorLeafGadget<F, PoseidonCRH_x5_4<F>, PoseidonCRH_x5_4Gadget<F>>;

pub type TestSetMembership<F, const M: usize> = SetMembership<F, M>;
pub type TestSetMembershipGadget<F, const M: usize> = SetMembershipGadget<F, M>;

pub type Circuit_x5<F, const N: usize, const M: usize> = AnchorCircuit<
	F,
	PoseidonCRH_x5_4<F>,
	PoseidonCRH_x5_4Gadget<F>,
	TreeConfig_x5<F>,
	LeafCRHGadget<F>,
	PoseidonCRH_x5_3Gadget<F>,
	N,
	M,
>;

pub type Leaf_x17<F> = AnchorLeaf<F, PoseidonCRH_x17_5<F>>;
pub type LeafGadget_x17<F> = AnchorLeafGadget<F, PoseidonCRH_x17_5<F>, PoseidonCRH_x17_5Gadget<F>>;

pub type Circuit_x17<F, const N: usize, const M: usize> = AnchorCircuit<
	F,
	PoseidonCRH_x17_5<F>,
	PoseidonCRH_x17_5Gadget<F>,
	TreeConfig_x17<F>,
	LeafCRHGadget<F>,
	PoseidonCRH_x17_3Gadget<F>,
	N,
	M,
>;

pub fn setup_leaf_x5_4<F: PrimeField, R: RngCore>(
	curve: Curve,
	chain_id_bytes: Vec<u8>,
	rng: &mut R,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>), Error> {
	let params5 = setup_params_x5_4::<F>(curve);
	// Secret inputs for the leaf
	let leaf_private = LeafPrivate::generate(rng);

	let chain_id = F::from_le_bytes_mod_order(&chain_id_bytes);
	let leaf_public = LeafPublic::new(chain_id);

	let leaf_hash = Leaf_x5::create_leaf(&leaf_private, &leaf_public, &params5)?;
	let nullifier_hash = Leaf_x5::create_nullifier(&leaf_private, &params5)?;

	let secret_bytes = leaf_private.secret().into_repr().to_bytes_le();
	let nullifier_bytes = leaf_private.nullifier().into_repr().to_bytes_le();

	let leaf_bytes = leaf_hash.into_repr().to_bytes_le();
	let nullifier_hash_bytes = nullifier_hash.into_repr().to_bytes_le();

	Ok((
		secret_bytes,
		nullifier_bytes,
		leaf_bytes,
		nullifier_hash_bytes,
	))
}

pub fn setup_leaf_with_privates_raw_x5_4<F: PrimeField>(
	curve: Curve,
	secret_bytes: Vec<u8>,
	nullfier_bytes: Vec<u8>,
	chain_id_bytes: Vec<u8>,
) -> Result<(Vec<u8>, Vec<u8>), Error> {
	let params5 = setup_params_x5_4::<F>(curve);

	let secret = F::from_le_bytes_mod_order(&secret_bytes);
	let nullifier = F::from_le_bytes_mod_order(&nullfier_bytes);
	// Secret inputs for the leaf
	let leaf_private = LeafPrivate::new(secret, nullifier);

	let chain_id = F::from_le_bytes_mod_order(&chain_id_bytes);
	let leaf_public = LeafPublic::new(chain_id);

	let leaf_hash = Leaf_x5::create_leaf(&leaf_private, &leaf_public, &params5)?;
	let nullifier_hash = Leaf_x5::create_nullifier(&leaf_private, &params5)?;

	let leaf_bytes = leaf_hash.into_repr().to_bytes_le();
	let nullifier_hash_bytes = nullifier_hash.into_repr().to_bytes_le();

	Ok((leaf_bytes, nullifier_hash_bytes))
}

pub const N: usize = 30;
pub const M: usize = 2;
type AnchorProverSetupBn254_30<F> = AnchorProverSetup<F, N, M>;

pub fn setup_proof_x5_4<E: PairingEngine, R: RngCore + CryptoRng>(
	curve: Curve,
	chain_id: Vec<u8>,
	secret_raw: Vec<u8>,
	nullifier_raw: Vec<u8>,
	leaves_raw: Vec<Vec<u8>>,
	index: u64,
	roots: Vec<Vec<u8>>,
	recipient_raw: Vec<u8>,
	relayer_raw: Vec<u8>,
	commitment_raw: Vec<u8>,
	fee: u128,
	refund: u128,
	pk: Vec<u8>,
	rng: &mut R,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<Vec<u8>>), Error> {
	let params3 = setup_params_x5_3::<E::Fr>(curve);
	let params4 = setup_params_x5_4::<E::Fr>(curve);
	let prover = AnchorProverSetupBn254_30::new(params3, params4);

	let (circuit, leaf_raw, nullifier_hash_raw, root_raw, public_inputs_raw) = prover
		.setup_circuit_with_privates_raw(
			chain_id,
			secret_raw,
			nullifier_raw,
			leaves_raw,
			index,
			roots,
			recipient_raw,
			relayer_raw,
			commitment_raw,
			fee,
			refund,
		)?;

	let proof = prove_unchecked::<E, _, _>(circuit, &pk, rng)?;

	Ok((
		proof,
		leaf_raw,
		nullifier_hash_raw,
		root_raw,
		public_inputs_raw,
	))
}

pub fn setup_keys_x5_4<E: PairingEngine, R: RngCore + CryptoRng>(
	curve: Curve,
	rng: &mut R,
) -> Result<(Vec<u8>, Vec<u8>), Error> {
	let params3 = setup_params_x5_3::<E::Fr>(curve);
	let params5 = setup_params_x5_4::<E::Fr>(curve);
	let prover = AnchorProverSetupBn254_30::new(params3, params5);

	let (circuit, ..) = prover.setup_random_circuit(rng)?;

	let (pk, vk) = setup_keys_unchecked::<E, _, _>(circuit, rng)?;

	Ok((pk, vk))
}

pub struct AnchorProverSetup<F: PrimeField, const M: usize, const N: usize> {
	params3: PoseidonParameters<F>,
	params4: PoseidonParameters<F>,
}

impl<F: PrimeField, const N: usize, const M: usize> AnchorProverSetup<F, M, N> {
	pub fn new(params3: PoseidonParameters<F>, params4: PoseidonParameters<F>) -> Self {
		Self { params3, params4 }
	}

	pub fn setup_set(root: &F, roots: &[F; M]) -> Result<SetMembershipPrivate<F, M>, Error> {
		TestSetMembership::generate_secrets(root, roots)
	}

	pub fn setup_arbitrary_data(
		recipient: F,
		relayer: F,
		fee: F,
		refund: F,
		commitment: F,
	) -> AnchorConstraintDataInput<F> {
		AnchorConstraintDataInput::new(recipient, relayer, fee, refund, commitment)
	}

	#[allow(clippy::too_many_arguments)]
	pub fn construct_public_inputs(
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
		let mut pub_ins = vec![chain_id, nullifier_hash];
		pub_ins.extend(roots.to_vec());
		pub_ins.extend(vec![root, recipient, relayer, fee, refund, commitment]);

		pub_ins
	}

	#[allow(clippy::too_many_arguments)]
	pub fn deconstruct_public_inputs(
		public_inputs: &[F],
	) -> (
		F,      // Chain id
		F,      // Nullifier Hash
		Vec<F>, // Roots
		F,      // Root
		F,      // Recipient
		F,      // Relayer
		F,      // Fee
		F,      // Refund
		F,      // Commitment
	) {
		let chain_id: F = public_inputs[0];
		let nullifier_hash = public_inputs[1];
		let offset = 2 + M;
		let roots = public_inputs[2..offset].to_vec();
		let root = public_inputs[offset + 1];
		let recipient = public_inputs[offset + 2];
		let relayer = public_inputs[offset + 3];
		let fee = public_inputs[offset + 4];
		let refund = public_inputs[offset + 5];
		let commitments = public_inputs[offset + 6];
		(
			chain_id,
			nullifier_hash,
			roots,
			root,
			recipient,
			relayer,
			fee,
			refund,
			commitments,
		)
	}

	pub fn setup_leaf<R: Rng>(
		&self,
		chain_id: F,
		rng: &mut R,
	) -> Result<(LeafPrivate<F>, LeafPublic<F>, F, F), Error> {
		// Secret inputs for the leaf
		let leaf_private = LeafPrivate::generate(rng);
		// Public inputs for the leaf
		let leaf_public = LeafPublic::new(chain_id);

		// Creating the leaf
		let leaf_hash = AnchorLeaf::<F, PoseidonCRH_x5_4<F>>::create_leaf(
			&leaf_private,
			&leaf_public,
			&self.params4,
		)?;
		let nullifier_hash =
			AnchorLeaf::<F, PoseidonCRH_x5_4<F>>::create_nullifier(&leaf_private, &self.params4)?;

		Ok((leaf_private, leaf_public, leaf_hash, nullifier_hash))
	}

	pub fn setup_leaf_with_privates(
		&self,
		chain_id: F,
		secret: F,
		nullfier: F,
	) -> Result<(LeafPrivate<F>, LeafPublic<F>, F, F), Error> {
		// Secret inputs for the leaf
		let leaf_private = LeafPrivate::new(secret, nullfier);
		let leaf_public = LeafPublic::new(chain_id);

		// Creating the leaf
		let leaf_hash = Leaf_x5::create_leaf(&leaf_private, &leaf_public, &self.params4)?;
		let nullifier_hash = Leaf_x5::create_nullifier(&leaf_private, &self.params4)?;

		Ok((leaf_private, leaf_public, leaf_hash, nullifier_hash))
	}

	#[allow(clippy::too_many_arguments)]
	pub fn setup_circuit<R: Rng>(
		self,
		chain_id: F,
		leaves: &[F],
		index: u64,
		roots: &[F], // only first M - 1 member will be used
		recipient: F,
		relayer: F,
		fee: F,
		refund: F,
		commitment: F,
		rng: &mut R,
	) -> Result<(Circuit_x5<F, N, M>, F, F, F, Vec<F>), Error> {
		let arbitrary_input =
			Self::setup_arbitrary_data(recipient, relayer, fee, refund, commitment);
		let (leaf_private, leaf_public, leaf, nullifier_hash) = self.setup_leaf(chain_id, rng)?;
		let mut leaves_new = leaves.to_vec();
		leaves_new.push(leaf);
		let (tree, path) = self.setup_tree_and_path(&leaves_new, index)?;
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
		let set_private_inputs = Self::setup_set(&root, &roots_new)?;

		let mc = Circuit_x5::new(
			arbitrary_input.clone(),
			leaf_private,
			leaf_public,
			set_private_inputs,
			roots_new,
			self.params4,
			path,
			root.clone(),
			nullifier_hash,
		);

		let public_inputs = Self::construct_public_inputs(
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

		Ok((mc, leaf, nullifier_hash, root, public_inputs))
	}

	#[allow(clippy::too_many_arguments)]
	pub fn setup_circuit_with_privates(
		self,
		chain_id: F,
		secret: F,
		nullifier: F,
		leaves: &[F],
		index: u64,
		roots: &[F], // only first M - 1 member will be used
		recipient: F,
		relayer: F,
		fee: F,
		refund: F,
		commitment: F,
	) -> Result<(Circuit_x5<F, N, M>, F, F, F, Vec<F>), Error> {
		let arbitrary_input =
			Self::setup_arbitrary_data(recipient, relayer, fee, refund, commitment);
		let (leaf_private, leaf_public, leaf, nullifier_hash) =
			self.setup_leaf_with_privates(chain_id, secret, nullifier)?;
		let mut leaves_new = leaves.to_vec();
		leaves_new.push(leaf);
		let (tree, path) = self.setup_tree_and_path(&leaves_new, index)?;
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
		let set_private_inputs = Self::setup_set(&root, &roots_new)?;

		let mc = Circuit_x5::new(
			arbitrary_input.clone(),
			leaf_private,
			leaf_public,
			set_private_inputs,
			roots_new,
			self.params4,
			path,
			root.clone(),
			nullifier_hash,
		);

		let public_inputs = Self::construct_public_inputs(
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

		Ok((mc, leaf, nullifier_hash, root, public_inputs))
	}

	pub fn setup_random_circuit<R: Rng>(
		self,
		rng: &mut R,
	) -> Result<(Circuit_x5<F, N, M>, F, F, F, Vec<F>), Error> {
		let chain_id = F::rand(rng);

		let roots = Vec::new();
		let recipient = F::rand(rng);
		let relayer = F::rand(rng);
		let fee = F::rand(rng);
		let refund = F::rand(rng);
		let commitment = F::rand(rng);

		let (leaf_privates, leaf_public, leaf_hash, ..) = self.setup_leaf(chain_id, rng).unwrap();
		let secret = leaf_privates.secret();
		let nullifier = leaf_privates.nullifier();
		let leaves = vec![leaf_hash];
		let index = 0;

		self.setup_circuit_with_privates(
			chain_id,
			secret,
			nullifier,
			&leaves,
			index,
			&roots,
			recipient,
			relayer,
			fee,
			refund,
			commitment,
		)
	}

	pub fn setup_circuit_with_privates_raw(
		self,
		chain_id: Vec<u8>,
		secret: Vec<u8>,
		nullifier: Vec<u8>,
		leaves: Vec<Vec<u8>>,
		index: u64,
		roots: Vec<Vec<u8>>,
		recipient: Vec<u8>,
		relayer: Vec<u8>,
		commitment: Vec<u8>,
		fee: u128,
		refund: u128,
	) -> Result<(Circuit_x5<F, N, M>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<Vec<u8>>), Error> {
		let chain_id_f = F::from_le_bytes_mod_order(&chain_id);
		let secret_f = F::from_le_bytes_mod_order(&secret);
		let nullifier_f = F::from_le_bytes_mod_order(&nullifier);
		let leaves_f: Vec<F> = leaves
			.iter()
			.map(|x| F::from_le_bytes_mod_order(x))
			.collect();
		let roots_f: Vec<F> = roots
			.iter()
			.map(|x| F::from_le_bytes_mod_order(&x))
			.collect();
		let recipient_f = F::from_le_bytes_mod_order(&recipient);
		let relayer_f = F::from_le_bytes_mod_order(&relayer);
		let commitment_f = F::from_le_bytes_mod_order(&commitment);
		let fee_f = F::from(fee);
		let refund_f = F::from(refund);

		let (mc, leaf, nullifier_hash, root, public_inputs) = self.setup_circuit_with_privates(
			chain_id_f,
			secret_f,
			nullifier_f,
			&leaves_f,
			index,
			&roots_f,
			recipient_f,
			relayer_f,
			fee_f,
			refund_f,
			commitment_f,
		)?;

		let leaf_raw = leaf.into_repr().to_bytes_le();
		let nullifier_hash_raw = nullifier_hash.into_repr().to_bytes_le();
		let root_raw = root.into_repr().to_bytes_le();
		let public_inputs_raw: Vec<Vec<u8>> = public_inputs
			.iter()
			.map(|x| x.into_repr().to_bytes_le())
			.collect();

		Ok((
			mc,
			leaf_raw,
			nullifier_hash_raw,
			root_raw,
			public_inputs_raw,
		))
	}

	pub fn setup_tree(&self, leaves: &[F]) -> Result<Tree_x5<F>, Error> {
		let inner_params = Rc::new(self.params3.clone());
		let mt = Tree_x5::new_sequential(inner_params, Rc::new(()), leaves)?;
		Ok(mt)
	}

	pub fn setup_tree_and_path(
		&self,
		leaves: &[F],
		index: u64,
	) -> Result<(Tree_x5<F>, Path<TreeConfig_x5<F>, N>), Error> {
		// Making the merkle tree
		let mt = self.setup_tree(leaves)?;
		// Getting the proof path
		let path = mt.generate_membership_proof(index);

		Ok((mt, path))
	}
}
