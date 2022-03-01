#[cfg(test)]
mod tests;
use ark_std::UniformRand;
use crate::{common::*, AnchorProver};
use arkworks_circuits::circuit::anchor::AnchorCircuit;
use ark_crypto_primitives::{Error};
use ark_ec::PairingEngine;
use ark_ff::{BigInteger, PrimeField};
use ark_std::Zero;
use ark_std::{
	marker::PhantomData,
	rand::{CryptoRng, Rng, RngCore},
	rc::Rc,
	vec::Vec,
};
use arkworks_gadgets::{
	arbitrary::anchor_data::Input as AnchorDataInput,
	leaf::anchor::{
		Private, Public,
	},
	merkle_tree::{simple_merkle::Path}, poseidon::{field_hasher_constraints::{PoseidonGadget, FieldHasherGadget}, field_hasher::Poseidon},
};
use arkworks_utils::{
	utils::common::{setup_params_x5_3, setup_params_x5_4, Curve},
};

use super::{SMT, create_merkle_tree};

pub type AnchorConstraintDataInput<F> = AnchorDataInput<F>;
pub type PoseidonAnchorCircuit<F, const N: usize, const M: usize> = AnchorCircuit<
	F,
	PoseidonGadget<F>,
	PoseidonGadget<F>,
	N,
	M,
>;

struct AnchorR1CSProver<E: PairingEngine, HG: FieldHasherGadget<E::Fr>, LHG: FieldHasherGadget<E::Fr>, const HEIGHT: usize, const ANCHOR_CT: usize> {
	engine: PhantomData<E>,
	tree_hasher: HG::Native,
	leaf_hasher: LHG::Native,
	default_leaf: [u8; 32],
}

impl<E: PairingEngine, HG: FieldHasherGadget<E::Fr>, LHG: FieldHasherGadget<E::Fr>, const HEIGHT: usize, const ANCHOR_CT: usize>
	AnchorR1CSProver<E, HG, LHG, HEIGHT, ANCHOR_CT>
{
	pub fn setup_tree_and_create_path(
		&self,
		leaves: &[E::Fr],
		index: u64,
	) -> Result<
		(
			SMT<E::Fr, HG::Native, HEIGHT>,
			Path<E::Fr, HG::Native, HEIGHT>,
		),
		Error,
	> {
		// Making the merkle tree
		let smt = create_merkle_tree::<E::Fr, HG::Native, HEIGHT>(
			self.tree_hasher.clone(),
			leaves,
			&self.default_leaf,
		);
		// Getting the proof path
		let path = smt.generate_membership_proof(index);
		Ok((smt, path))
	}

	#[allow(clippy::too_many_arguments)]
	pub fn construct_public_inputs(
		chain_id: E::Fr,
		nullifier_hash: E::Fr,
		roots: [E::Fr; ANCHOR_CT],
		recipient: E::Fr,
		relayer: E::Fr,
		fee: E::Fr,
		refund: E::Fr,
		commitment: E::Fr,
	) -> Vec<E::Fr> {
		let mut pub_ins = vec![chain_id, nullifier_hash];
		pub_ins.extend(roots.to_vec());
		pub_ins.extend(vec![recipient, relayer, fee, refund, commitment]);
		pub_ins
	}

	pub fn setup_arbitrary_data(
		recipient: E::Fr,
		relayer: E::Fr,
		fee: E::Fr,
		refund: E::Fr,
		commitment: E::Fr,
	) -> AnchorConstraintDataInput<E::Fr> {
		AnchorConstraintDataInput::new(recipient, relayer, fee, refund, commitment)
	}

	pub fn setup_random_circuit<R: CryptoRng + RngCore>(
		self,
		rng: &mut R,
	) -> Result<
		(
			AnchorCircuit<E::Fr, HG, LHG, HEIGHT, ANCHOR_CT>,
			E::Fr,
			E::Fr,
			Vec<E::Fr>,
			Vec<E::Fr>,
		),
		Error,
	> {
		let recipient = E::Fr::rand(rng);
		let relayer = E::Fr::rand(rng);
		let fee = E::Fr::rand(rng);
		let refund = E::Fr::rand(rng);
		let commitment = E::Fr::rand(rng);
		// Create the arbitrary input data
		let arbitrary_input = AnchorConstraintDataInput::<E::Fr> {
			recipient,
			relayer,
			fee,
			refund,
			commitment,
		};
		// Create random chain_id public input
		let chain_id = 1u64.into();
		let chain_id_f = E::Fr::from(chain_id);
		// Generate the leaf
		let leaf = self.create_leaf_with_privates(chain_id, None, None, rng)?;
		let leaf_value = E::Fr::from_le_bytes_mod_order(&leaf.leaf_bytes);
		let leaf_public = Public::new(chain_id_f);
		let leaf_private = Private::new(
			E::Fr::from_le_bytes_mod_order(&leaf.secret_bytes),
			E::Fr::from_le_bytes_mod_order(&leaf.nullifier_bytes),
		);
		let nullifier_hash = E::Fr::from_le_bytes_mod_order(&leaf.nullifier_hash_bytes);
		let leaves = vec![E::Fr::from_le_bytes_mod_order(&leaf.leaf_bytes)];
		let (tree, path) = self.setup_tree_and_create_path(&leaves, 0)?;
		let mut root_set = [E::Fr::rand(rng); ANCHOR_CT];
		root_set[0] = tree.root();

		let mc = AnchorCircuit::new(
			arbitrary_input,
			leaf_private,
			leaf_public,
			root_set,
			path,
			nullifier_hash,
			self.tree_hasher,
			self.leaf_hasher,
		);
		let public_inputs =
			Self::construct_public_inputs(chain_id_f, nullifier_hash, root_set, recipient, relayer, fee, refund, commitment);

		Ok((mc, leaf_value, nullifier_hash, root_set.to_vec(), public_inputs))
	}

	pub fn setup_circuit_with_privates(
		self,
		chain_id: E::Fr,
		secret: E::Fr,
		nullifier: E::Fr,
		leaves: &[E::Fr],
		index: u64,
		roots: [E::Fr; ANCHOR_CT],
		recipient: E::Fr,
		relayer: E::Fr,
		fee: E::Fr,
		refund: E::Fr,
		commitment: E::Fr,
	) -> Result<(AnchorCircuit<E::Fr, HG, LHG, HEIGHT, ANCHOR_CT>, E::Fr, E::Fr, Vec<E::Fr>, Vec<E::Fr>), Error> {
		use arkworks_gadgets::leaf::anchor;
		let arbitrary_input = Self::setup_arbitrary_data(recipient, relayer, fee, refund, commitment);
		let leaf_public = Public::new(chain_id);
		let leaf_private: Private<E::Fr> = Private::new(secret, nullifier);
		let leaf = anchor::AnchorLeaf::<E::Fr, LHG::Native>::create_leaf(&leaf_private, &leaf_public, &self.leaf_hasher)?;
		let nullifier_hash = anchor::AnchorLeaf::<E::Fr, HG::Native>::create_nullifier(&leaf_private, &self.tree_hasher)?;
		let (_, path) = self.setup_tree_and_create_path(&leaves, index)?;

		let mc = AnchorCircuit::new(
			arbitrary_input,
			leaf_private,
			leaf_public,
			roots,
			path,
			nullifier_hash,
			self.tree_hasher,
			self.leaf_hasher,
		);
		let public_inputs = Self::construct_public_inputs(chain_id, nullifier_hash, roots, recipient, relayer, fee, refund, commitment);
		Ok((mc, leaf, nullifier_hash, roots.to_vec(), public_inputs))
	}

	#[allow(clippy::too_many_arguments)]
	pub fn setup_circuit_with_privates_raw(
		self,
		chain_id: u64,
		secret: Vec<u8>,
		nullifier: Vec<u8>,
		leaves: &[Vec<u8>],
		index: u64,
		roots: [Vec<u8>; ANCHOR_CT],
		recipient: Vec<u8>,
		relayer: Vec<u8>,
		fee: u128,
		refund: u128,
		commitment: Vec<u8>,
	) -> Result<(AnchorCircuit<E::Fr, HG, LHG, HEIGHT, ANCHOR_CT>, Vec<u8>, Vec<u8>, Vec<Vec<u8>>, Vec<Vec<u8>>), Error> {
		let chain_id_f = E::Fr::from_le_bytes_mod_order(&chain_id.to_be_bytes());
		let secret_f = E::Fr::from_le_bytes_mod_order(&secret);
		let nullifier_f = E::Fr::from_le_bytes_mod_order(&nullifier);
		let leaves_f: Vec<E::Fr> = leaves
			.iter()
			.map(|x| E::Fr::from_le_bytes_mod_order(x))
			.collect();
		let recipient_f = E::Fr::from_le_bytes_mod_order(&recipient);
		let relayer_f = E::Fr::from_le_bytes_mod_order(&relayer);
		let fee_f = E::Fr::from(fee);
		let refund_f = E::Fr::from(refund);
		let commitment_f = E::Fr::from_le_bytes_mod_order(&commitment);
		let roots_set: [E::Fr; ANCHOR_CT] = roots
			.iter()
			.map(|x| E::Fr::from_le_bytes_mod_order(x))
			.collect::<Vec<E::Fr>>().try_into().unwrap_or([E::Fr::zero(); ANCHOR_CT]);

		let (mc, leaf, nullifier_hash, roots, public_inputs) = self.setup_circuit_with_privates(
			chain_id_f,
			secret_f,
			nullifier_f,
			&leaves_f,
			index,
			roots_set,
			recipient_f,
			relayer_f,
			fee_f,
			refund_f,
			commitment_f,
		)?;

		let leaf_raw = leaf.into_repr().to_bytes_le();
		let nullifier_hash_raw = nullifier_hash.into_repr().to_bytes_le();
		let roots_raw = roots.iter().map(|v| v.into_repr().to_bytes_le()).collect();
		let public_inputs_raw: Vec<Vec<u8>> = public_inputs
			.iter()
			.map(|x| x.into_repr().to_bytes_le())
			.collect();

		Ok((
			mc,
			leaf_raw,
			nullifier_hash_raw,
			roots_raw,
			public_inputs_raw,
		))
	}

	pub fn create_circuit(
		self,
		arbitrary_input: AnchorConstraintDataInput<E::Fr>,
		leaf_private: Private<E::Fr>,
		leaf_public: Public<E::Fr>,
		path: Path<E::Fr, HG::Native, HEIGHT>,
		root_set: [E::Fr; ANCHOR_CT],
		nullifier_hash: E::Fr,
	) -> AnchorCircuit<E::Fr, HG, LHG, HEIGHT, ANCHOR_CT> {
		let mc = AnchorCircuit::new(
			arbitrary_input,
			leaf_private,
			leaf_public,
			root_set,
			path,
			nullifier_hash,
			self.tree_hasher,
			self.leaf_hasher,
		);
		mc
	}
}

impl<E: PairingEngine, HG: FieldHasherGadget<E::Fr>, LHG: FieldHasherGadget<E::Fr>, const HEIGHT: usize, const ANCHOR_CT: usize> AnchorProver<E, HG, LHG, HEIGHT, ANCHOR_CT>
	for AnchorR1CSProver<E, HG, LHG, HEIGHT, ANCHOR_CT>
{
	fn create_leaf_with_privates<R: RngCore + CryptoRng>(
		&self,
		chain_id: u64,
		secret: Option<Vec<u8>>,
		nullifier: Option<Vec<u8>>,
		rng: &mut R,
	) -> Result<AnchorLeaf, Error> {
		use arkworks_gadgets::leaf::anchor;
		let secret_field_elt: E::Fr = match secret {
			Some(secret) => E::Fr::from_le_bytes_mod_order(&secret),
			None => E::Fr::rand(rng),
		};
		let nullifier_field_elt: E::Fr = match nullifier {
			Some(nullifier) => E::Fr::from_le_bytes_mod_order(&nullifier),
			None => E::Fr::rand(rng),
		};
		// We big-endian encode the chain ID when we pass it into the field elements
		let chain_id_elt = E::Fr::from_le_bytes_mod_order(&chain_id.to_be_bytes());
		let public = Public::new(chain_id_elt);
		let private: Private<E::Fr> = Private::new(secret_field_elt, nullifier_field_elt);
		let leaf_field_element = anchor::AnchorLeaf::create_leaf(&private, &public, &self.leaf_hasher)?;
		let nullifier_hash_field_element = anchor::AnchorLeaf::create_nullifier(&private, &self.tree_hasher)?;
		Ok(AnchorLeaf {
			chain_id_bytes: chain_id.to_be_bytes().to_vec(),
			secret_bytes: secret_field_elt.into_repr().to_bytes_le(),
			nullifier_bytes: nullifier_field_elt.into_repr().to_bytes_le(),
			leaf_bytes: leaf_field_element.into_repr().to_bytes_le(),
			nullifier_hash_bytes: nullifier_hash_field_element.into_repr().to_bytes_le(),
		})
	}

	fn create_proof<R: RngCore + CryptoRng>(
		&self,
		chain_id: u64,
		secret: Vec<u8>,
		nullifier: Vec<u8>,
		leaves: Vec<Vec<u8>>,
		index: u64,
		recipient: Vec<u8>,
		relayer: Vec<u8>,
		fee: u128,
		refund: u128,
		commitment: Vec<u8>,
		pk: Vec<u8>,
		rng: &mut R,
	) -> Result<AnchorProof, Error> {
		// Get field element version of all the data
		let secret_f = E::Fr::from_le_bytes_mod_order(&secret);
		let nullifier_f = E::Fr::from_le_bytes_mod_order(&nullifier);
		let leaves_f: Vec<E::Fr> = leaves
			.iter()
			.map(|x| E::Fr::from_le_bytes_mod_order(x))
			.collect();
		let recipient_f = E::Fr::from_le_bytes_mod_order(&recipient);
		let relayer_f = E::Fr::from_le_bytes_mod_order(&relayer);
		let fee_f = E::Fr::from(fee);
		let refund_f = E::Fr::from(refund);
		let commitment_f = E::Fr::from_le_bytes_mod_order(&commitment);
		// Create the arbitrary input data
		let arbitrary_input =
			Self::setup_arbitrary_data(recipient_f, relayer_f, fee_f, refund_f, commitment_f);
		// Generate the leaf
		let AnchorLeaf {
			leaf_bytes,
			nullifier_hash_bytes,
			..
		} = self.create_leaf_with_privates(chain_id, Some(secret), Some(nullifier), rng)?;
		// Setup the tree and generate the path
		let (tree, path) = self.setup_tree_and_create_path(&leaves_f, index)?;
		let mut root_set = [E::Fr::zero(); ANCHOR_CT];
		root_set[0] = tree.root();

		let chain_id_f = E::Fr::from_le_bytes_mod_order(&chain_id.to_be_bytes());
		let leaf_public = Public::new(chain_id_f);
		let leaf_private = Private::new(secret_f, nullifier_f);
		let mc = AnchorCircuit::<E::Fr, HG, LHG, HEIGHT, ANCHOR_CT>::new(
			arbitrary_input,
			leaf_private,
			leaf_public,
			root_set,
			path,
			nullifier_f,
			self.tree_hasher.clone(),
			self.leaf_hasher.clone(),
		);
		let public_inputs =
			Self::construct_public_inputs(chain_id_f, nullifier_f, root_set, recipient_f, relayer_f, fee_f, refund_f, commitment_f);

		let leaf_raw = leaf_bytes;
		let nullifier_hash_raw = nullifier_hash_bytes;
		let roots_raw = root_set.iter().map(|v| v.into_repr().to_bytes_le()).collect();
		let public_inputs_raw: Vec<Vec<u8>> = public_inputs
			.iter()
			.map(|x| x.into_repr().to_bytes_le())
			.collect();

		let proof = prove_unchecked::<E, _, _>(mc, &pk, rng)?;

		Ok(AnchorProof {
			leaf_raw,
			nullifier_hash_raw,
			roots_raw,
			public_inputs_raw,
			proof,
		})
	}
}
