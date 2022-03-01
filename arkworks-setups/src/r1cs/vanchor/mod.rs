use crate::{common::*, AnchorProver};
use ark_crypto_primitives::Error;
use ark_ec::PairingEngine;
use ark_ff::{BigInteger, PrimeField};
use ark_std::{
	marker::PhantomData,
	rand::{CryptoRng, Rng, RngCore},
	rc::Rc,
	vec::Vec,
	UniformRand, Zero,
};
use arkworks_circuits::circuit::anchor::AnchorCircuit;
use arkworks_gadgets::{
	arbitrary::vanchor_data::VAnchorArbitraryData,
	leaf::vanchor::{Private, Public},
	poseidon::field_hasher::Poseidon,
};
use arkworks_utils::utils::common::{
	setup_params_x5_3, setup_params_x5_4, setup_params_x5_5, Curve,
};

use super::{create_merkle_tree, setup_tree_and_create_path, SMT};

pub mod utxo;

struct VAnchorR1CSProver<
	E: PairingEngine,
	const HEIGHT: usize,
	const ANCHOR_CT: usize,
	const INS: usize,
	const OUTS: usize,
> {
	engine: PhantomData<E>,
}

impl<
		E: PairingEngine,
		const HEIGHT: usize,
		const ANCHOR_CT: usize,
		const INS: usize,
		const OUTS: usize,
	> AnchorProver<E, HEIGHT, ANCHOR_CT> for VAnchorR1CSProver<E, HEIGHT, ANCHOR_CT, INS, OUTS>
{
	fn create_leaf_with_privates<R: RngCore + CryptoRng>(
		curve: Curve,
		chain_id: u64,
		secret: Option<Vec<u8>>,
		nullifier: Option<Vec<u8>>,
		rng: &mut R,
	) -> Result<VAnchorLeaf, Error> {
		use arkworks_gadgets::leaf::vanchor;
		// Initialize hashers
		let params3 = setup_params_x5_3::<E::Fr>(curve);
		let params4 = setup_params_x5_4::<E::Fr>(curve);
		let params5 = setup_params_x5_5::<E::Fr>(curve);
		let tree_hasher = Poseidon::<E::Fr> { params: params3 };
		let nullifier_hasher = Poseidon::<E::Fr> { params: params4 };
		let leaf_hasher = Poseidon::<E::Fr> { params: params5 };

		let secret_field_elt: E::Fr = match secret {
			Some(secret) => E::Fr::from_le_bytes_mod_order(&secret),
			None => E::Fr::rand(rng),
		};
		let nullifier_field_elt: E::Fr = match nullifier {
			Some(nullifier) => E::Fr::from_le_bytes_mod_order(&nullifier),
			None => E::Fr::rand(rng),
		};
		// We big-endian encode the chain ID when we pass it into the field elements
		let chain_id_elt = E::Fr::from(chain_id);
		let public = Public::new(chain_id_elt);
		let private: Private<E::Fr> = Private::new(secret_field_elt, nullifier_field_elt);
		let leaf_field_element =
			vanchor::VAnchorLeaf::create_leaf(&private, &public, &leaf_hasher)?;
		let nullifier_hash_field_element =
			vanchor::VAnchorLeaf::create_nullifier(&private, &tree_hasher)?;
		Ok(VAnchorLeaf {
			chain_id_bytes: chain_id.to_be_bytes().to_vec(),
			secret_bytes: secret_field_elt.into_repr().to_bytes_le(),
			nullifier_bytes: nullifier_field_elt.into_repr().to_bytes_le(),
			leaf_bytes: leaf_field_element.into_repr().to_bytes_le(),
			nullifier_hash_bytes: nullifier_hash_field_element.into_repr().to_bytes_le(),
		})
	}

	fn create_proof<R: RngCore + CryptoRng>(
		curve: Curve,
		chain_id: u64,
		secret: Vec<u8>,
		nullifier: Vec<u8>,
		leaves: Vec<Vec<u8>>,
		index: u64,
		root_set: [Vec<u8>; ANCHOR_CT],
		recipient: Vec<u8>,
		relayer: Vec<u8>,
		fee: u128,
		refund: u128,
		commitment: Vec<u8>,
		pk: Vec<u8>,
		default_leaf: [u8; 32],
		rng: &mut R,
	) -> Result<AnchorProof, Error> {
		// Initialize hashers
		let params3 = setup_params_x5_3::<E::Fr>(curve);
		let params4 = setup_params_x5_4::<E::Fr>(curve);
		let tree_hasher = Poseidon::<E::Fr> { params: params3 };
		let leaf_hasher = Poseidon::<E::Fr> { params: params4 };
		// Get field element version of all the data
		let secret_f = E::Fr::from_le_bytes_mod_order(&secret);
		let nullifier_f = E::Fr::from_le_bytes_mod_order(&nullifier);
		let leaves_f: Vec<E::Fr> = leaves
			.iter()
			.map(|x| E::Fr::from_le_bytes_mod_order(x))
			.collect();
		let root_set_f: [E::Fr; ANCHOR_CT] = root_set.map(|x| E::Fr::from_le_bytes_mod_order(&x));
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
		} = Self::create_leaf_with_privates(curve, chain_id, Some(secret), Some(nullifier), rng)?;
		// Setup the tree and generate the path
		let (_, path) = setup_tree_and_create_path::<E::Fr, PoseidonGadget<E::Fr>, HEIGHT>(
			tree_hasher.clone(),
			&leaves_f,
			index,
			&default_leaf,
		)?;

		let chain_id_f = E::Fr::from(chain_id);
		let leaf_public = Public::new(chain_id_f);
		let leaf_private = Private::new(secret_f, nullifier_f);
		let mc = AnchorCircuit::<
			E::Fr,
			PoseidonGadget<E::Fr>,
			PoseidonGadget<E::Fr>,
			HEIGHT,
			ANCHOR_CT,
		>::new(
			arbitrary_input,
			leaf_private,
			leaf_public,
			root_set_f,
			path,
			nullifier_f,
			tree_hasher,
			leaf_hasher,
		);
		let public_inputs = Self::construct_public_inputs(
			chain_id_f,
			nullifier_f,
			root_set_f,
			recipient_f,
			relayer_f,
			fee_f,
			refund_f,
			commitment_f,
		);

		let leaf_raw = leaf_bytes;
		let nullifier_hash_raw = nullifier_hash_bytes;
		let roots_raw = root_set_f
			.iter()
			.map(|v| v.into_repr().to_bytes_le())
			.collect();
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
