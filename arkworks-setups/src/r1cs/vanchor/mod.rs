use crate::{common::*, r1cs::vanchor::utxo::Utxo, VAnchorProver};
use ark_crypto_primitives::Error;
use ark_ec::PairingEngine;
use ark_ff::{BigInteger, PrimeField};
use ark_std::{
	collections::BTreeMap,
	marker::PhantomData,
	rand::{CryptoRng, Rng, RngCore},
	vec::Vec,
	UniformRand,
};
use arkworks_circuits::vanchor::VAnchorCircuit;
use arkworks_gadgets::{
	merkle_tree::simple_merkle::Path,
	poseidon::{field_hasher::Poseidon, field_hasher_constraints::PoseidonGadget},
};
use arkworks_utils::utils::common::{
	setup_params_x5_2, setup_params_x5_3, setup_params_x5_4, setup_params_x5_5, Curve,
};

use super::{setup_tree_and_create_path, SMT};
use crate::utxo;

#[cfg(test)]
mod tests;

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
	> VAnchorR1CSProver<E, HEIGHT, ANCHOR_CT, INS, OUTS>
{
	// TODO: Should be deprecated and tests migrated to `create_utxo`
	#[allow(dead_code)]
	pub fn new_utxo<R: RngCore>(
		curve: Curve,
		chain_id: u64,
		amount: E::Fr,
		index: Option<u64>,
		secret_key: Option<E::Fr>,
		blinding: Option<E::Fr>,
		rng: &mut R,
	) -> Result<Utxo<E::Fr>, Error> {
		// Initialize hashers
		let params2 = setup_params_x5_2::<E::Fr>(curve);
		let params4 = setup_params_x5_4::<E::Fr>(curve);
		let params5 = setup_params_x5_5::<E::Fr>(curve);
		let keypair_hasher = Poseidon::<E::Fr> { params: params2 };
		let nullifier_hasher = Poseidon::<E::Fr> { params: params4 };
		let leaf_hasher = Poseidon::<E::Fr> { params: params5 };
		Utxo::new(
			chain_id,
			amount,
			index,
			secret_key,
			blinding,
			&keypair_hasher,
			&nullifier_hasher,
			&leaf_hasher,
			rng,
		)
	}

	#[allow(dead_code)]
	pub fn setup_random_circuit<R: RngCore>(
		curve: Curve,
		default_leaf: [u8; 32],
		rng: &mut R,
	) -> Result<VAnchorCircuit<E::Fr, PoseidonGadget<E::Fr>, HEIGHT, INS, OUTS, ANCHOR_CT>, Error> {
		let public_amount = E::Fr::rand(rng);
		let ext_data_hash = E::Fr::rand(rng);
		let in_root_set = [E::Fr::rand(rng); ANCHOR_CT];
		let in_leaves = [E::Fr::rand(rng); INS].map(|x| vec![x]);
		let in_indices = [0; INS];

		let chain_id: u64 = rng.gen();
		let amount: u128 = rng.gen();
		let index: u64 = rng.gen();
		let secret_key = E::Fr::rand(rng);
		let blinding = E::Fr::rand(rng);

		let in_utxo = Self::create_utxo(
			curve,
			chain_id,
			amount,
			Some(index),
			secret_key.into_repr().to_bytes_le(),
			blinding.into_repr().to_bytes_le(),
		)?;
		let in_utxos: [Utxo<E::Fr>; INS] = [0; INS].map(|_| in_utxo.clone());

		let out_utxo = Self::create_utxo(
			curve,
			chain_id,
			amount,
			None,
			secret_key.into_repr().to_bytes_le(),
			blinding.into_repr().to_bytes_le(),
		)?;
		let out_utxos: [Utxo<E::Fr>; OUTS] = [0; OUTS].map(|_| out_utxo.clone());

		let (circuit, ..) = Self::setup_circuit_with_utxos(
			curve,
			E::Fr::from(chain_id),
			E::Fr::from(public_amount),
			ext_data_hash,
			in_root_set,
			in_indices,
			in_leaves,
			in_utxos,
			out_utxos,
			default_leaf,
		)?;

		Ok(circuit)
	}

	#[allow(dead_code)]
	pub fn setup_circuit_with_utxos(
		curve: Curve,
		chain_id: E::Fr,
		// External data
		public_amount: E::Fr,
		ext_data_hash: E::Fr,
		in_root_set: [E::Fr; ANCHOR_CT],
		in_indices: [u64; INS],
		in_leaves: [Vec<E::Fr>; INS],
		// Input transactions
		in_utxos: [Utxo<E::Fr>; INS],
		// Output transactions
		out_utxos: [Utxo<E::Fr>; OUTS],
		default_leaf: [u8; 32],
	) -> Result<
		(
			VAnchorCircuit<E::Fr, PoseidonGadget<E::Fr>, HEIGHT, INS, OUTS, ANCHOR_CT>,
			Vec<E::Fr>,
		),
		Error,
	> {
		// Initialize hashers
		let params2 = setup_params_x5_2::<E::Fr>(curve);
		let params3 = setup_params_x5_3::<E::Fr>(curve);
		let params4 = setup_params_x5_4::<E::Fr>(curve);
		let params5 = setup_params_x5_5::<E::Fr>(curve);
		let keypair_hasher = Poseidon::<E::Fr> { params: params2 };
		let tree_hasher = Poseidon::<E::Fr> { params: params3 };
		let nullifier_hasher = Poseidon::<E::Fr> { params: params4 };
		let leaf_hasher = Poseidon::<E::Fr> { params: params5 };
		// Tree + set for proving input txos
		let in_indices_f = in_indices.map(|x| E::Fr::from(x));
		let mut in_paths = Vec::new();
		for i in 0..INS {
			let (_, path) = setup_tree_and_create_path::<E::Fr, PoseidonGadget<E::Fr>, HEIGHT>(
				tree_hasher.clone(),
				&in_leaves[i],
				in_indices[i],
				&default_leaf,
			)?;
			in_paths.push(path)
		}
		// Arbitrary data

		let circuit = Self::setup_circuit(
			chain_id,
			public_amount,
			ext_data_hash,
			in_utxos.clone(),
			in_indices_f,
			in_paths,
			in_root_set,
			out_utxos.clone(),
			keypair_hasher,
			tree_hasher,
			nullifier_hasher,
			leaf_hasher,
		)?;

		let in_nullifiers: Result<Vec<E::Fr>, Error> =
			in_utxos.iter().map(|x| x.get_nullifier()).collect();
		let out_nullifiers = out_utxos
			.iter()
			.map(|x| x.commitment)
			.collect::<Vec<E::Fr>>();
		let public_inputs = Self::construct_public_inputs(
			in_utxos[0].chain_id,
			public_amount,
			in_root_set.to_vec(),
			in_nullifiers?,
			out_nullifiers,
			ext_data_hash,
		);

		Ok((circuit, public_inputs))
	}

	pub fn setup_circuit(
		chain_id: E::Fr,
		public_amount: E::Fr,
		arbitrary_data: E::Fr,
		// Input transactions
		in_utxos: [Utxo<E::Fr>; INS],
		// Data related to tree
		in_indicies: [E::Fr; INS],
		in_paths: Vec<Path<E::Fr, Poseidon<E::Fr>, HEIGHT>>,
		public_root_set: [E::Fr; ANCHOR_CT],
		// Output transactions
		out_utxos: [Utxo<E::Fr>; OUTS],
		keypair_hasher: Poseidon<E::Fr>,
		tree_hasher: Poseidon<E::Fr>,
		nullifier_hasher: Poseidon<E::Fr>,
		leaf_hasher: Poseidon<E::Fr>,
	) -> Result<VAnchorCircuit<E::Fr, PoseidonGadget<E::Fr>, HEIGHT, INS, OUTS, ANCHOR_CT>, Error> {
		let in_amounts = in_utxos
			.iter()
			.map(|x| x.amount.clone())
			.collect::<Vec<E::Fr>>();
		let in_blinding = in_utxos
			.iter()
			.map(|x| x.blinding.clone())
			.collect::<Vec<E::Fr>>();
		let in_private_keys = in_utxos
			.iter()
			.map(|x| x.keypair.secret_key.clone())
			.collect::<Vec<E::Fr>>();
		let in_nullifiers: Result<Vec<E::Fr>, Error> =
			in_utxos.iter().map(|x| x.get_nullifier()).collect();

		let out_pub_keys: Result<Vec<E::Fr>, _> = out_utxos
			.iter()
			.map(|x| x.keypair.public_key(&keypair_hasher))
			.collect();
		let out_commitments = out_utxos
			.iter()
			.map(|x| x.commitment)
			.collect::<Vec<E::Fr>>();
		let out_amounts = out_utxos
			.iter()
			.map(|x| x.amount.clone())
			.collect::<Vec<E::Fr>>();
		let out_blindings = out_utxos
			.iter()
			.map(|x| x.blinding.clone())
			.collect::<Vec<E::Fr>>();
		let out_chain_ids = out_utxos
			.iter()
			.map(|x| x.chain_id.clone())
			.collect::<Vec<E::Fr>>();

		let circuit =
			VAnchorCircuit::<E::Fr, PoseidonGadget<E::Fr>, HEIGHT, INS, OUTS, ANCHOR_CT>::new(
				public_amount,
				arbitrary_data,
				in_amounts,
				in_blinding,
				in_private_keys,
				chain_id,
				public_root_set,
				in_paths,
				in_indicies.to_vec(),
				in_nullifiers?,
				out_commitments,
				out_amounts,
				out_blindings,
				out_chain_ids,
				out_pub_keys?,
				tree_hasher,
				keypair_hasher,
				leaf_hasher,
				nullifier_hasher,
			);

		Ok(circuit)
	}

	pub fn construct_public_inputs(
		chain_id: E::Fr,
		public_amount: E::Fr,
		roots: Vec<E::Fr>,
		nullifiers: Vec<E::Fr>,
		commitments: Vec<E::Fr>,
		ext_data_hash: E::Fr,
	) -> Vec<E::Fr> {
		let mut public_inputs = vec![public_amount, ext_data_hash];
		public_inputs.extend(nullifiers);
		public_inputs.extend(commitments);
		public_inputs.push(chain_id);
		public_inputs.extend(roots);

		public_inputs
	}
}

impl<
		E: PairingEngine,
		const HEIGHT: usize,
		const ANCHOR_CT: usize,
		const INS: usize,
		const OUTS: usize,
	> VAnchorProver<E, HEIGHT, ANCHOR_CT, INS, OUTS>
	for VAnchorR1CSProver<E, HEIGHT, ANCHOR_CT, INS, OUTS>
{
	fn create_utxo(
		curve: Curve,
		chain_id: u64,
		amount: u128,
		index: Option<u64>,
		private_key: Vec<u8>,
		blinding: Vec<u8>,
	) -> Result<Utxo<E::Fr>, Error> {
		// Initialize hashers
		let params2 = setup_params_x5_2::<E::Fr>(curve);
		let params4 = setup_params_x5_4::<E::Fr>(curve);
		let params5 = setup_params_x5_5::<E::Fr>(curve);
		let keypair_hasher = Poseidon::<E::Fr> { params: params2 };
		let nullifier_hasher = Poseidon::<E::Fr> { params: params4 };
		let leaf_hasher = Poseidon::<E::Fr> { params: params5 };

		let private_key_elt: E::Fr = E::Fr::from_le_bytes_mod_order(&private_key);
		let blinding_field_elt: E::Fr = E::Fr::from_le_bytes_mod_order(&blinding);
		let amount_elt = E::Fr::from(amount);
		let utxo = Utxo::new_with_privates(
			chain_id,
			amount_elt,
			index,
			private_key_elt,
			blinding_field_elt,
			&keypair_hasher,
			&nullifier_hasher,
			&leaf_hasher,
		)?;
		Ok(utxo)
	}

	fn create_proof<R: RngCore + CryptoRng>(
		curve: Curve,
		chain_id: u64,
		// External data
		public_amount: u128,
		ext_data_hash: Vec<u8>,
		public_root_set: [Vec<u8>; ANCHOR_CT],
		in_indices: [u64; INS],
		in_leaves: BTreeMap<u64, Vec<Vec<u8>>>,
		// Input transactions
		in_utxos: [Utxo<E::Fr>; INS],
		// Output transactions
		out_utxos: [Utxo<E::Fr>; OUTS],
		pk: Vec<u8>,
		default_leaf: [u8; 32],
		rng: &mut R,
	) -> Result<VAnchorProof, Error> {
		// Initialize hashers
		let params2 = setup_params_x5_2::<E::Fr>(curve);
		let params3 = setup_params_x5_3::<E::Fr>(curve);
		let params4 = setup_params_x5_4::<E::Fr>(curve);
		let params5 = setup_params_x5_5::<E::Fr>(curve);
		let keypair_hasher = Poseidon::<E::Fr> { params: params2 };
		let tree_hasher = Poseidon::<E::Fr> { params: params3 };
		let nullifier_hasher = Poseidon::<E::Fr> { params: params4 };
		let leaf_hasher = Poseidon::<E::Fr> { params: params5 };
		// Cast as field elements
		let chain_id_elt = E::Fr::from(chain_id);
		let public_amount_elt = E::Fr::from(public_amount);
		let ext_data_hash_elt = E::Fr::from_le_bytes_mod_order(&ext_data_hash);
		// Generate the paths for each UTXO
		let mut trees = BTreeMap::<u64, SMT<E::Fr, Poseidon<E::Fr>, HEIGHT>>::new();

		let in_paths = in_utxos
			.iter()
			.map(|utxo| {
				let chain_id_of_utxo: u64 = utxo.chain_id_raw;
				if trees.contains_key(&chain_id_of_utxo) {
					let tree = trees.get(&chain_id_of_utxo).unwrap();
					tree.generate_membership_proof(utxo.index.unwrap_or_default())
				} else {
					let leaves = in_leaves.get(&chain_id_of_utxo).unwrap();
					let leaves_f = leaves
						.iter()
						.map(|l| E::Fr::from_le_bytes_mod_order(&l))
						.collect::<Vec<E::Fr>>();
					match setup_tree_and_create_path::<E::Fr, PoseidonGadget<E::Fr>, HEIGHT>(
						tree_hasher.clone(),
						&leaves_f,
						utxo.index.unwrap_or_default(),
						&default_leaf,
					) {
						Ok((tree, path)) => {
							trees.insert(chain_id_of_utxo, tree);
							path
						}
						Err(err) => panic!("{}", err),
					}
				}
			})
			.collect();

		// Get the circuit
		let circuit = Self::setup_circuit(
			chain_id_elt,
			public_amount_elt,
			ext_data_hash_elt,
			in_utxos.clone(),
			in_indices.map(|elt| E::Fr::from(elt)),
			in_paths,
			public_root_set
				.clone()
				.map(|elt| E::Fr::from_le_bytes_mod_order(&elt)),
			out_utxos.clone(),
			keypair_hasher,
			tree_hasher,
			nullifier_hasher,
			leaf_hasher,
		)?;

		let proof = prove_unchecked::<E, _, _>(circuit, &pk, rng)?;

		let public_inputs = Self::construct_public_inputs(
			chain_id_elt,
			public_amount_elt,
			public_root_set
				.map(|elt| E::Fr::from_le_bytes_mod_order(&elt))
				.to_vec(),
			in_utxos.map(|utxo| utxo.get_nullifier().unwrap()).to_vec(),
			out_utxos.map(|utxo| utxo.commitment).to_vec(),
			ext_data_hash_elt,
		);

		let public_inputs_raw = public_inputs
			.iter()
			.map(|inp| inp.into_repr().to_bytes_le())
			.collect();

		Ok(VAnchorProof {
			public_inputs_raw,
			proof,
		})
	}

	fn create_random_utxo<R: RngCore + CryptoRng>(
		curve: Curve,
		chain_id: u64,
		amount: u128,
		index: Option<u64>,
		rng: &mut R,
	) -> Result<Utxo<<E as PairingEngine>::Fr>, Error> {
		// Initialize hashers
		let params2 = setup_params_x5_2::<E::Fr>(curve);
		let params4 = setup_params_x5_4::<E::Fr>(curve);
		let params5 = setup_params_x5_5::<E::Fr>(curve);
		let keypair_hasher = Poseidon::<E::Fr> { params: params2 };
		let nullifier_hasher = Poseidon::<E::Fr> { params: params4 };
		let leaf_hasher = Poseidon::<E::Fr> { params: params5 };

		let amount_elt = E::Fr::from(amount);
		let utxo = Utxo::new(
			chain_id,
			amount_elt,
			index,
			None,
			None,
			&keypair_hasher,
			&nullifier_hasher,
			&leaf_hasher,
			rng,
		)?;
		Ok(utxo)
	}
}
