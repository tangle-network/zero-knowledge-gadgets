use crate::{common::*, r1cs::vanchor::utxo::Utxo, utxo, VAnchorProver};
use ark_crypto_primitives::Error;
use ark_ec::PairingEngine;
use ark_ff::{BigInteger, PrimeField, SquareRootField, Zero};
use ark_std::{
	boxed::Box,
	collections::BTreeMap,
	marker::PhantomData,
	rand::{CryptoRng, Rng, RngCore},
	vec,
	vec::Vec,
	UniformRand,
};

use arkworks_native_gadgets::{merkle_tree::Path, poseidon::Poseidon};
use arkworks_r1cs_circuits::vanchor::VAnchorCircuit;
use arkworks_r1cs_gadgets::poseidon::PoseidonGadget;
use arkworks_utils::Curve;

#[cfg(test)]
mod tests;

#[derive(Debug)]
pub enum VAnchorError {
	InvalidInputChainId,
}

impl core::fmt::Display for VAnchorError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		let msg = match self {
			Self::InvalidInputChainId => ark_std::format!("Invalid input chain ID"),
		};
		write!(f, "{}", msg)
	}
}

impl ark_std::error::Error for VAnchorError {}

pub struct VAnchorR1CSProver<
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
where
	<E as PairingEngine>::Fr: PrimeField + SquareRootField + From<i128>,
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
		let params2 = setup_params::<E::Fr>(curve, 5, 2);
		let params5 = setup_params::<E::Fr>(curve, 5, 5);
		let keypair_hasher = Poseidon::<E::Fr> { params: params2 };
		let leaf_hasher = Poseidon::<E::Fr> { params: params5 };
		Utxo::new(
			chain_id,
			amount,
			index,
			secret_key,
			blinding,
			&keypair_hasher,
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
		// Initialize hashers
		let params2 = setup_params::<E::Fr>(curve, 5, 2);
		let params3 = setup_params::<E::Fr>(curve, 5, 3);
		let params4 = setup_params::<E::Fr>(curve, 5, 4);
		let params5 = setup_params::<E::Fr>(curve, 5, 5);
		let keypair_hasher = Poseidon::<E::Fr> { params: params2 };
		let tree_hasher = Poseidon::<E::Fr> { params: params3 };
		let nullifier_hasher = Poseidon::<E::Fr> { params: params4 };
		let leaf_hasher = Poseidon::<E::Fr> { params: params5 };

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
			secret_key.into_repr().to_bytes_be(),
			blinding.into_repr().to_bytes_be(),
		)?;
		let in_utxos: [Utxo<E::Fr>; INS] = [0; INS].map(|_| in_utxo.clone());

		let out_utxo = Self::create_utxo(
			curve,
			chain_id,
			amount,
			None,
			secret_key.into_repr().to_bytes_be(),
			blinding.into_repr().to_bytes_be(),
		)?;
		let out_utxos: [Utxo<E::Fr>; OUTS] = [0; OUTS].map(|_| out_utxo.clone());

		// Tree + set for proving input txos
		let in_indices_f = in_indices.map(E::Fr::from);
		let mut in_paths = Vec::new();
		for i in 0..INS {
			let (_, path) = setup_tree_and_create_path::<E::Fr, Poseidon<E::Fr>, HEIGHT>(
				&tree_hasher,
				&in_leaves[i],
				in_indices[i],
				&default_leaf,
			)?;
			in_paths.push(path)
		}
		// Arbitrary data

		let circuit = Self::setup_circuit(
			E::Fr::from(chain_id),
			public_amount,
			ext_data_hash,
			in_utxos,
			in_indices_f,
			in_paths,
			in_root_set,
			out_utxos,
			keypair_hasher,
			tree_hasher,
			nullifier_hasher,
			leaf_hasher,
		)?;

		Ok(circuit)
	}

	pub fn setup_circuit(
		chain_id: E::Fr,
		public_amount: E::Fr,
		arbitrary_data: E::Fr,
		// Input transactions
		in_utxos: [Utxo<E::Fr>; INS],
		// Data related to tree
		in_indices: [E::Fr; INS],
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
			.map(|x| x.amount)
			.collect::<Vec<E::Fr>>();
		let in_blinding = in_utxos
			.iter()
			.map(|x| x.blinding)
			.collect::<Vec<E::Fr>>();
		let in_private_keys = in_utxos
			.iter()
			.map(|x| x.keypair.secret_key.unwrap())
			.collect::<Vec<E::Fr>>();
		let in_nullifiers: Result<Vec<E::Fr>, Error> = in_utxos
			.iter()
			.map(|x| x.calculate_nullifier(&nullifier_hasher.clone()))
			.collect();

		let out_pub_keys = out_utxos
			.iter()
			.map(|x| x.keypair.public_key)
			.collect::<Vec<E::Fr>>();
		let out_commitments = out_utxos
			.iter()
			.map(|x| x.commitment)
			.collect::<Vec<E::Fr>>();
		let out_amounts = out_utxos
			.iter()
			.map(|x| x.amount)
			.collect::<Vec<E::Fr>>();
		let out_blindings = out_utxos
			.iter()
			.map(|x| x.blinding)
			.collect::<Vec<E::Fr>>();
		let out_chain_ids = out_utxos
			.iter()
			.map(|x| x.chain_id)
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
				in_indices.to_vec(),
				in_nullifiers?,
				out_commitments,
				out_amounts,
				out_blindings,
				out_chain_ids,
				out_pub_keys,
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
where
	<E as PairingEngine>::Fr: PrimeField + SquareRootField + From<i128>,
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
		let params2 = setup_params::<E::Fr>(curve, 5, 2);
		let params5 = setup_params::<E::Fr>(curve, 5, 5);
		let keypair_hasher = Poseidon::<E::Fr> { params: params2 };
		let leaf_hasher = Poseidon::<E::Fr> { params: params5 };

		let private_key_elt: E::Fr = E::Fr::from_be_bytes_mod_order(&private_key);
		let blinding_field_elt: E::Fr = E::Fr::from_be_bytes_mod_order(&blinding);
		let amount_elt = E::Fr::from(amount);
		let utxo = Utxo::new_with_privates(
			chain_id,
			amount_elt,
			index,
			private_key_elt,
			blinding_field_elt,
			&keypair_hasher,
			&leaf_hasher,
		)?;
		Ok(utxo)
	}

	fn create_proof<R: RngCore + CryptoRng>(
		curve: Curve,
		chain_id: u64,
		// External data
		public_amount: i128,
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
		let params2 = setup_params::<E::Fr>(curve, 5, 2);
		let params3 = setup_params::<E::Fr>(curve, 5, 3);
		let params4 = setup_params::<E::Fr>(curve, 5, 4);
		let params5 = setup_params::<E::Fr>(curve, 5, 5);
		let keypair_hasher = Poseidon::<E::Fr> { params: params2 };
		let tree_hasher = Poseidon::<E::Fr> { params: params3 };
		let nullifier_hasher = Poseidon::<E::Fr> { params: params4 };
		let leaf_hasher = Poseidon::<E::Fr> { params: params5 };

		// Cast as field elements
		let chain_id_elt = E::Fr::from(chain_id);
		let public_amount_elt = E::Fr::from(public_amount);
		let ext_data_hash_elt = E::Fr::from_be_bytes_mod_order(&ext_data_hash);
		// Generate the paths for each UTXO
		let mut trees = BTreeMap::<u64, SMT<E::Fr, Poseidon<E::Fr>, HEIGHT>>::new();

		// Throw an error if chain IDs don't match intended spending chain.
		for utxo in in_utxos.clone() {
			if utxo.chain_id_raw != chain_id {
				//return Err("Invalid input chain ID".into());
				return Err(Box::new(VAnchorError::InvalidInputChainId).into());
			}
		}

		let input_nullifiers = in_utxos
			.clone()
			.map(|utxo| utxo.calculate_nullifier(&nullifier_hasher).unwrap());

		let in_paths = in_utxos
			.iter()
			.map(|utxo| {
				let chain_id_of_utxo: u64 = utxo.chain_id_raw;
				// Handle the default utxo when the amount is 0.
				if utxo.amount == E::Fr::zero() {
					// If the amount is 0, we just need to create a dummy path for a tree
					// that contains this dummy UTXO so that we can satisfy the merkle path
					// constraints on the path gadget.
					//
					// The path gadget contains constraints that verify the path was correctly
					// generated for a tree containing the UTXO in question. Therefore even for
					// dummy UTXOs, we still need to *simulate* this by creating a valid path in an
					// arbitrary tree. Since the amount is 0, this arbitrary tree has no effect on
					// the set membership check.
					match setup_tree_and_create_path::<E::Fr, Poseidon<E::Fr>, HEIGHT>(
						&tree_hasher,
						&[utxo.commitment],
						utxo.index.unwrap_or_default(),
						&default_leaf,
					) {
						Ok((_, path)) => path,
						Err(err) => panic!("{}", err),
					}
				} else if let std::collections::btree_map::Entry::Vacant(e) = trees.entry(chain_id_of_utxo) {
					let leaves = in_leaves.get(&chain_id_of_utxo).unwrap();
					let leaves_f = leaves
						.iter()
						.map(|l| E::Fr::from_be_bytes_mod_order(l))
						.collect::<Vec<E::Fr>>();
					match setup_tree_and_create_path::<E::Fr, Poseidon<E::Fr>, HEIGHT>(
						&tree_hasher,
						&leaves_f,
						utxo.index.unwrap_or_default(),
						&default_leaf,
					) {
						Ok((tree, path)) => {
							e.insert(tree);
							path
						}
						Err(err) => panic!("{}", err),
					}
				} else {
					let tree = trees.get(&chain_id_of_utxo).unwrap();
					tree.generate_membership_proof(utxo.index.unwrap_or_default())
				}
			})
			.collect();

		// Get the circuit
		let circuit = Self::setup_circuit(
			chain_id_elt,
			public_amount_elt,
			ext_data_hash_elt,
			in_utxos,
			in_indices.map(E::Fr::from),
			in_paths,
			public_root_set
				.clone()
				.map(|elt| E::Fr::from_be_bytes_mod_order(&elt)),
			out_utxos.clone(),
			keypair_hasher,
			tree_hasher,
			nullifier_hasher,
			leaf_hasher,
		)?;

		#[cfg(feature = "trace")]
		{
			use ark_relations::r1cs::{
				ConstraintLayer, ConstraintSynthesizer, ConstraintSystem, TracingMode,
			};
			use tracing_subscriber::layer::SubscriberExt;

			let mut layer = ConstraintLayer::default();
			layer.mode = TracingMode::OnlyConstraints;
			let subscriber = tracing_subscriber::Registry::default().with(layer);
			let _guard = tracing::subscriber::set_default(subscriber);

			let cs = ConstraintSystem::new_ref();
			circuit.clone().generate_constraints(cs.clone()).unwrap();
			println!("Number of constraints: {}", cs.num_constraints());
			let is_satisfied = cs.is_satisfied().unwrap();
			if !is_satisfied {
				println!("{:?}", cs.which_is_unsatisfied());
			}
		}

		let proof = prove_unchecked::<E, _, _>(circuit, &pk, rng)?;

		let public_inputs = Self::construct_public_inputs(
			chain_id_elt,
			public_amount_elt,
			public_root_set
				.map(|elt| E::Fr::from_be_bytes_mod_order(&elt))
				.to_vec(),
			input_nullifiers.to_vec(),
			out_utxos.map(|utxo| utxo.commitment).to_vec(),
			ext_data_hash_elt,
		);

		let public_inputs_raw = public_inputs
			.iter()
			.map(|inp| inp.into_repr().to_bytes_be())
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
		let params2 = setup_params::<E::Fr>(curve, 5, 2);
		let params5 = setup_params::<E::Fr>(curve, 5, 5);
		let keypair_hasher = Poseidon::<E::Fr> { params: params2 };
		let leaf_hasher = Poseidon::<E::Fr> { params: params5 };

		let amount_elt = E::Fr::from(amount);
		let utxo = Utxo::new(
			chain_id,
			amount_elt,
			index,
			None,
			None,
			&keypair_hasher,
			&leaf_hasher,
			rng,
		)?;
		Ok(utxo)
	}

	fn create_public_utxo(
		curve: Curve,
		chain_id: u64,
		amount: u128,
		blinding: Vec<u8>,
		public_key: Vec<u8>,
		index: Option<u64>,
	) -> Result<Utxo<<E as PairingEngine>::Fr>, Error> {
		// Initialize hashers
		let params5 = setup_params::<E::Fr>(curve, 5, 5);
		let leaf_hasher = Poseidon::<E::Fr> { params: params5 };

		let blinding_field_elt: E::Fr = E::Fr::from_be_bytes_mod_order(&blinding);
		let public_key_elt: E::Fr = E::Fr::from_be_bytes_mod_order(&public_key);
		let amount_elt = E::Fr::from(amount);
		let utxo = Utxo::new_with_public(
			chain_id,
			amount_elt,
			index,
			public_key_elt,
			blinding_field_elt,
			&leaf_hasher,
		)?;
		Ok(utxo)
	}
}
