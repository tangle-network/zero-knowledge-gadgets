use ark_crypto_primitives::Error;
use ark_ff::PrimeField;
use ark_std::collections::BTreeMap;
use arkworks_native_gadgets::{
	merkle_tree::{Path, SparseMerkleTree},
	poseidon::FieldHasher,
	poseidon::PoseidonParameters,
	poseidon::sbox::PoseidonSbox
};
use arkworks_r1cs_gadgets::poseidon::FieldHasherGadget;
use arkworks_utils::Curve;
use arkworks_utils::{bytes_vec_to_f, bytes_matrix_to_f};
use arkworks_utils::poseidon_params::{setup_poseidon_params};

pub mod anchor;
pub mod mixer;
pub mod vanchor;

// TODO: Move the contents of the whole file to ../common.rs, to be used for other proving systems
pub type SMT<F, H, const HEIGHT: usize> = SparseMerkleTree<F, H, HEIGHT>;

pub fn create_merkle_tree<F: PrimeField, H: FieldHasher<F>, const N: usize>(
	hasher: H,
	leaves: &[F],
	default_leaf: &[u8],
) -> SparseMerkleTree<F, H, N> {
	let pairs: BTreeMap<u32, F> = leaves
		.iter()
		.enumerate()
		.map(|(i, l)| (i as u32, *l))
		.collect();
	let smt = SparseMerkleTree::<F, H, N>::new(&pairs, &hasher, default_leaf).unwrap();

	smt
}

pub fn setup_tree_and_create_path<F: PrimeField, HG: FieldHasherGadget<F>, const HEIGHT: usize>(
	hasher: HG::Native,
	leaves: &[F],
	index: u64,
	default_leaf: &[u8],
) -> Result<(SMT<F, HG::Native, HEIGHT>, Path<F, HG::Native, HEIGHT>), Error> {
	// Making the merkle tree
	let smt = create_merkle_tree::<F, HG::Native, HEIGHT>(hasher, leaves, default_leaf);
	// Getting the proof path
	let path = smt.generate_membership_proof(index);
	Ok((smt, path))
}

pub fn setup_params<F: PrimeField>(curve: Curve, exp: i8, width: u8) -> PoseidonParameters<F> {
	let pos_data = setup_poseidon_params(curve, exp, width).unwrap();

	let mds_f = bytes_matrix_to_f(&pos_data.mds);
	let rounds_f = bytes_vec_to_f(&pos_data.rounds);

	let pos = PoseidonParameters {
		mds_matrix: mds_f,
		round_keys: rounds_f,
		full_rounds: pos_data.full_rounds,
		partial_rounds: pos_data.partial_rounds,
		sbox: PoseidonSbox(pos_data.exp),
		width: pos_data.width
	};

	pos
}