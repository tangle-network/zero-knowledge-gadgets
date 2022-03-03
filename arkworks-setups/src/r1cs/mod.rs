use ark_crypto_primitives::Error;
use ark_ff::PrimeField;
use ark_std::collections::BTreeMap;
use arkworks_native_gadgets::merkle_tree::{Path, SparseMerkleTree};
use arkworks_r1cs_gadgets::poseidon::FieldHasherGadget;
use arkworks_native_gadgets::poseidon::FieldHasher;

pub mod anchor;
pub mod mixer;
pub mod vanchor;

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
