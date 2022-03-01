use ark_std::collections::BTreeMap;
use ark_ff::PrimeField;
use arkworks_gadgets::poseidon::field_hasher::FieldHasher;
use arkworks_gadgets::merkle_tree::simple_merkle::SparseMerkleTree;

pub mod mixer;
pub mod anchor;

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