use super::{is_left_child, is_root, left_child, parent, right_child, sibling, tree_height};
use crate::poseidon::field_hasher::FieldHasher;
use ark_crypto_primitives::Error;
use ark_ff::PrimeField;
use ark_std::collections::BTreeMap;
use std::{collections::BTreeSet, marker::PhantomData};

// Path
#[derive(Clone)]
pub struct Path<F: PrimeField, H: FieldHasher<F>, const N: usize> {
	pub(crate) path: [(F, F); N],
	_marker: PhantomData<H>,
}

impl<F: PrimeField, H: FieldHasher<F>, const N: usize> Path<F, H, N> {
	/// Takes in an expected `root_hash` and leaf-level data (i.e. hashes of
	/// secrets) for a leaf and checks that the leaf belongs to a tree having
	/// the expected hash.
	pub fn check_membership(&self, root_hash: &F, leaf: &F, hasher: &H) -> Result<bool, Error> {
		let root = self.calculate_root(leaf, hasher)?;
		Ok(root == *root_hash)
	}

	/// Assumes leaf contains leaf-level data, i.e. hashes of secrets
	/// stored on leaf-level.
	pub fn calculate_root(&self, leaf: &F, hasher: &H) -> Result<F, Error> {
		if *leaf != self.path[0].0 && *leaf != self.path[0].1 {
			return Err(Error::from("Leaf is not on path"));
		}

		let mut prev = *leaf;
		// Check levels between leaf level and root
		for &(ref left_hash, ref right_hash) in &self.path {
			if &prev != left_hash && &prev != right_hash {
				return Err(Error::from("Path nodes are not consistent"));
			}
			prev = hasher.hash_two(left_hash, right_hash)?;
		}

		Ok(prev)
	}

	/// Given leaf data determine what the index of this leaf must be
	/// in the Merkle tree it belongs to.  Before doing so check that the leaf
	/// does indeed belong to a tree with the given `root_hash`
	pub fn get_index(&self, root_hash: &F, leaf: &F, hasher: &H) -> Result<F, Error> {
		if !self.check_membership(root_hash, leaf, hasher)? {
			return Err(Error::from("Leaf is not on path"));
		}

		let mut prev = *leaf;
		let mut index = F::zero();
		let mut twopower = F::one();
		// Check levels between leaf level and root
		for &(ref left_hash, ref right_hash) in &self.path {
			// Check if the previous hash is for a left node or right node
			if &prev != left_hash {
				index += twopower;
			}
			twopower = twopower + twopower;
			prev = hasher.hash_two(left_hash, right_hash)?;
		}

		Ok(index)
	}
}

// Merkle sparse tree
// We wanted the "default" or "empty" leaf to be specified as a constant in
// the struct's trait bounds but arrays are not allowed as constants.  Instead
// all constructor functions take in a default/empty leaf argument.
pub struct SparseMerkleTree<F: PrimeField, H: FieldHasher<F>, const N: usize> {
	/// data of the tree
	pub tree: BTreeMap<u64, F>,
	empty_hashes: [F; N],
	_marker: PhantomData<H>,
}

impl<F: PrimeField, H: FieldHasher<F>, const N: usize> SparseMerkleTree<F, H, N> {
	/// Takes a collection of leaf data (hashes of secrets), inserts
	/// these hashes at leaf level, and propagates the changes up the tree to
	/// the root.
	pub fn insert_batch(&mut self, leaves: &BTreeMap<u32, F>, hasher: &H) -> Result<(), Error> {
		let last_level_index: u64 = (1u64 << N) - 1;

		let mut level_idxs: BTreeSet<u64> = BTreeSet::new();
		for (i, leaf) in leaves {
			let true_index = last_level_index + (*i as u64);
			self.tree.insert(true_index, *leaf);
			level_idxs.insert(parent(true_index).unwrap());
		}

		for level in 0..N {
			let mut new_idxs: BTreeSet<u64> = BTreeSet::new();
			for i in level_idxs {
				let left_index = left_child(i);
				let right_index = right_child(i);

				let empty_hash = self.empty_hashes[level].clone();
				let left = self.tree.get(&left_index).unwrap_or(&empty_hash);
				let right = self.tree.get(&right_index).unwrap_or(&empty_hash);
				#[allow(mutable_borrow_reservation_conflict)]
				self.tree.insert(i, hasher.hash_two(left, right)?);

				let parent = match parent(i) {
					Some(i) => i,
					None => break,
				};
				new_idxs.insert(parent);
			}
			level_idxs = new_idxs;
		}

		Ok(())
	}

	pub fn new(leaves: &BTreeMap<u32, F>, hasher: &H, empty_leaf: &[u8]) -> Result<Self, Error> {
		// Ensure the tree can hold this many leaves
		let last_level_size = leaves.len().next_power_of_two();
		let tree_size = 2 * last_level_size - 1;
		let tree_height = tree_height(tree_size as u64);
		assert!(tree_height <= N as u32);

		// Initialize the merkle tree
		let tree: BTreeMap<u64, F> = BTreeMap::new();
		let empty_hashes = gen_empty_hashes(hasher, empty_leaf)?;

		let mut smt = SparseMerkleTree::<F, H, N> {
			tree,
			empty_hashes,
			_marker: PhantomData,
		};
		smt.insert_batch(leaves, hasher)?;

		Ok(smt)
	}

	pub fn new_sequential(leaves: &[F], hasher: &H, empty_leaf: &[u8]) -> Result<Self, Error> {
		let pairs: BTreeMap<u32, F> = leaves
			.iter()
			.enumerate()
			.map(|(i, l)| (i as u32, l.clone()))
			.collect();
		let smt = Self::new(&pairs, hasher, empty_leaf)?;

		Ok(smt)
	}

	pub fn root(&self) -> F {
		self.tree
			.get(&0)
			.cloned()
			.unwrap_or(*self.empty_hashes.last().unwrap())
	}

	/// Give the path leading from the leaf at `index` up to the root.  This is
	/// a "proof" in the sense of "valid path in a Merkle tree", not a ZK
	/// argument.
	pub fn generate_membership_proof(&self, index: u64) -> Path<F, H, N> {
		let mut path = [(F::zero(), F::zero()); N];

		let tree_index = convert_index_to_last_level(index, N);

		// Iterate from the leaf up to the root, storing all intermediate hash values.
		let mut current_node = tree_index;
		let mut level = 0;
		while !is_root(current_node) {
			let sibling_node = sibling(current_node).unwrap();

			let empty_hash = &self.empty_hashes[level];

			let current = self
				.tree
				.get(&current_node)
				.cloned()
				.unwrap_or_else(|| empty_hash.clone());
			let sibling = self
				.tree
				.get(&sibling_node)
				.cloned()
				.unwrap_or_else(|| empty_hash.clone());

			if is_left_child(current_node) {
				path[level] = (current, sibling);
			} else {
				path[level] = (sibling, current);
			}
			current_node = parent(current_node).unwrap();
			level += 1;
		}

		Path {
			path,
			_marker: PhantomData,
		}
	}
}

pub fn gen_empty_hashes<F: PrimeField, H: FieldHasher<F>, const N: usize>(
	hasher: &H,
	default_leaf: &[u8],
) -> Result<[F; N], Error> {
	let mut empty_hashes = [F::zero(); N];

	// let mut empty_hash =
	// hasher.hash(&[F::from_le_bytes_mod_order(default_leaf)])?;
	let mut empty_hash = F::from_le_bytes_mod_order(default_leaf);
	empty_hashes[0] = empty_hash;

	for i in 1..N {
		empty_hash = hasher.hash_two(&empty_hash, &empty_hash)?;
		empty_hashes[i] = empty_hash;
	}

	Ok(empty_hashes)
}

fn convert_index_to_last_level(index: u64, height: usize) -> u64 {
	index + (1u64 << height) - 1
}

#[cfg(test)]
mod test {
	use super::{gen_empty_hashes, SparseMerkleTree};
	use crate::poseidon::field_hasher::{FieldHasher, Poseidon};
	use ark_bls12_381::Fq;
	use ark_ff::{BigInteger, PrimeField, UniformRand};
	use ark_std::{collections::BTreeMap, test_rng};
	use arkworks_utils::utils::{
		common::{setup_params_x5_3, Curve},
		parse_vec,
	};

	type BLSHash = Poseidon<Fq>;

	//helper to change leaves array to BTreeMap and then create SMT
	fn create_merkle_tree<F: PrimeField, H: FieldHasher<F>, const N: usize>(
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

	#[test]
	fn should_create_tree_poseidon() {
		let rng = &mut test_rng();
		let curve = Curve::Bls381;

		let params = setup_params_x5_3(curve);
		let poseidon = Poseidon::new(params);
		let default_leaf = [0u8; 32];
		let leaves = [Fq::rand(rng), Fq::rand(rng), Fq::rand(rng)];
		const HEIGHT: usize = 3;
		let smt =
			create_merkle_tree::<Fq, BLSHash, HEIGHT>(poseidon.clone(), &leaves, &default_leaf);

		let root = smt.root();

		let empty_hashes =
			gen_empty_hashes::<Fq, BLSHash, HEIGHT>(&poseidon, &default_leaf).unwrap();
		let hash1 = leaves[0];
		let hash2 = leaves[1];
		let hash3 = leaves[2];

		let hash12 = poseidon.hash_two(&hash1, &hash2).unwrap();
		let hash34 = poseidon.hash_two(&hash3, &empty_hashes[0]).unwrap();

		let hash1234 = poseidon.hash_two(&hash12, &hash34).unwrap();
		let calc_root = poseidon.hash_two(&hash1234, &empty_hashes[2]).unwrap();

		assert_eq!(root, calc_root);
	}

	#[test]
	fn should_generate_and_validate_proof_poseidon() {
		let rng = &mut test_rng();
		let curve = Curve::Bls381;

		let params = setup_params_x5_3(curve);
		let poseidon = Poseidon::new(params);
		let default_leaf = [0u8; 32];
		let leaves = [Fq::rand(rng), Fq::rand(rng), Fq::rand(rng)];
		const HEIGHT: usize = 3;
		let smt =
			create_merkle_tree::<Fq, BLSHash, HEIGHT>(poseidon.clone(), &leaves, &default_leaf);

		let proof = smt.generate_membership_proof(0);

		let res = proof
			.check_membership(&smt.root(), &leaves[0], &poseidon)
			.unwrap();
		assert!(res);
	}

	#[test]
	fn should_find_the_index_poseidon() {
		let rng = &mut test_rng();
		let curve = Curve::Bls381;

		let params = setup_params_x5_3(curve);
		let poseidon = Poseidon::new(params);
		let default_leaf = [0u8; 32];
		let leaves = [Fq::rand(rng), Fq::rand(rng), Fq::rand(rng)];
		const HEIGHT: usize = 3;
		let smt =
			create_merkle_tree::<Fq, BLSHash, HEIGHT>(poseidon.clone(), &leaves, &default_leaf);

		let index = 2;

		let proof = smt.generate_membership_proof(index);

		let res = proof
			.get_index(&smt.root(), &leaves[index as usize], &poseidon)
			.unwrap();
		let desired_res = Fq::from(index);

		assert_eq!(res, desired_res);
	}

	// Backwards-compatibility tests:
	use crate::{
		merkle_tree::{Config, SparseMerkleTree as OldSparseMerkleTree},
		poseidon::CRH as PoseidonCRH,
	};
	use ark_crypto_primitives::crh::{TwoToOneCRH, CRH};
	use ark_ff::ToBytes;
	use ark_std::rc::Rc;

	type SMTCRH = PoseidonCRH<Fq>;

	#[derive(Clone, Debug, Eq, PartialEq)]
	struct SMTConfig;
	impl Config for SMTConfig {
		type H = SMTCRH;
		type LeafH = SMTCRH;

		const HEIGHT: u8 = 3;
	}

	// Helper function to create a Merkle tree in the old way:
	fn create_old_merkle_tree<L: Default + ToBytes + Copy, C: Config>(
		inner_params: Rc<<C::H as CRH>::Parameters>,
		leaf_params: Rc<<C::LeafH as CRH>::Parameters>,
		leaves: &[L],
	) -> OldSparseMerkleTree<C> {
		let pairs: BTreeMap<u32, L> = leaves
			.iter()
			.enumerate()
			.map(|(i, l)| (i as u32, *l))
			.collect();
		let smt = OldSparseMerkleTree::<C>::new(inner_params, leaf_params, &pairs).unwrap();

		smt
	}

	#[test]
	fn should_create_trees_with_same_root_poseidon() {
		// Common to both
		let rng = &mut test_rng();
		let curve = Curve::Bls381;

		let params = setup_params_x5_3(curve);

		let leaves = [Fq::rand(rng), Fq::rand(rng), Fq::rand(rng)];

		// Specific to old method
		let inner_params = Rc::new(params.clone());
		let leaf_params = inner_params.clone();

		let old_smt = create_old_merkle_tree::<Fq, SMTConfig>(
			inner_params.clone(),
			leaf_params.clone(),
			&leaves.to_vec(),
		);

		let old_root = old_smt.root().inner();

		// Specific to new method
		let poseidon = Poseidon::new(params);
		let default_leaf = [0u8; 32]; // what's used as old empty leaf? Looks empty: INPUT_SIZE_BITS / 8 = 0 ?
		const HEIGHT: usize = 3;
		// hash leaves before constructing tree b/c old implementation does too:
		// can this be done with map() or something instead of for loop?
		let mut hashed_leaves = [Fq::from(0u64); 3];
		for i in 0..3 {
			hashed_leaves[i] = poseidon.hash(&[leaves[i]]).unwrap();
		}
		let smt = create_merkle_tree::<Fq, BLSHash, HEIGHT>(
			poseidon.clone(),
			&hashed_leaves,
			&default_leaf,
		);

		let root = smt.root();

		assert_eq!(root, old_root);
	}

	use ark_bn254::Fr as Bn254Fr;

	#[test]
	fn compare_with_solidity_empty_hashes() {
		// These are taken from protocol-solidity/contracts/trees/MerkleTreePoseidon.sol
		let solidity_empty_hashes_hex = vec![
			"0x2fe54c60d3acabf3343a35b6eba15db4821b340f76e741e2249685ed4899af6c",
			"0x13e37f2d6cb86c78ccc1788607c2b199788c6bb0a615a21f2e7a8e88384222f8",
			"0x217126fa352c326896e8c2803eec8fd63ad50cf65edfef27a41a9e32dc622765",
			"0x0e28a61a9b3e91007d5a9e3ada18e1b24d6d230c618388ee5df34cacd7397eee",
			"0x27953447a6979839536badc5425ed15fadb0e292e9bc36f92f0aa5cfa5013587",
			"0x194191edbfb91d10f6a7afd315f33095410c7801c47175c2df6dc2cce0e3affc",
			"0x1733dece17d71190516dbaf1927936fa643dc7079fc0cc731de9d6845a47741f",
			"0x267855a7dc75db39d81d17f95d0a7aa572bf5ae19f4db0e84221d2b2ef999219",
			"0x1184e11836b4c36ad8238a340ecc0985eeba665327e33e9b0e3641027c27620d",
			"0x0702ab83a135d7f55350ab1bfaa90babd8fc1d2b3e6a7215381a7b2213d6c5ce",
			"0x2eecc0de814cfd8c57ce882babb2e30d1da56621aef7a47f3291cffeaec26ad7",
			"0x280bc02145c155d5833585b6c7b08501055157dd30ce005319621dc462d33b47",
			"0x045132221d1fa0a7f4aed8acd2cbec1e2189b7732ccb2ec272b9c60f0d5afc5b",
			"0x27f427ccbf58a44b1270abbe4eda6ba53bd6ac4d88cf1e00a13c4371ce71d366",
			"0x1617eaae5064f26e8f8a6493ae92bfded7fde71b65df1ca6d5dcec0df70b2cef",
			"0x20c6b400d0ea1b15435703c31c31ee63ad7ba5c8da66cec2796feacea575abca",
			"0x09589ddb438723f53a8e57bdada7c5f8ed67e8fece3889a73618732965645eec",
			"0x0064b6a738a5ff537db7b220f3394f0ecbd35bfd355c5425dc1166bf3236079b",
			"0x095de56281b1d5055e897c3574ff790d5ee81dbc5df784ad2d67795e557c9e9f",
			"0x11cf2e2887aa21963a6ec14289183efe4d4c60f14ecd3d6fe0beebdf855a9b63",
			"0x2b0f6fc0179fa65b6f73627c0e1e84c7374d2eaec44c9a48f2571393ea77bcbb",
			"0x16fdb637c2abf9c0f988dbf2fd64258c46fb6a273d537b2cf1603ea460b13279",
			"0x21bbd7e944f6124dad4c376df9cc12e7ca66e47dff703ff7cedb1a454edcf0ff",
			"0x2784f8220b1c963e468f590f137baaa1625b3b92a27ad9b6e84eb0d3454d9962",
			"0x16ace1a65b7534142f8cc1aad810b3d6a7a74ca905d9c275cb98ba57e509fc10",
			"0x2328068c6a8c24265124debd8fe10d3f29f0665ea725a65e3638f6192a96a013",
			"0x2ddb991be1f028022411b4c4d2c22043e5e751c120736f00adf54acab1c9ac14",
			"0x0113798410eaeb95056a464f70521eb58377c0155f2fe518a5594d38cc209cc0",
			"0x202d1ae61526f0d0d01ef80fb5d4055a7af45721024c2c24cffd6a3798f54d50",
			"0x23ab323453748129f2765f79615022f5bebd6f4096a796300aab049a60b0f187",
			"0x1f15585f8947e378bcf8bd918716799da909acdb944c57150b1eb4565fda8aa0",
			"0x1eb064b21055ac6a350cf41eb30e4ce2cb19680217df3a243617c2838185ad06",
		];
		let solidity_empty_hashes: Vec<Bn254Fr> = parse_vec(solidity_empty_hashes_hex);

		// Generate again with this module's functions
		let curve = Curve::Bn254;
		let params = setup_params_x5_3::<Bn254Fr>(curve);
		let poseidon = Poseidon::<Bn254Fr>::new(params.clone());

		let default_leaf_hex =
			vec!["0x2fe54c60d3acabf3343a35b6eba15db4821b340f76e741e2249685ed4899af6c"];
		let default_leaf_scalar: Vec<Bn254Fr> = parse_vec(default_leaf_hex);
		let default_leaf_vec = default_leaf_scalar[0].into_repr().to_bytes_le();
		let mut default_leaf = [0u8; 64];
		for i in 0..default_leaf_vec.len() {
			default_leaf[i] = default_leaf_vec[i];
		}
		let empty_hashes =
			gen_empty_hashes::<Bn254Fr, _, 32usize>(&poseidon, &default_leaf).unwrap();

		assert_eq!(empty_hashes.to_vec(), solidity_empty_hashes);
	}
}
