use std::marker::PhantomData;

use ark_crypto_primitives::{CRHGadget, CRH};
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;

use crate::{
	arbitrary::{constraints::ArbitraryGadget, Arbitrary},
	leaf::{constraints::NewLeafCreationGadget, NewLeafCreation},
	merkle_tree::{
		constraints::{NodeVar, PathVar},
		Config as MerkleConfig, Path,
	},
	set::{Set, SetGadget},
	Vec,
};

use super::{constraints::{KeypairsCreationGadget, KeypairsVar}, keypairs::{Keypairs, KeypairsCreation}};

pub struct TransactionGadget<
	F: PrimeField,
	// Arbitrary data constraints
	A: Arbitrary,
	AG: ArbitraryGadget<F, A>,
	// Hasher for the leaf creation
	H: CRH,
	HG: CRHGadget<H, F>,
	// Merkle config and hasher gadget for the tree
	C: MerkleConfig,
	LHGT: CRHGadget<C::LeafH, F>,
	HGT: CRHGadget<C::H, F>,
	// Type of leaf creation
	L: NewLeafCreation<H>,
	LG: NewLeafCreationGadget<F, H, HG, L>,
	// Set of merkle roots
	S: Set<F, M>,
	SG: SetGadget<F, S, M>,
	KP: KeypairsCreation<H, F>,
	KPG: KeypairsCreationGadget<H, HG, F, L, LG>,
	const N: usize,
	const M: usize,
> {
	publicAmount: Vec<F>,
	extDataHash: Vec<A>,

	inputNullifier: Vec<H::Output>,
	inputAmount: Vec<F>,
	inPrivateKey: Vec<F>,
	inBlinding: Vec<F>,
	inPathIndices: Vec<F>,
	inPathElements: Vec<Path<C, N>>,

	outputCommitment: Vec<F>,
	outChaiID: Vec<F>,
	outAmount: Vec<F>,
	outPubkey: Vec<F>,
	outBlinding: Vec<F>,

	chainID: F,
	root_set: [F; M],
	diffs: [Vec<F>; M],

	inKeyPair: Vec<F>,
	inUtxoHasher: H,
	nullifierHasher: H,
	sums: F,
	_arbitrary_gadget: PhantomData<AG>,
	_hasher: PhantomData<H>,
	_hasher_gadget: PhantomData<HG>,
	_leaf_hasher_gadget: PhantomData<LHGT>,
	_tree_hasher_gadget: PhantomData<HGT>,
	_leaf_creation: PhantomData<L>,
	_leaf_creation_gadget: PhantomData<LG>,
	_set: PhantomData<S>,
	_set_gadget: PhantomData<SG>,
	_merkle_config: PhantomData<C>,
	_keypairs: PhantomData<KP>,
    _keypairsgadet: PhantomData<KPG>,
}

impl<F, A, AG, H, HG, C, LHGT, HGT, L, LG, S, SG, KP, KPG, const N: usize, const M: usize>
	TransactionGadget<F, A, AG, H, HG, C, LHGT, HGT, L, LG, S, SG, KP, KPG, N, M>
where
	F: PrimeField,
	A: Arbitrary,
	AG: ArbitraryGadget<F, A>,
	H: CRH,
	HG: CRHGadget<H, F>,
	C: MerkleConfig,
	LHGT: CRHGadget<C::LeafH, F>,
	HGT: CRHGadget<C::H, F>,
	L: NewLeafCreation<H>,
	LG: NewLeafCreationGadget<F, H, HG, L>,
	S: Set<F, M>,
	SG: SetGadget<F, S, M>,
	KP: KeypairsCreation<H, F>,
    KPG: KeypairsCreationGadget<H, HG, F, L, LG>,

{
	//TODO: Verify correctness of transaction inputs
	pub fn verify_input(&self) {
		// /self.inKeyPair = Vec::<>;
		for tx in 0..N {}
	}
	//TODO: Verify correctness of transaction outputs

	//TODO: Check that there are no same nullifiers among all inputs

	//TODO: Verify amount invariant

	//TODO: Optional safety constraint to make sure extDataHash cannot be changed
}
