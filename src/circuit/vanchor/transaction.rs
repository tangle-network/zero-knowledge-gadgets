use std::marker::PhantomData;

use crate::{
	arbitrary::{constraints::ArbitraryGadget, Arbitrary},
	leaf::{
		constraints::VanchorLeafCreationGadget,
		vanchor::{
			constraints::{PrivateVar, PublicVar},
			Private,
		},
		VanchorLeafCreation,
	},
	merkle_tree::{
		constraints::{NodeVar, PathVar},
		Config as MerkleConfig, Path,
	},
	set::{Set, SetGadget},
	Vec,
};
use ark_bls12_381::Fq;
use ark_crypto_primitives::{CRHGadget, CRH};
use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::EqGadget};
use ark_relations::r1cs::SynthesisError;

use super::{
	constraints::{KeypairCreationGadget, KeypairVar},
	keypair::{Keypair, KeypairCreation},
};

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
	L: VanchorLeafCreation<H>,
	LG: VanchorLeafCreationGadget<F, H, HG, L>,
	// Set of merkle roots
	S: Set<F, M>,
	SG: SetGadget<F, S, M>,
	KC: KeypairCreation<H, F>,
	KCG: KeypairCreationGadget<H, HG, F, L, LG>,
	const N: usize,
	const M: usize,
> {
	publicAmount: F,
	extDataHash: A,

	inputNullifier: Vec<LG::NullifierVar>,
	inputAmount: Vec<F>,
	inPrivateKey: Vec<F>,
	inPrivateKey_var: Vec<FpVar<F>>,
	inBlinding: Vec<F>,
	inPathIndices: Vec<F>,
	inPathElements: Vec<Path<C, N>>,

	outputCommitment: Vec<F>,
	outChainID: Vec<F>,
	outAmount: Vec<F>,
	outPubkey: Vec<F>,
	outBlinding: Vec<F>,

	chainID: F,
	root_set: [F; M],
	diffs: [Vec<F>; M],
	inKeyPair: Vec<KC>,
	inKeyPair_var: Vec<KCG>,
	nullifierHasher: H,
	sums: F,
	sums_var: FpVar<F>,
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
	_Keypair: PhantomData<KC>,
	_Keypairgadet: PhantomData<KCG>,
}
use crate::{ark_std::Zero, leaf::vanchor::constraints::VanchorLeafGadget};
use ark_r1cs_std::fields::FieldVar;

impl<F, A, AG, H, HG, C, LHGT, HGT, L, LG, S, SG, KC, KCG, const N: usize, const M: usize>
	TransactionGadget<F, A, AG, H, HG, C, LHGT, HGT, L, LG, S, SG, KC, KCG, N, M>
where
	F: PrimeField,
	A: Arbitrary,
	AG: ArbitraryGadget<F, A>,
	H: CRH,
	HG: CRHGadget<H, F>,
	C: MerkleConfig,
	LHGT: CRHGadget<C::LeafH, F>,
	HGT: CRHGadget<C::H, F>,
	L: VanchorLeafCreation<H>,
	LG: VanchorLeafCreationGadget<F, H, HG, L>,
	S: Set<F, M>,
	SG: SetGadget<F, S, M>,
	KC: KeypairCreation<H, F>,
	KCG: KeypairCreationGadget<H, HG, F, L, LG>,
{
	//TODO: Verify correctness of transaction inputs with native values
	pub fn verify_input(&mut self, hasher_params: H::Parameters, secrets: Vec<Private<F>>) {
		//self.inKeyPair = Keypair();
		for tx in 0..N {
			self.inKeyPair[tx] = KC::new(&hasher_params, &secrets[tx]).unwrap();
			self.inPrivateKey[tx] = self.inKeyPair[tx].private_key().unwrap();
			//...
		}
		//...
	}

	//TODO: Verify correctness of transaction inputs using constraints
	pub fn verify_input_var(
		&mut self,
		hg: HG::ParametersVar,
		hg4: HG::ParametersVar,
		hg3: HG::ParametersVar,
		secrets_var: Vec<<LG as VanchorLeafCreationGadget<F, H, HG, L>>::PrivateVar>,
		public_var: Vec<<LG as VanchorLeafCreationGadget<F, H, HG, L>>::PublicVar>,
		nullifier_var: Vec<LG::NullifierVar>,
		indices: Vec<FpVar<F>>,
		// ...
	) -> Result<(), SynthesisError> {
		self.sums_var = FpVar::<F>::zero();
		self.inputNullifier = nullifier_var;
		let mut inUtxoHasher_var_out: Vec<LG::LeafVar> = Vec::with_capacity(10);
		for tx in 0..N {
			self.inKeyPair_var[tx] = KCG::new(&hg, &secrets_var[tx]).unwrap();
			self.inPrivateKey_var[tx] = self.inKeyPair_var[tx].private_key_var().unwrap();

			let pubkey = self.inKeyPair_var[tx].public_key_var().unwrap();
			inUtxoHasher_var_out[tx] =
				LG::create_leaf(&secrets_var[tx], &public_var[tx], &pubkey, &hg4).unwrap();
			let nullifier_hasher_out = LG::create_nullifier(
				&secrets_var[tx],
				&inUtxoHasher_var_out[tx],
				&hg3,
				&indices[tx],
			)
			.unwrap();
			nullifier_hasher_out.enforce_equal(&self.inputNullifier[tx])?;

			let amount = LG::get_amount(&secrets_var[tx])?;
			self.sums_var = self.sums_var.clone() + amount;
			//...
		}

		Ok(())
	}

	//TODO: Verify correctness of transaction outputs

	//TODO: Check that there are no same nullifiers among all inputs

	//TODO: Verify amount invariant

	//TODO: Optional safety constraint to make sure extDataHash cannot be changed
}
