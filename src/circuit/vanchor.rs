use crate::{
	arbitrary::bridge_data::{constraints::InputVar as ArbitraryInputVar, Input as ArbitraryInput},
	keypair::vanchor::{constraints::KeypairVar, Keypair},
	leaf::vanchor::{
		constraints::{
			PrivateVar as LeafPrivateInputsVar, PublicVar as LeafPublicInputsVar, VAnchorLeafGadget,
		},
		Private as LeafPrivateInputs, Public as LeafPublicInputs,
	},
	merkle_tree::{
		constraints::{NodeVar, PathVar},
		Config as MerkleConfig, Path,
	},
	set::membership::{
		constraints::{PrivateVar as SetPrivateInputsVar, SetMembershipGadget},
		Private as SetPrivateInputs,
	},
	Vec,
};
use ark_crypto_primitives::{crh::CRHGadget, CRH};
use ark_ff::{fields::PrimeField, to_bytes, ToBytes};
use ark_r1cs_std::{eq::EqGadget, fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::{cmp::Ordering::Less, marker::PhantomData};
pub struct VAnchorCircuit<
	F: PrimeField,
	// Hasher for the leaf creation,  Nullifier, Public key generation
	H2: CRH,
	HG2: CRHGadget<H2, F>,
	H4: CRH,
	HG4: CRHGadget<H4, F>,
	H5: CRH,
	HG5: CRHGadget<H5, F>,
	// Merkle config and hasher gadget for the tree
	C: MerkleConfig,
	LHGT: CRHGadget<C::LeafH, F>,
	HGT: CRHGadget<C::H, F>,
	const N: usize,
	const M: usize,
> {
	public_amount: F,
	ext_data_hash: ArbitraryInput<F>,

	leaf_private_inputs: Vec<LeafPrivateInputs<F>>, // amount, blinding
	private_key_inputs: Vec<F>,
	leaf_public_inputs: LeafPublicInputs<F>,         // chain_id
	set_private_inputs: Vec<SetPrivateInputs<F, M>>, // diffs
	root_set: [F; M],
	hasher_params_w2: H2::Parameters,
	hasher_params_w4: H4::Parameters,
	hasher_params_w5: H5::Parameters,
	path: Vec<Path<C, M>>,
	index: Vec<F>,
	nullifier_hash: Vec<H4::Output>,

	output_commitment: Vec<H5::Output>,
	out_chain_id: Vec<F>,
	out_amount: Vec<F>,
	out_pubkey: Vec<F>,
	out_blinding: Vec<F>,

	_hasher2: PhantomData<H2>,
	_hasher2_gadget: PhantomData<HG2>,
	_hasher4: PhantomData<H4>,
	_hasher4_gadget: PhantomData<HG4>,
	_hasher5: PhantomData<H5>,
	_hasher5_gadget: PhantomData<HG5>,
	_leaf_hasher_gadget: PhantomData<LHGT>,
	_tree_hasher_gadget: PhantomData<HGT>,
	_merkle_config: PhantomData<C>,
}

impl<
		F,
		H2,
		HG2,
		H4,
		HG4,
		H5,
		HG5,
		C,
		LHGT,
		HGT,
		const N: usize,
		const M: usize,
	> VAnchorCircuit<F, H2, HG2, H4, HG4, H5, HG5, C, LHGT, HGT,  N, M>
where
	F: PrimeField,
	H2: CRH,
	HG2: CRHGadget<H2, F>,
	H4: CRH,
	HG4: CRHGadget<H4, F>,
	H5: CRH,
	HG5: CRHGadget<H5, F>,
	C: MerkleConfig,
	LHGT: CRHGadget<C::LeafH, F>,
	HGT: CRHGadget<C::H, F>,
{
	pub fn new(
		public_amount: F,
		ext_data_hash: ArbitraryInput<F>,
		leaf_private_inputs: Vec<LeafPrivateInputs<F>>,
		private_key_inputs: Vec<F>,
		leaf_public_inputs: LeafPublicInputs<F>,
		set_private_inputs: Vec<SetPrivateInputs<F, M>>,
		root_set: [F; M],
		hasher_params_w2: H2::Parameters,
		hasher_params_w4: H4::Parameters,
		hasher_params_w5: H5::Parameters,
		path: Vec<Path<C, M>>,
		index: Vec<F>,
		nullifier_hash: Vec<H4::Output>,
		output_commitment: Vec<H5::Output>,
		out_chain_id: Vec<F>,
		out_amount: Vec<F>,
		out_pubkey: Vec<F>,
		out_blinding: Vec<F>,
	) -> Self {
		Self {
			public_amount,
			ext_data_hash,
			leaf_private_inputs,
			private_key_inputs,
			leaf_public_inputs,
			set_private_inputs,
			root_set,
			hasher_params_w2,
			hasher_params_w4,
			hasher_params_w5,
			path,
			index,
			nullifier_hash,
			output_commitment,
			out_chain_id,
			out_amount,
			out_pubkey,
			out_blinding,
			_hasher2: PhantomData,
			_hasher2_gadget: PhantomData,
			_hasher4: PhantomData,
			_hasher4_gadget: PhantomData,
			_hasher5: PhantomData,
			_hasher5_gadget: PhantomData,
			_leaf_hasher_gadget: PhantomData,
			_tree_hasher_gadget: PhantomData,
			_merkle_config: PhantomData,
		}
	}

	pub fn verify_input_var(
		&self,
		hasher_params_w2_var: &HG2::ParametersVar,
		hasher_params_w4_var: &HG4::ParametersVar,
		hasher_params_w5_var: &HG5::ParametersVar,
		leaf_private_var: &Vec<LeafPrivateInputsVar<F>>,
		private_key_inputs_var: &Vec<FpVar<F>>,
		leaf_public_var: &LeafPublicInputsVar<F>,
		//key_pairs_inputs_var: &Vec<KeypairVar<F, BG, H2, HG2, H4, HG4, H5, HG5>>,
		in_path_indices_var: &Vec<FpVar<F>>,
		in_path_elements_var: &Vec<PathVar<F, C, HGT, LHGT, M>>,
		in_nullifier_var: &Vec<HG4::OutputVar>,
		root_set_var: &Vec<FpVar<F>>,
		set_input_private_var: &Vec<SetPrivateInputsVar<F, M>>,
	) -> Result<FpVar<F>, SynthesisError> {
		let mut sums_ins_var = FpVar::<F>::zero();
		let mut in_utxo_hasher_var: Vec<HG5::OutputVar> = Vec::with_capacity(N);
		let mut nullifier_hash: Vec<HG4::OutputVar> = Vec::with_capacity(N);
		let mut in_amount_tx: FpVar<F>;
		//let keypairs
		let mut inkeypair: Vec<KeypairVar<F, H2, HG2, H4, HG4, H5, HG5>> = Vec::with_capacity(N);
		for tx in 0..N {
			inkeypair.push(
				KeypairVar::<F, H2, HG2, H4, HG4, H5, HG5>::new(&private_key_inputs_var[tx])
					.unwrap(),
			);

			// Computing the hash
			in_utxo_hasher_var.push(
				VAnchorLeafGadget::<F, H2, HG2, H4, HG4, H5, HG5>::create_leaf(
					//<FpVar<F>>
					&leaf_private_var[tx],
					&inkeypair[tx].public_key(hasher_params_w2_var).unwrap(),
					&leaf_public_var,
					&hasher_params_w5_var,
				)?,
			);
			// End of computing the hash

			// Nullifier
			nullifier_hash.push(
				VAnchorLeafGadget::<F, H2, HG2, H4, HG4, H5, HG5>::create_nullifier(
					&inkeypair[tx].private_key().unwrap(),
					&in_utxo_hasher_var[tx],
					&hasher_params_w4_var,
					&in_path_indices_var[tx],
				)?,
			);

			nullifier_hash[tx].enforce_equal(&in_nullifier_var[tx])?;

			// add the roots and diffs signals to the vanchor circuit
			let roothash =
				&in_path_elements_var[tx].root_hash(&in_utxo_hasher_var[tx]).unwrap();
			in_amount_tx = VAnchorLeafGadget::<F, H2, HG2, H4, HG4, H5, HG5>::get_amount(
				&leaf_private_var[tx],
			)
			.unwrap();
			let check = SetMembershipGadget::check_is_enabled(
				&roothash,
				&root_set_var,
				&set_input_private_var[tx],
				&in_amount_tx,
			)?;
			check.enforce_equal(&Boolean::TRUE)?;
			/* if !nullifier_hash[tx].cs().is_in_setup_mode() {
				println!("here0");
				assert!(nullifier_hash[tx].cs().is_satisfied().unwrap());
				println!("here1");
			} */
			sums_ins_var = sums_ins_var + in_amount_tx;
		}
		Ok(sums_ins_var)
	}

	// Verify correctness of transaction outputs
	pub fn verify_output_var(
		&self,
		hasher_params_w5_var: &HG5::ParametersVar,
		output_commitment_var: &Vec<HG5::OutputVar>,
		out_chain_id_var: &Vec<FpVar<F>>,
		out_amount_var: &Vec<FpVar<F>>,
		out_pubkey_var: &Vec<FpVar<F>>,
		out_blinding_var: &Vec<FpVar<F>>,
		limit_var: &FpVar<F>,
	) -> Result<FpVar<F>, SynthesisError> {
		let mut sums_outs_var = FpVar::<F>::zero();
		let mut in_utxo_hasher_var_out: Vec<HG5::OutputVar> = Vec::with_capacity(N);
		for tx in 0..N {
			// Computing the hash
			let mut bytes = Vec::new();
			bytes.extend(out_chain_id_var[tx].to_bytes()?);
			bytes.extend(out_amount_var[tx].to_bytes()?);
			bytes.extend(out_pubkey_var[tx].to_bytes()?);
			bytes.extend(out_blinding_var[tx].to_bytes()?);
			in_utxo_hasher_var_out.push(HG5::evaluate(&hasher_params_w5_var, &bytes)?);
			// End of computing the hash
			in_utxo_hasher_var_out[tx].enforce_equal(&output_commitment_var[tx])?;

			// Check that amount is less than 2^248 in the field (to prevent overflow)
			out_amount_var[tx].enforce_cmp_unchecked(&limit_var, Less, false)?;

			sums_outs_var = sums_outs_var + out_amount_var[tx].clone();
			//...
		}
		Ok(sums_outs_var)
	}

	//Check that there are no same nullifiers among all inputs
	pub fn verify_no_same_nul(
		&self,
		in_nullifier_var: &Vec<HG4::OutputVar>,
	) -> Result<(), SynthesisError> {
		
		let mut same_nullifiers: Vec<HG4::OutputVar> = Vec::with_capacity(2);
		for i in 0..N-1 {
			for j in (i+1)..N {
				same_nullifiers.push(in_nullifier_var[i].clone());
				same_nullifiers.push(in_nullifier_var[j].clone());
				same_nullifiers[0].enforce_not_equal(&same_nullifiers[1])?;
			}
		
		}
	
		Ok(())
	}

	// Verify amount invariant
	pub fn verify_input_invariant(
		&self,
		public_amount_var: &FpVar<F>,
		sum_ins_var: &FpVar<F>,
		sum_outs_var: &FpVar<F>,
	) -> Result<(), SynthesisError> {
		let res = sum_ins_var + public_amount_var.clone();
		res.enforce_equal(&sum_outs_var).unwrap();
		Ok(())
	}
	//TODO: Optional safety constraint to make sure extDataHash cannot be changed
}

impl<
		F,
		H2,
		HG2,
		H4,
		HG4,
		H5,
		HG5,
		C,
		LHGT,
		HGT,
		const N: usize,
		const M: usize,
	> Clone for VAnchorCircuit<F, H2, HG2, H4, HG4, H5, HG5, C, LHGT, HGT, N, M>
where
	F: PrimeField,
	H2: CRH,
	HG2: CRHGadget<H2, F>,
	H4: CRH,
	HG4: CRHGadget<H4, F>,
	H5: CRH,
	HG5: CRHGadget<H5, F>,
	C: MerkleConfig,
	LHGT: CRHGadget<C::LeafH, F>,
	HGT: CRHGadget<C::H, F>,
{
	fn clone(&self) -> Self {
		let public_amount = self.public_amount.clone();
		let ext_data_hash = self.ext_data_hash.clone();
		let leaf_private_inputs = self.leaf_private_inputs.clone();
		let leaf_public_inputs = self.leaf_public_inputs.clone();
		let set_private_inputs = self.set_private_inputs.clone();
		let root_set = self.root_set;
		let hasher_params_w2 = self.hasher_params_w2.clone();
		let hasher_params_w4 = self.hasher_params_w4.clone();
		let hasher_params_w5 = self.hasher_params_w5.clone();
		let path = self.path.clone();
		let index = self.index.clone();
		let nullifier_hash = self.nullifier_hash.clone();
		let private_key_inputs = self.private_key_inputs.clone();
		let output_commitment = self.output_commitment.clone();
		let out_chain_id = self.out_chain_id.clone();
		let out_amount = self.out_amount.clone();
		let out_pubkey = self.out_pubkey.clone();
		let out_blinding = self.out_blinding.clone();
		Self::new(
			public_amount,
			ext_data_hash,
			leaf_private_inputs,
			private_key_inputs,
			leaf_public_inputs,
			set_private_inputs,
			root_set,
			hasher_params_w2,
			hasher_params_w4,
			hasher_params_w5,
			path,
			index,
			nullifier_hash,
			output_commitment,
			out_chain_id,
			out_amount,
			out_pubkey,
			out_blinding,
		)
	}
}

impl<
		F,
		H2,
		HG2,
		H4,
		HG4,
		H5,
		HG5,
		C,
		LHGT,
		HGT,
		const N: usize,
		const M: usize,
	> ConstraintSynthesizer<F> for VAnchorCircuit<F, H2, HG2, H4, HG4, H5, HG5, C, LHGT, HGT, N, M>
where
	F: PrimeField,
	H2: CRH,
	HG2: CRHGadget<H2, F>,
	H4: CRH,
	HG4: CRHGadget<H4, F>,
	H5: CRH,
	HG5: CRHGadget<H5, F>,
	C: MerkleConfig,
	LHGT: CRHGadget<C::LeafH, F>,
	HGT: CRHGadget<C::H, F>,
{
	fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
		let public_amount = self.public_amount.clone();
		let ext_data_hash = self.ext_data_hash.clone();
		let leaf_private = self.leaf_private_inputs.clone(); // amount, blinding
		let private_key_inputs = self.private_key_inputs.clone();
		let leaf_public = self.leaf_public_inputs.clone(); // chain id
		let set_private = self.set_private_inputs.clone();
		let root_set = self.root_set.clone();
		let hasher_params_w2 = self.hasher_params_w2.clone();
		let hasher_params_w4 = self.hasher_params_w4.clone();
		let hasher_params_w5 = self.hasher_params_w5.clone();
		let path = self.path.clone();
		let index = self.index.clone();
		let nullifier_hash = self.nullifier_hash.clone();

		let output_commitment = self.output_commitment.clone();
		let out_chain_id = self.out_chain_id.clone();
		let out_amount = self.out_amount.clone();
		let out_pubkey = self.out_pubkey.clone();
		let out_blinding = self.out_blinding.clone();
		// 2^248
		let limit: F = F::from_str(
			"452312848583266388373324160190187140051835877600158453279131187530910662656",
		)
		.unwrap_or_default();
		// check the previous conversion is done correctly
		assert_ne!(limit, F::default());

		// Generating vars
		// Public inputs
		let limit_var: FpVar<F> = FpVar::<F>::new_constant(cs.clone(), limit)?;
		let leaf_public_var =
			LeafPublicInputsVar::new_input(cs.clone(), || Ok(leaf_public.clone()))?;
		let public_amount_var = FpVar::<F>::new_input(cs.clone(), || Ok(public_amount))?;
		let root_set_var = Vec::<FpVar<F>>::new_input(cs.clone(), || Ok(root_set))?;
		let mut set_input_private_var: Vec<SetPrivateInputsVar<F, M>> = Vec::with_capacity(N);

		let mut in_nullifier_var: Vec<HG4::OutputVar> = Vec::with_capacity(N);

		//let root_set_var = Vec::<FpVar<F>>::new_input(cs.clone(), || Ok(root_set))?;
		let arbitrary_input_var = ArbitraryInputVar::new_input(cs.clone(), || Ok(ext_data_hash))?;

		// Constants
		let hasher_params_w2_var = HG2::ParametersVar::new_constant(cs.clone(), hasher_params_w2)?;
		let hasher_params_w4_var = HG4::ParametersVar::new_constant(cs.clone(), hasher_params_w4)?;
		let hasher_params_w5_var = HG5::ParametersVar::new_constant(cs.clone(), hasher_params_w5)?;

		// Private inputs
		let mut leaf_private_var: Vec<LeafPrivateInputsVar<F>> = Vec::with_capacity(N);
		let mut private_key_inputs_var: Vec<FpVar<F>> = Vec::with_capacity(N);

		let mut in_path_elements_var: Vec<PathVar<F, C, HGT, LHGT, M>> = Vec::with_capacity(N);
		let mut in_path_indices_var: Vec<FpVar<F>> = Vec::with_capacity(N);

		// Outputs
		let mut out_amount_var: Vec<FpVar<F>> = Vec::with_capacity(N);
		let mut out_chain_id_var: Vec<FpVar<F>> = Vec::with_capacity(N);
		let mut out_pubkey_var: Vec<FpVar<F>> = Vec::with_capacity(N);
		let mut out_blinding_var: Vec<FpVar<F>> = Vec::with_capacity(N);
		let mut output_commitment_var: Vec<HG5::OutputVar> = Vec::with_capacity(N);

		for i in 0..N {
			set_input_private_var.push(SetPrivateInputsVar::new_witness(cs.clone(), || {
				Ok(set_private[i].clone())
			})?);

			private_key_inputs_var.push(FpVar::<F>::new_witness(cs.clone(), || {
				Ok(private_key_inputs[i].clone())
			})?);

			leaf_private_var.push(LeafPrivateInputsVar::new_witness(cs.clone(), || {
				Ok(leaf_private[i].clone())
			})?);
			in_nullifier_var.push(HG4::OutputVar::new_input(cs.clone(), || {
				Ok(nullifier_hash[i].clone())
			})?);

			in_path_elements_var.push(PathVar::<F, C, HGT, LHGT, M>::new_witness(
				cs.clone(),
				|| Ok(path[i].clone()),
			)?);
			in_path_indices_var.push(FpVar::<F>::new_witness(
				cs.clone(),
				|| Ok(index[i].clone()),
			)?);

			out_amount_var.push(FpVar::<F>::new_witness(cs.clone(), || {
				Ok(out_amount[i].clone())
			})?);
			out_chain_id_var.push(FpVar::<F>::new_witness(cs.clone(), || {
				Ok(out_chain_id[i].clone())
			})?);
			out_pubkey_var.push(FpVar::<F>::new_witness(cs.clone(), || {
				Ok(out_pubkey[i].clone())
			})?);
			out_blinding_var.push(FpVar::<F>::new_witness(cs.clone(), || {
				Ok(out_blinding[i].clone())
			})?);
			output_commitment_var.push(HG5::OutputVar::new_witness(cs.clone(), || {
				Ok(output_commitment[i].clone())
			})?);
		}

		// verify correctness of transaction inputs
		let sum_ins_var = self
			.verify_input_var(
				&hasher_params_w2_var,
				&hasher_params_w4_var,
				&hasher_params_w5_var,
				&leaf_private_var,
				&private_key_inputs_var,
				&leaf_public_var,
				&in_path_indices_var,
				&in_path_elements_var,
				&in_nullifier_var,
				&root_set_var,
				&set_input_private_var,
			)
			.unwrap();
		if !cs.is_in_setup_mode(){
			assert!(cs.is_satisfied().unwrap());
		}
		// verify correctness of transaction outputs
		let sum_outs_var = self
			.verify_output_var(
				&hasher_params_w5_var,
				&output_commitment_var,
				&out_chain_id_var,
				&out_amount_var,
				&out_pubkey_var,
				&out_blinding_var,
				&limit_var,
			)
			.unwrap();
		if !cs.is_in_setup_mode(){
			assert!(cs.is_satisfied().unwrap());
		}
		// check that there are no same nullifiers among all inputs
		self.verify_no_same_nul(&in_nullifier_var).unwrap();
		if !cs.is_in_setup_mode(){
			assert!(cs.is_satisfied().unwrap());
		}
		// verify amount invariant
		self.verify_input_invariant(&public_amount_var, &sum_ins_var, &sum_outs_var)
			.unwrap();
		if !cs.is_in_setup_mode(){
			assert!(cs.is_satisfied().unwrap());
		}
		// optional safety constraint to make sure extDataHash cannot be changed
		// TODO: Modify it when the Arbitrary gadget is Implemened for VAnchor
		ArbitraryInputVar::constrain(&arbitrary_input_var)?;
		if !cs.is_in_setup_mode(){
			assert!(cs.is_satisfied().unwrap());
		}
		Ok(())
	}
}

#[cfg(feature = "default_poseidon")]
#[cfg(test)]
mod test {
	use super::*;
	use crate::{
		ark_std::{One, Zero},
		leaf::vanchor::{constraints::VAnchorLeafGadget, VAnchorLeaf},
		poseidon::{
			constraints::CRHGadget as PCRHGadget, sbox::PoseidonSbox, PoseidonParameters, Rounds,
			CRH as PCRH,
		},
		merkle_tree::{Config as MerkleConfig, Path, SparseMerkleTree},
		setup::{bridge::*, common::*},
	};
	use ark_bn254::{Bn254, Fr as BnFr};
	use ark_ff::UniformRand;
	use ark_groth16::{
		create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
		Groth16,
	};

	use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
	use ark_relations::r1cs::ConstraintSystem;
	use ark_snark::SNARK;
	use ark_std::{rand::Rng, test_rng};
	use std::{rc::Rc, str::FromStr};

	pub const TEST_K: usize = 30;
	pub const TEST_N: usize = 2;
	pub const TEST_M: usize = 2;

	#[derive(Default, Clone)]
	struct PoseidonRounds2;

	impl Rounds for PoseidonRounds2 {
		const FULL_ROUNDS: usize = 8;
		const PARTIAL_ROUNDS: usize = 56;
		const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
		const WIDTH: usize = 2;
	}

	#[derive(Default, Clone)]
	struct PoseidonRounds4;

	impl Rounds for PoseidonRounds4 {
		const FULL_ROUNDS: usize = 8;
		const PARTIAL_ROUNDS: usize = 56;
		const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
		const WIDTH: usize = 4;
	}

	#[derive(Default, Clone)]
	struct PoseidonRounds5;

	impl Rounds for PoseidonRounds5 {
		const FULL_ROUNDS: usize = 8;
		const PARTIAL_ROUNDS: usize = 60;
		const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
		const WIDTH: usize = 5;
	}

	type PoseidonCRH2 = PCRH<BnFr, PoseidonRounds2>;
	type PoseidonCRH4 = PCRH<BnFr, PoseidonRounds4>;
	type PoseidonCRH5 = PCRH<BnFr, PoseidonRounds5>;

	type PoseidonCRH2Gadget = PCRHGadget<BnFr, PoseidonRounds2>;
	type PoseidonCRH4Gadget = PCRHGadget<BnFr, PoseidonRounds4>;
	type PoseidonCRH5Gadget = PCRHGadget<BnFr, PoseidonRounds5>;

	type Leaf = VAnchorLeaf<BnFr, PoseidonCRH2, PoseidonCRH4, PoseidonCRH5>;

	#[derive(Clone, PartialEq)]
	pub struct TreeConfig_x5<F: PrimeField>(PhantomData<F>);
	impl<F: PrimeField> MerkleConfig for TreeConfig_x5<F> {
		type H = PoseidonCRH_x5_3<F>;
		type LeafH = LeafCRH<F>;

		const HEIGHT: u8 = 2;
	}
	pub type Tree_x5<BnFr> = SparseMerkleTree<TreeConfig_x5<BnFr>>;

	// type LeafGadget = VAnchorLeafGadget<
	// 	BnFr,
	// 	PoseidonCRH2,
	// 	PoseidonCRH2Gadget,
	// 	PoseidonCRH4,
	// 	PoseidonCRH4Gadget,
	// 	PoseidonCRH5,
	// 	PoseidonCRH5Gadget,
	// >;

	type VACircuit = VAnchorCircuit<
		BnFr,
		PoseidonCRH2,
		PoseidonCRH2Gadget,
		PoseidonCRH4,
		PoseidonCRH4Gadget,
		PoseidonCRH5,
		PoseidonCRH5Gadget,
		TreeConfig_x5<BnFr>,
		LeafCRHGadget<BnFr>,
		PoseidonCRH_x5_3Gadget<BnFr>,
		TEST_N,
		TEST_M,
	>;

	#[test]
	fn should_create_circuit_and_proves_groth16() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;
		let params5: PoseidonParameters<BnFr> = setup_params_x5_5(curve);
		let params4: PoseidonParameters<BnFr> = setup_params_x5_4(curve);
		let params3: PoseidonParameters<BnFr> = setup_params_x5_3(curve);
		let params2: PoseidonParameters<BnFr> = setup_params_x5_2(curve);
		let chain_id = BnFr::zero();
		let relayer = BnFr::rand(rng);
		let recipient = BnFr::rand(rng);
		let fee = BnFr::rand(rng);
		let refund = BnFr::rand(rng);

		let in_amount_1 = BnFr::one();
		let blinding_1 = BnFr::rand(rng);
		let in_amount_2 = BnFr::one() + BnFr::one();
		let blinding_2 = BnFr::rand(rng);
		let leaf_private_1 = LeafPrivateInputs::<BnFr>::new(&in_amount_1, &blinding_1);
		let leaf_private_2 = LeafPrivateInputs::<BnFr>::new(&in_amount_2, &blinding_2);
		let leaf_privates = vec![leaf_private_1.clone(), leaf_private_2.clone()];

		let leaf_public = LeafPublicInputs::<BnFr>::new(chain_id.clone());

		let private_key_1 = BnFr::rand(rng);
		let privkey = to_bytes![private_key_1].unwrap();
		let public_key_1 = PoseidonCRH2::evaluate(&params2, &privkey).unwrap();
		let private_key_2 = BnFr::rand(rng);
		let privkey = to_bytes![private_key_2].unwrap();
		let public_key_2 = PoseidonCRH2::evaluate(&params2, &privkey).unwrap();
		let private_keys = 	vec![private_key_1.clone(), private_key_2.clone()];

		let leaf_1 = Leaf::create_leaf(&leaf_private_1, &public_key_1, &leaf_public, &params5).unwrap();
		let commitment_1 = leaf_1.clone();
		let leaf_2 = Leaf::create_leaf(&leaf_private_2, &public_key_2, &leaf_public, &params5).unwrap();
		let commitment_2 = leaf_2.clone();

		let inner_params = Rc::new(params3.clone());
		let leaves = [leaf_1, leaf_2];
		let tree = Tree_x5::new_sequential(inner_params, Rc::new(()), &leaves).unwrap();
		//let (tree_1, path_1) = setup_tree_and_create_path_tree_x5::<BnFr, TEST_M>(&[leaf_1], 0, &params3);
		//let (tree_2, path_2) = setup_tree_and_create_path_tree_x5::<BnFr, TEST_M>(&[leaf_1], 0, &params3);
		
		let path_1 = tree.generate_membership_proof(0);
		let path_2 = tree.generate_membership_proof(1);
		let paths = vec![path_1.clone(), path_2.clone()];
		
		let public_amount = BnFr::one();
		//TODO: Change aritrary data
		let ext_data_hash_1 = setup_arbitrary_data(recipient, relayer, fee, refund, commitment_1);
		//let ext_data_hash_2 = setup_arbitrary_data(recipient, relayer, fee, refund, commitment_2);
		let ext_data_hash = ext_data_hash_1;// TODO: change it with new Arbitrary values
		let root = tree.root().inner();

		let mut root_set = [BnFr::rand(rng); TEST_M];
		root_set[0] = root;
		assert_eq!(root_set.len(),TEST_M);
		//let leaves = vec![leaf, BnFr::rand(rng), BnFr::rand(rng)];
		let index_0: BnFr = path_1.get_index(&tree.root(), &leaf_1).unwrap();
		let index_1: BnFr = path_1.get_index(&tree.root(), &leaf_2).unwrap();
		assert_eq!(index_0, BnFr::zero());
		assert_eq!(index_1, BnFr::one());
		let indices = vec![index_0, index_1];

		let nullifier_hash_1 = Leaf::create_nullifier(&private_key_1, &leaf_1, &params4, &index_0).unwrap();
		let nullifier_hash_2 = Leaf::create_nullifier(&private_key_2, &leaf_2, &params4, &index_1).unwrap();
		let nullifier_hash= vec![nullifier_hash_1, nullifier_hash_2];
		assert_ne!(nullifier_hash_1,nullifier_hash_2);

		let set_private_inputs_1 = setup_set(&root, &root_set);
		let set_private_inputs = vec![set_private_inputs_1.clone(), set_private_inputs_1.clone()];
		let out_chain_id_1 = BnFr::one();
		let out_amount_1 = public_amount + leaf_private_1.get_amount().unwrap();
		let out_pubkey_1 = BnFr::rand(rng);
		let out_blinding_1 = BnFr::rand(rng);
		let bytes = to_bytes![out_chain_id_1, out_amount_1, out_pubkey_1, out_blinding_1].unwrap();
		let out_commitment_1 = PoseidonCRH5::evaluate(&params5, &bytes).unwrap();

		let out_chain_id_2 = BnFr::one();
		let out_amount_2 =  leaf_private_2.get_amount().unwrap();
		let out_pubkey_2 = BnFr::rand(rng);
		let out_blinding_2 = BnFr::rand(rng);
		let bytes = to_bytes![out_chain_id_2, out_amount_2, out_pubkey_2, out_blinding_2].unwrap();
		let out_commitment_2 = PoseidonCRH5::evaluate(&params5, &bytes).unwrap();

		let out_chain_id = vec![out_chain_id_1, out_chain_id_2];
		let out_amount = vec![out_amount_1, out_amount_2];
		let out_pubkey = vec![out_pubkey_1, out_pubkey_2];
		let out_blinding = vec![out_blinding_1, out_blinding_2];
		let out_commitment= vec![out_commitment_1, out_commitment_2];
		let circuit = VACircuit::new(
			public_amount.clone(),
			ext_data_hash.clone(),
			leaf_privates,
			private_keys,
			leaf_public,
			set_private_inputs,
			root_set.clone(),
			params2,
			params4,
			params5,
			paths,
			indices,
			nullifier_hash.clone(),
			out_commitment.clone(),
			out_chain_id,
			out_amount,
			out_pubkey,
			out_blinding,
		);

		let mut public_inputs = Vec::new();
		public_inputs.push(chain_id);
		public_inputs.extend( nullifier_hash);
		public_inputs.extend(root_set);
		public_inputs.extend(out_commitment);
		public_inputs.push(public_amount);
		//public_inputs.push(ext_data_hash.recipient);
		//public_inputs.push(ext_data_hash.relayer);
		//public_inputs.push(ext_data_hash.fee);
		public_inputs.push(ext_data_hash.commitment);

		//let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), rng).unwrap();
		let pk = generate_random_parameters::<Bn254,_,_>(circuit.clone(), rng).unwrap();
		let proof = Groth16::<Bn254>::prove(&pk, circuit, rng).unwrap();
		let pvk = prepare_verifying_key(&pk.vk);
		//let res = Groth16::<Bn254>::verify(&vk, &public_inputs, &proof).unwrap();
		let res =     verify_proof(&pvk, &proof, &public_inputs).unwrap();
		assert!(res);
	}
}
