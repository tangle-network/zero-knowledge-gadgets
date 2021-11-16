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
	path: Vec<Path<C, N>>,
	index: Vec<F>, // TODO: Temporary, we may need to compute it from path
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

impl<F, H2, HG2, H4, HG4, H5, HG5, C, LHGT, HGT, const N: usize, const M: usize>
	VAnchorCircuit<F, H2, HG2, H4, HG4, H5, HG5, C, LHGT, HGT, N, M>
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
		path: Vec<Path<C, N>>,
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
		in_path_elements_var: &Vec<PathVar<F, C, HGT, LHGT, N>>,
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
			inkeypair[tx] =
				KeypairVar::<F, H2, HG2, H4, HG4, H5, HG5>::new(&private_key_inputs_var[tx])
					.unwrap();

			// Computing the hash
			// TODO: Remove private key from Private and fed it here as input using
			// keypairs:
			in_utxo_hasher_var[tx] =
				VAnchorLeafGadget::<F, H2, HG2, H4, HG4, H5, HG5>::create_leaf(
					//<FpVar<F>>
					&leaf_private_var[tx],
					&inkeypair[tx].public_key(hasher_params_w2_var).unwrap(),
					&leaf_public_var,
					&hasher_params_w5_var,
				)?;
			// End of computing the hash

			// Nullifier
			nullifier_hash[tx] =
				VAnchorLeafGadget::<F, H2, HG2, H4, HG4, H5, HG5>::create_nullifier(
					&inkeypair[tx].private_key().unwrap(),
					&in_utxo_hasher_var[tx],
					&hasher_params_w4_var,
					&in_path_indices_var[tx],
				)?;

			nullifier_hash[tx].enforce_equal(&in_nullifier_var[tx])?;
			// add the roots and diffs signals to the vanchor circuit
			// TODO:
			let roothash =
				PathVar::root_hash(&in_path_elements_var[tx], &in_utxo_hasher_var[tx]).unwrap();
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
			sums_ins_var = sums_ins_var + in_amount_tx; // TODo: inamount
		}
		Ok(sums_ins_var)
	}

	//TODO: Verify correctness of transaction outputs
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
			in_utxo_hasher_var_out[tx] = HG5::evaluate(&hasher_params_w5_var, &bytes)?;
			// End of computing the hash
			in_utxo_hasher_var_out[tx].enforce_equal(&output_commitment_var[tx])?;

			// Check that amount is less than 2^248 in the field (to prevent overflow)
			out_amount_var[tx].enforce_cmp_unchecked(&limit_var, Less, false)?;

			sums_outs_var = sums_outs_var + out_amount_var[tx].clone();
			//...
		}
		Ok(sums_outs_var)
	}

	//TODO: Check that there are no same nullifiers among all inputs
	pub fn verify_no_same_nul(
		&self,
		in_nullifier_var: &Vec<HG4::OutputVar>,
	) -> Result<(), SynthesisError> {
		let mut same_nullifiers: Vec<HG4::OutputVar> = Vec::with_capacity(2);
		for i in 0..N {
			for j in i..N {
				same_nullifiers[0] = in_nullifier_var[i].clone();
				same_nullifiers[1] = in_nullifier_var[j].clone();
				same_nullifiers[0].enforce_not_equal(&same_nullifiers[1])?;
			}
		}
		Ok(())
	}

	//TODO: Verify amount invariant
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

impl<F, H2, HG2, H4, HG4, H5, HG5, C, LHGT, HGT, const N: usize, const M: usize> Clone
	for VAnchorCircuit<F, H2, HG2, H4, HG4, H5, HG5, C, LHGT, HGT, N, M>
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

impl<F, H2, HG2, H4, HG4, H5, HG5, C, LHGT, HGT, const N: usize, const M: usize>
	ConstraintSynthesizer<F> for VAnchorCircuit<F, H2, HG2, H4, HG4, H5, HG5, C, LHGT, HGT, N, M>
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
		let set_private = self.set_private_inputs.clone(); // TODO
		let root_set = self.root_set.clone(); // TODO
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

		let mut in_path_elements_var: Vec<PathVar<F, C, HGT, LHGT, N>> = Vec::with_capacity(N);
		let mut in_path_indices_var: Vec<FpVar<F>> = Vec::with_capacity(N);

		// Outputs
		let mut out_amount_var: Vec<FpVar<F>> = Vec::with_capacity(N);
		let mut out_chain_id_var: Vec<FpVar<F>> = Vec::with_capacity(N);
		let mut out_pubkey_var: Vec<FpVar<F>> = Vec::with_capacity(N);
		let mut out_blinding_var: Vec<FpVar<F>> = Vec::with_capacity(N);
		let mut output_commitment_var: Vec<HG5::OutputVar> = Vec::with_capacity(N);

		for i in 0..N {
			set_input_private_var[i] =
				SetPrivateInputsVar::new_witness(cs.clone(), || Ok(set_private[i].clone()))?;

			private_key_inputs_var[i] =
				FpVar::<F>::new_witness(cs.clone(), || Ok(private_key_inputs[i].clone()))?;

			leaf_private_var[i] =
				LeafPrivateInputsVar::new_input(cs.clone(), || Ok(leaf_private[i].clone()))?;
			in_nullifier_var[i] =
				HG4::OutputVar::new_input(cs.clone(), || Ok(nullifier_hash[i].clone()))?;

			in_path_elements_var[i] =
				PathVar::<F, C, HGT, LHGT, N>::new_witness(cs.clone(), || Ok(path[i].clone()))?;
			in_path_indices_var[i] = FpVar::<F>::new_witness(cs.clone(), || Ok(index[i].clone()))?;

			out_amount_var[i] = FpVar::<F>::new_witness(cs.clone(), || Ok(out_amount[i].clone()))?;
			out_chain_id_var[i] =
				FpVar::<F>::new_witness(cs.clone(), || Ok(out_chain_id[i].clone()))?;
			out_pubkey_var[i] = FpVar::<F>::new_witness(cs.clone(), || Ok(out_pubkey[i].clone()))?;
			out_blinding_var[i] =
				FpVar::<F>::new_witness(cs.clone(), || Ok(out_blinding[i].clone()))?;
			output_commitment_var[i] =
				HG5::OutputVar::new_witness(cs.clone(), || Ok(output_commitment[i].clone()))?;
		}

		//TODO: Change this one
		// let key_pairs_inputs_var: Vec<KeypairVar<F, H2, HG2, H4, HG4, H5, HG5>> =
		// 	Vec::with_capacity(N);

		// verify correctness of transaction inputs
		let sum_ins_var = self
			.verify_input_var(
				&hasher_params_w2_var,
				&hasher_params_w4_var,
				&hasher_params_w5_var,
				&leaf_private_var,
				&private_key_inputs_var,
				&leaf_public_var,
				//&key_pairs_inputs_var,
				&in_path_indices_var,
				&in_path_elements_var,
				&in_nullifier_var,
				&root_set_var,
				&set_input_private_var,
			)
			.unwrap();

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

		// check that there are no same nullifiers among all inputs
		self.verify_no_same_nul(&in_nullifier_var).unwrap();

		// verify amount invariant
		self.verify_input_invariant(&public_amount_var, &sum_ins_var, &sum_outs_var)
			.unwrap();
		// Check if target root is in set

		// optional safety constraint to make sure extDataHash cannot be changed
		ArbitraryInputVar::constrain(&arbitrary_input_var)?;

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
	use std::str::FromStr;

	pub const TEST_N: usize = 30;
	pub const TEST_M: usize = 1;

	#[derive(Default, Clone)]
	struct PoseidonRounds2;

	impl Rounds for PoseidonRounds2 {
		const FULL_ROUNDS: usize = 8;
		const PARTIAL_ROUNDS: usize = 57;
		const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
		const WIDTH: usize = 2;
	}

	#[derive(Default, Clone)]
	struct PoseidonRounds4;

	impl Rounds for PoseidonRounds4 {
		const FULL_ROUNDS: usize = 8;
		const PARTIAL_ROUNDS: usize = 59;
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

	#[should_panic]
	#[test]
	fn should_fail_with_invalid_root() {
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
		let commitment = BnFr::rand(rng); //TODO: Change to VanchorLeaf
		let leaf_private = LeafPrivateInputs::<BnFr>::generate(rng);
		let leaf_public = LeafPublicInputs::<BnFr>::new(chain_id);
		let private_key = BnFr::rand(rng);
		let privkey = to_bytes![private_key].unwrap();
		let public_key = PoseidonCRH2::evaluate(&params2, &privkey).unwrap();
		let leaf = Leaf::create_leaf(&leaf_private, &public_key, &leaf_public, &params2).unwrap();

		let (tree, path) = setup_tree_and_create_path_tree_x5::<BnFr, TEST_N>(&[leaf], 0, &params3);
		let public_amount = BnFr::rand(rng);
		//TODO: Change aritrary data
		let ext_data_hash = setup_arbitrary_data(recipient, relayer, fee, refund, commitment);
		let root = BnFr::rand(rng);
		let root_set = [root; TEST_M];
		let leaves = vec![leaf, BnFr::rand(rng), BnFr::rand(rng)];
		let index: BnFr = path.get_index(&tree.root(), &leaves[0 as usize]).unwrap();
		let nullifier_hash = Leaf::create_nullifier(&private_key, &leaf, &params4, &index).unwrap();
		let set_private_inputs = setup_set(&root, &root_set);

		let out_chain_id = BnFr::one();
		let out_amount = BnFr::one() + BnFr::one();
		let out_pubkey = BnFr::rand(rng);
		let out_blinding = BnFr::rand(rng);
		let bytes = to_bytes![out_chain_id, out_amount, out_pubkey, out_blinding].unwrap();
		let out_commitment = PoseidonCRH5::evaluate(&params4, &bytes).unwrap();

		let circuit = VACircuit::new(
			public_amount,
			ext_data_hash.clone(),
			vec![leaf_private],
			vec![private_key],
			leaf_public,
			vec![set_private_inputs],
			root_set,
			params2,
			params4,
			params5,
			vec![path],
			vec![index],
			vec![nullifier_hash],
			vec![out_commitment],
			vec![out_chain_id],
			vec![out_chain_id],
			vec![out_pubkey],
			vec![out_blinding],
		);

		let mut public_inputs = Vec::new();
		public_inputs.push(chain_id);
		public_inputs.push(nullifier_hash);
		public_inputs.extend(&root_set);
		public_inputs.push(root);
		public_inputs.push(ext_data_hash.recipient);
		public_inputs.push(ext_data_hash.relayer);
		public_inputs.push(ext_data_hash.fee);
		public_inputs.push(ext_data_hash.commitment);
		let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), rng).unwrap();
		//let pk = generate_random_parameters::<Bn254,_,_>(circuit.clone(),&mut
		// rng).unwrap();
		let proof = Groth16::<Bn254>::prove(&pk, circuit, rng).unwrap();
		//let vk = prepare_verifying_key(&pk.vk);
		let res = Groth16::<Bn254>::verify(&vk, &public_inputs, &proof).unwrap();
		assert!(res);
	}
}
