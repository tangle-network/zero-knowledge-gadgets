use crate::{
	circuit::vanchor::VAnchorCircuit as VACircuit,
	setup::common::{
		LeafCRHGadget, PoseidonCRH_x5_2, PoseidonCRH_x5_2Gadget, PoseidonCRH_x5_3Gadget,
		PoseidonCRH_x5_4, TreeConfig_x5, Tree_x5,
	},
};
use ark_bn254::Fr as Bn254Fr;
use ark_crypto_primitives::Error;
use ark_ff::{BigInteger, PrimeField};
use ark_std::{rand::RngCore, rc::Rc, vec::Vec};
use arkworks_gadgets::{
	arbitrary::vanchor_data::VAnchorArbitraryData,
	keypair::vanchor::Keypair,
	leaf::vanchor::{Private as LeafPrivateInput, Public as LeafPublicInput, VAnchorLeaf as Leaf},
	merkle_tree::Path,
	set::membership::{Private as SetPrivateInputs, SetMembership},
};
use arkworks_utils::{
	poseidon::PoseidonParameters,
	utils::{
		common::{
			setup_params_x5_2, setup_params_x5_3, setup_params_x5_4, setup_params_x5_5, Curve,
		},
		keccak_256, ExtData,
	},
};

pub fn get_hash_params<F: PrimeField>(
	curve: Curve,
) -> (
	PoseidonParameters<F>,
	PoseidonParameters<F>,
	PoseidonParameters<F>,
	PoseidonParameters<F>,
) {
	(
		setup_params_x5_2::<F>(curve),
		setup_params_x5_3::<F>(curve),
		setup_params_x5_4::<F>(curve),
		setup_params_x5_5::<F>(curve),
	)
}

#[derive(Clone)]
pub struct Utxo<F: PrimeField> {
	pub chain_id: F,
	pub amount: F,
	pub keypair: Keypair<F, PoseidonCRH_x5_2<F>>,
	pub leaf_private: LeafPrivateInput<F>,
	pub leaf_public: LeafPublicInput<F>,
	pub nullifier: F,
	pub commitment: F,
}

pub struct VAnchorProverSetup<
	F: PrimeField,
	const TREE_DEPTH: usize,
	const M: usize,
	const INS: usize,
	const OUTS: usize,
> {
	params2: PoseidonParameters<F>,
	params3: PoseidonParameters<F>,
	params4: PoseidonParameters<F>,
	params5: PoseidonParameters<F>,
}

impl<
		F: PrimeField,
		const TREE_DEPTH: usize,
		const M: usize,
		const INS: usize,
		const OUTS: usize,
	> VAnchorProverSetup<F, TREE_DEPTH, M, INS, OUTS>
{
	pub fn new(
		params2: PoseidonParameters<F>,
		params3: PoseidonParameters<F>,
		params4: PoseidonParameters<F>,
		params5: PoseidonParameters<F>,
	) -> Self {
		Self {
			params2,
			params3,
			params4,
			params5,
		}
	}

	pub fn new_utxos<R: RngCore, const N: usize>(
		&self,
		chain_ids: [u128; N],
		amounts: [u128; N],
		rng: &mut R,
	) -> Result<Vec<Utxo<F>>, Error> {
		let chain_ids_f = chain_ids.map(|x| F::from(x));
		let amounts_f = amounts.map(|x| F::from(x));

		let keypairs = Self::setup_keypairs::<_, N>(rng);
		let (commitments, nullifiers, leaf_privates, leaf_publics) =
			self.setup_leaves(&chain_ids_f, &amounts_f, &keypairs, rng)?;

		let utxos: Vec<Utxo<F>> = (0..N)
			.map(|i| Utxo {
				chain_id: chain_ids_f[i],
				amount: amounts_f[i],
				keypair: keypairs[i].clone(),
				leaf_private: leaf_privates[i].clone(),
				leaf_public: leaf_publics[i].clone(),
				nullifier: nullifiers[i],
				commitment: commitments[i],
			})
			.collect();

		Ok(utxos)
	}

	pub fn new_utxos_f<R: RngCore, const N: usize>(
		&self,
		chain_ids_f: [F; N],
		amounts_f: [F; N],
		rng: &mut R,
	) -> Result<Vec<Utxo<F>>, Error> {
		let keypairs = Self::setup_keypairs::<_, N>(rng);
		let (commitments, nullifiers, leaf_privates, leaf_publics) =
			self.setup_leaves(&chain_ids_f, &amounts_f, &keypairs, rng)?;

		let utxos: Vec<Utxo<F>> = (0..N)
			.map(|i| Utxo {
				chain_id: chain_ids_f[i],
				amount: amounts_f[i],
				keypair: keypairs[i].clone(),
				leaf_private: leaf_privates[i].clone(),
				leaf_public: leaf_publics[i].clone(),
				nullifier: nullifiers[i],
				commitment: commitments[i],
			})
			.collect();

		Ok(utxos)
	}

	pub fn setup_random_circuit<R: RngCore>(
		self,
		rng: &mut R,
	) -> Result<
		VACircuit<
			F,
			PoseidonCRH_x5_2<F>,
			PoseidonCRH_x5_2Gadget<F>,
			TreeConfig_x5<F>,
			LeafCRHGadget<F>,
			PoseidonCRH_x5_3Gadget<F>,
			TREE_DEPTH,
			INS,
			OUTS,
			M,
		>,
		Error,
	> {
		let public_amount = rng.next_u64() as i128;

		let mut recipient = [0u8; 20];
		rng.fill_bytes(&mut recipient);

		let mut relayer = [0u8; 20];
		rng.fill_bytes(&mut relayer);

		let ext_amount = rng.next_u64() as i128;
		let fee = rng.next_u64() as u128;

		let in_chain_id = rng.next_u64() as u128;
		let in_amounts = [rng.next_u64() as u128; INS];
		let out_chain_ids = [rng.next_u64() as u128; OUTS];
		let out_amounts = [rng.next_u64() as u128; OUTS];

		let (circuit, ..) = self.setup_circuit_with_data(
			public_amount,
			recipient.to_vec(),
			relayer.to_vec(),
			ext_amount,
			fee,
			in_chain_id,
			in_amounts,
			out_chain_ids,
			out_amounts,
			rng,
		)?;

		Ok(circuit)
	}

	pub fn setup_circuit_with_utxos(
		self,
		// External data
		public_amount: i128,
		recipient: Vec<u8>,
		relayer: Vec<u8>,
		ext_amount: i128,
		fee: u128,
		// Input transactions
		in_utxos: Vec<Utxo<F>>,
		// Output transactions
		out_utxos: Vec<Utxo<F>>,
	) -> Result<
		(
			VACircuit<
				F,
				PoseidonCRH_x5_2<F>,
				PoseidonCRH_x5_2Gadget<F>,
				TreeConfig_x5<F>,
				LeafCRHGadget<F>,
				PoseidonCRH_x5_3Gadget<F>,
				TREE_DEPTH,
				INS,
				OUTS,
				M,
			>,
			Vec<F>,
		),
		Error,
	> {
		assert_eq!(in_utxos.len(), INS);
		assert_eq!(out_utxos.len(), OUTS);
		// Tree + set for proving input txos
		let in_commitments = in_utxos.iter().map(|x| x.commitment).collect::<Vec<F>>();
		let (in_indices, in_paths, in_set_private_inputs, in_root_set) =
			self.setup_tree_and_set(&in_commitments[..])?;

		let ext_data = ExtData::new(
			recipient,
			relayer,
			ext_amount.to_le_bytes().to_vec(),
			fee.to_le_bytes().to_vec(),
			out_utxos[0].commitment.into_repr().to_bytes_le(),
			out_utxos[1].commitment.into_repr().to_bytes_le(),
		);
		let ext_data_hash = keccak_256(&ext_data.encode_abi());
		let ext_data_hash_f = F::from_le_bytes_mod_order(&ext_data_hash);
		// Arbitrary data
		let arbitrary_data = Self::setup_arbitrary_data(ext_data_hash_f);

		let mut public_amount_f = F::from(public_amount.unsigned_abs());
		if public_amount.is_negative() {
			public_amount_f = -public_amount_f;
		}

		let circuit = self.setup_circuit(
			public_amount_f,
			arbitrary_data,
			in_utxos.clone(),
			in_indices,
			in_paths,
			in_set_private_inputs,
			in_root_set,
			out_utxos.clone(),
		)?;

		let in_nullifiers = in_utxos.iter().map(|x| x.nullifier).collect::<Vec<F>>();
		let out_nullifiers = out_utxos.iter().map(|x| x.commitment).collect::<Vec<F>>();
		let public_inputs = Self::construct_public_inputs(
			in_utxos[0].leaf_public.chain_id,
			public_amount_f,
			in_root_set.to_vec(),
			in_nullifiers,
			out_nullifiers,
			ext_data_hash_f,
		);

		Ok((circuit, public_inputs))
	}

	// This function is used only for first transaction, when the tree is empty
	pub fn setup_circuit_with_data<R: RngCore>(
		self,
		public_amount: i128,
		recipient: Vec<u8>,
		relayer: Vec<u8>,
		ext_amount: i128,
		fee: u128,
		in_chain_id: u128,
		in_amounts: [u128; INS],
		out_chain_ids: [u128; OUTS],
		out_amounts: [u128; OUTS],
		rng: &mut R,
	) -> Result<
		(
			VACircuit<
				F,
				PoseidonCRH_x5_2<F>,
				PoseidonCRH_x5_2Gadget<F>,
				TreeConfig_x5<F>,
				LeafCRHGadget<F>,
				PoseidonCRH_x5_3Gadget<F>,
				TREE_DEPTH,
				INS,
				OUTS,
				M,
			>,
			Vec<F>,
			Vec<Utxo<F>>,
			Vec<Utxo<F>>,
		),
		Error,
	> {
		// Making a vec of same chain ids to be passed into setup_leaves
		let in_chain_ids = [in_chain_id; INS];

		// Input leaves (txos)
		let in_utxos = self.new_utxos(in_chain_ids, in_amounts, rng)?;

		// Output leaves (txos)
		let out_utxos = self.new_utxos(out_chain_ids, out_amounts, rng)?;

		let (circuit, public_inputs) = self.setup_circuit_with_utxos(
			public_amount,
			recipient,
			relayer,
			ext_amount,
			fee,
			in_utxos.clone(),
			out_utxos.clone(),
		)?;

		Ok((circuit, public_inputs, in_utxos, out_utxos))
	}

	pub fn setup_circuit(
		self,
		public_amount: F,
		arbitrary_data: VAnchorArbitraryData<F>,
		// Input transactions
		in_utxos: Vec<Utxo<F>>,
		// Data related to tree
		in_indicies: Vec<F>,
		in_paths: Vec<Path<TreeConfig_x5<F>, TREE_DEPTH>>,
		in_set_private_inputs: Vec<SetPrivateInputs<F, M>>,
		in_root_set: [F; M],
		// Output transactions
		out_utxos: Vec<Utxo<F>>,
	) -> Result<
		VACircuit<
			F,
			PoseidonCRH_x5_2<F>,
			PoseidonCRH_x5_2Gadget<F>,
			TreeConfig_x5<F>,
			LeafCRHGadget<F>,
			PoseidonCRH_x5_3Gadget<F>,
			TREE_DEPTH,
			INS,
			OUTS,
			M,
		>,
		Error,
	> {
		let in_leaf_private_inputs = in_utxos
			.iter()
			.map(|x| x.leaf_private.clone())
			.collect::<Vec<LeafPrivateInput<F>>>();
		let in_keypair_inputs = in_utxos
			.iter()
			.map(|x| x.keypair.clone())
			.collect::<Vec<Keypair<F, PoseidonCRH_x5_2<F>>>>();
		let in_nullifiers = in_utxos.iter().map(|x| x.nullifier).collect::<Vec<F>>();

		let out_pub_keys: Result<Vec<F>, _> = out_utxos
			.iter()
			.map(|x| x.keypair.public_key(&self.params2))
			.collect();
		let out_commitments = out_utxos.iter().map(|x| x.commitment).collect::<Vec<F>>();
		let out_leaf_private = out_utxos
			.iter()
			.map(|x| x.leaf_private.clone())
			.collect::<Vec<LeafPrivateInput<F>>>();
		let out_leaf_public = out_utxos
			.iter()
			.map(|x| x.leaf_public.clone())
			.collect::<Vec<LeafPublicInput<F>>>();
		let circuit = VACircuit::<
			F,
			PoseidonCRH_x5_2<F>,
			PoseidonCRH_x5_2Gadget<F>,
			TreeConfig_x5<F>,
			LeafCRHGadget<F>,
			PoseidonCRH_x5_3Gadget<F>,
			TREE_DEPTH,
			INS,
			OUTS,
			M,
		>::new(
			public_amount,
			arbitrary_data,
			in_leaf_private_inputs,
			in_keypair_inputs,
			in_utxos[0].leaf_public.clone(),
			in_set_private_inputs,
			in_root_set,
			self.params2,
			self.params4,
			self.params5,
			in_paths,
			in_indicies,
			in_nullifiers,
			out_commitments,
			out_leaf_private,
			out_leaf_public,
			out_pub_keys?,
		);

		Ok(circuit)
	}

	pub fn setup_keypairs<R: RngCore, const N: usize>(
		rng: &mut R,
	) -> [Keypair<F, PoseidonCRH_x5_2<F>>; N] {
		[(); N].map(|_| Keypair::<_, PoseidonCRH_x5_2<F>>::new(F::rand(rng)))
	}

	pub fn setup_leaves<R: RngCore, const N: usize>(
		&self,
		chain_ids: &[F; N],
		amounts: &[F; N],
		keypairs: &[Keypair<F, PoseidonCRH_x5_2<F>>; N],
		rng: &mut R,
	) -> Result<
		(
			[F; N],
			[F; N],
			[LeafPrivateInput<F>; N],
			[LeafPublicInput<F>; N],
		),
		Error,
	> {
		let num_inputs = amounts.len();

		let mut leaves = [F::default(); N];
		let mut nullifiers = [F::default(); N];
		let mut private_inputs = [LeafPrivateInput::<F>::default(); N];
		let mut public_inputs = [LeafPublicInput::<F>::default(); N];

		for i in 0..num_inputs {
			let chain_id = F::from(chain_ids[i]);
			let amount = F::from(amounts[i]);
			let blinding = F::rand(rng);
			let index = F::from(i as u64);

			let private_input = LeafPrivateInput::<F>::new(amount, blinding);
			let public_input = LeafPublicInput::<F>::new(chain_id);

			let pub_key = keypairs[i].public_key(&self.params2)?;

			let leaf = Leaf::<F, PoseidonCRH_x5_4<F>>::create_leaf(
				&private_input,
				&public_input,
				&pub_key,
				&self.params5,
			)?;

			let signature = keypairs[i].signature(&leaf, &index, &self.params4)?;

			let nullifier = Leaf::<F, PoseidonCRH_x5_4<F>>::create_nullifier(
				&signature,
				&leaf,
				&self.params4,
				&index,
			)?;

			leaves[i] = leaf;
			nullifiers[i] = nullifier;
			private_inputs[i] = private_input;
			public_inputs[i] = public_input;
		}

		Ok((leaves, nullifiers, private_inputs, public_inputs))
	}

	pub fn setup_tree(
		&self,
		leaves: &[F],
	) -> Result<(Vec<Path<TreeConfig_x5<F>, TREE_DEPTH>>, Vec<F>, F), Error> {
		let inner_params = Rc::new(self.params3.clone());
		let tree = Tree_x5::new_sequential(inner_params, Rc::new(()), &leaves.to_vec())?;
		let root = tree.root();

		let num_leaves = leaves.len();

		let mut paths = Vec::new();
		let mut indices = Vec::new();
		for i in 0..num_leaves {
			let path = tree.generate_membership_proof::<TREE_DEPTH>(i as u64);
			let index = path.get_index(&root, &leaves[i])?;
			paths.push(path);
			indices.push(index);
		}

		Ok((paths, indices, root.inner()))
	}

	pub fn setup_root_set(root: F) -> Result<([F; M], Vec<SetPrivateInputs<F, M>>), Error> {
		let root_set = [root.clone(); M];

		let mut set_private_inputs = Vec::new();
		for _ in 0..M {
			let set_private_input = SetMembership::generate_secrets(&root, &root_set)?;
			set_private_inputs.push(set_private_input);
		}

		Ok((root_set, set_private_inputs))
	}

	pub fn setup_tree_and_set(
		&self,
		leaves: &[F],
	) -> Result<
		(
			Vec<F>,
			Vec<Path<TreeConfig_x5<F>, TREE_DEPTH>>,
			Vec<SetPrivateInputs<F, M>>,
			[F; M],
		),
		Error,
	> {
		let (paths, indices, root) = self.setup_tree(&leaves)?;
		let (root_set, set_private_inputs) = Self::setup_root_set(root)?;
		Ok((indices, paths, set_private_inputs, root_set))
	}

	pub fn construct_public_inputs(
		chain_id: F,
		public_amount: F,
		roots: Vec<F>,
		nullifiers: Vec<F>,
		commitments: Vec<F>,
		ext_data_hash: F,
	) -> Vec<F> {
		let mut public_inputs = vec![public_amount, ext_data_hash];
		public_inputs.extend(nullifiers);
		public_inputs.extend(commitments);
		public_inputs.push(chain_id);
		public_inputs.extend(roots);

		public_inputs
	}

	// TODO: Fix to match INS and OUTS
	pub fn deconstruct_public_inputs(
		public_inputs: Vec<F>,
	) -> Result<
		(
			F,      // Chain Id
			F,      // Public amount
			Vec<F>, // Roots
			Vec<F>, // Input tx Nullifiers
			Vec<F>, // Output tx commitments
			F,      // External data hash
		),
		Error,
	> {
		let mut pub_ins = public_inputs;

		let err = "Invalid public inputs";

		let mut root_set = Vec::new();
		for _ in 0..INS {
			root_set.push(pub_ins.pop().ok_or(err)?);
		}

		let chain_id = pub_ins.pop().ok_or(err)?;

		let mut out_commitments = Vec::new();
		for _ in 0..OUTS {
			out_commitments.push(pub_ins.pop().ok_or(err)?);
		}

		let mut in_nullifiers = Vec::new();
		for _ in 0..INS {
			in_nullifiers.push(pub_ins.pop().ok_or(err)?);
		}

		let ext_data_hash = pub_ins.pop().ok_or(err)?;
		let public_amount = pub_ins.pop().ok_or(err)?;

		Ok((
			chain_id,
			public_amount,
			root_set,
			in_nullifiers,
			out_commitments,
			ext_data_hash,
		))
	}

	pub fn setup_arbitrary_data(ext_data: F) -> VAnchorArbitraryData<F> {
		VAnchorArbitraryData::new(ext_data)
	}
}

// const TREE_DEPTH: usize = 30;
// const M: usize = 2;
// const INS: usize = 2;
// const OUTS: usize = 2;
pub type VAnchorProverBn2542x2 = VAnchorProverSetup<Bn254Fr, 30, 2, 2, 2>;

// For backwards compatability
// TODO: remove later
pub fn setup_vanchor_arbitrary_data<F: PrimeField>(ext_data: F) -> VAnchorArbitraryData<F> {
	VAnchorArbitraryData::new(ext_data)
}
