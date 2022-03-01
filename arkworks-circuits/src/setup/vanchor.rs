use crate::{
	circuit::vanchor::VAnchorCircuit as VACircuit,
	setup::common::{
		LeafCRHGadget, PoseidonCRH_x5_2, PoseidonCRH_x5_2Gadget, PoseidonCRH_x5_3Gadget,
		PoseidonCRH_x5_4, TreeConfig_x5, Tree_x5,
	},
};
use ark_bn254::Fr as Bn254Fr;
use ark_crypto_primitives::Error;
use ark_ff::PrimeField;
use ark_std::{error::Error as ArkError, rand::RngCore, rc::Rc, string::ToString, vec::Vec};
use arkworks_gadgets::{
	keypair::vanchor::Keypair,
	leaf::vanchor::{Private as LeafPrivateInput, Public as LeafPublicInput, VAnchorLeaf as Leaf},
	merkle_tree::Path,
};
use arkworks_utils::{
	poseidon::PoseidonParameters,
	utils::common::{
		setup_params_x5_2, setup_params_x5_3, setup_params_x5_4, setup_params_x5_5, Curve,
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

#[derive(Debug)]
pub enum UtxoError {
	NullifierNotCalculated,
}

impl core::fmt::Display for UtxoError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		let msg = match self {
			UtxoError::NullifierNotCalculated => "Nullifier not calculated".to_string(),
		};
		write!(f, "{}", msg)
	}
}

impl ArkError for UtxoError {}

#[derive(Clone, Copy)]
pub struct Utxo<F: PrimeField> {
	pub chain_id: F,
	pub amount: F,
	pub keypair: Keypair<F, PoseidonCRH_x5_2<F>>,
	pub leaf_private: LeafPrivateInput<F>,
	pub leaf_public: LeafPublicInput<F>,
	pub index: Option<F>,
	pub nullifier: Option<F>,
	pub commitment: F,
}

impl<F: PrimeField> Utxo<F> {
	pub fn new<R: RngCore>(
		chain_id: F,
		amount: F,
		index: Option<F>,
		private_key: Option<F>,
		blinding: Option<F>,
		params2: &PoseidonParameters<F>,
		params4: &PoseidonParameters<F>,
		params5: &PoseidonParameters<F>,
		rng: &mut R,
	) -> Result<Self, Error> {
		let blinding = blinding.unwrap_or(F::rand(rng));
		let private_input = LeafPrivateInput::<F>::new(amount, blinding);
		let public_input = LeafPublicInput::<F>::new(chain_id);

		let keypair = Keypair::new(private_key.unwrap_or(F::rand(rng)));
		let pub_key = keypair.public_key(params2)?;

		let leaf = Leaf::<F, PoseidonCRH_x5_4<F>>::create_leaf(
			&private_input,
			&public_input,
			&pub_key,
			&params5,
		)?;

		let nullifier = if index.is_some() {
			let i = index.unwrap();

			let signature = keypair.signature(&leaf, &i, params4)?;

			let nullifier =
				Leaf::<_, PoseidonCRH_x5_4<F>>::create_nullifier(&signature, &leaf, &params4, &i)?;

			Some(nullifier)
		} else {
			None
		};

		Ok(Self {
			chain_id,
			amount,
			keypair,
			leaf_private: private_input,
			leaf_public: public_input,
			index,
			nullifier,
			commitment: leaf,
		})
	}

	pub fn get_nullifier(&self) -> Result<F, Error> {
		self.nullifier
			.ok_or(UtxoError::NullifierNotCalculated.into())
	}
}

#[derive(Clone)]
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

	pub fn new_utxo<R: RngCore>(
		&self,
		chain_id: F,
		amount: F,
		index: Option<F>,
		secret_key: Option<F>,
		blinding: Option<F>,
		rng: &mut R,
	) -> Result<Utxo<F>, Error> {
		Utxo::new(
			chain_id,
			amount,
			index,
			secret_key,
			blinding,
			&self.params2,
			&self.params4,
			&self.params5,
			rng,
		)
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
		let public_amount = F::rand(rng);
		let ext_data_hash = F::rand(rng);
		let in_root_set = [F::rand(rng); M];
		let in_leaves = [F::rand(rng); INS].map(|x| vec![x]);
		let in_indices = [0; INS];

		let chain_id = F::rand(rng);
		let amount = F::rand(rng);
		let index = F::rand(rng);
		let secret_key = F::rand(rng);
		let blinding = F::rand(rng);

		let in_utxo = self.new_utxo(
			chain_id,
			amount,
			Some(index),
			Some(secret_key),
			Some(blinding),
			rng,
		)?;
		let in_utxos = [in_utxo; INS];
		let out_utxo = self.new_utxo(
			chain_id,
			amount,
			None,
			Some(secret_key),
			Some(blinding),
			rng,
		)?;
		let out_utxos = [out_utxo; OUTS];

		let (circuit, ..) = self.setup_circuit_with_utxos(
			public_amount,
			ext_data_hash,
			in_root_set,
			in_indices,
			in_leaves,
			in_utxos,
			out_utxos,
		)?;

		Ok(circuit)
	}

	pub fn setup_circuit_with_utxos(
		self,
		// External data
		public_amount: F,
		ext_data_hash: F,
		in_root_set: [F; M],
		in_indices: [u64; INS],
		in_leaves: [Vec<F>; INS],
		// Input transactions
		in_utxos: [Utxo<F>; INS],
		// Output transactions
		out_utxos: [Utxo<F>; OUTS],
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
		// Tree + set for proving input txos
		let in_indices_f = in_indices.map(|x| F::from(x));
		let mut in_paths = Vec::new();
		for i in 0..INS {
			let (in_path, _) = self.setup_tree(&in_leaves[i], in_indices[i])?;
			in_paths.push(in_path)
		}

		let circuit = self.setup_circuit(
			public_amount,
			ext_data_hash,
			in_utxos.clone(),
			in_indices_f,
			in_paths,
			in_root_set,
			out_utxos.clone(),
		)?;

		let in_nullifiers: Result<Vec<F>, Error> =
			in_utxos.iter().map(|x| x.get_nullifier()).collect();
		let out_nullifiers = out_utxos.iter().map(|x| x.commitment).collect::<Vec<F>>();
		let public_inputs = Self::construct_public_inputs(
			in_utxos[0].leaf_public.chain_id,
			public_amount,
			in_root_set.to_vec(),
			in_nullifiers?,
			out_nullifiers,
			ext_data_hash,
		);

		Ok((circuit, public_inputs))
	}

	pub fn setup_circuit(
		self,
		public_amount: F,
		arbitrary_data: F,
		// Input transactions
		in_utxos: [Utxo<F>; INS],
		// Data related to tree
		in_indicies: [F; INS],
		in_paths: Vec<Path<TreeConfig_x5<F>, TREE_DEPTH>>,
		in_root_set: [F; M],
		// Output transactions
		out_utxos: [Utxo<F>; OUTS],
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
		let in_nullifiers: Result<Vec<F>, Error> =
			in_utxos.iter().map(|x| x.get_nullifier()).collect();

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
			in_root_set,
			self.params2,
			self.params4,
			self.params5,
			in_paths,
			in_indicies.to_vec(),
			in_nullifiers?,
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

	pub fn setup_tree(
		&self,
		leaves: &[F],
		index: u64,
	) -> Result<(Path<TreeConfig_x5<F>, TREE_DEPTH>, F), Error> {
		let inner_params = Rc::new(self.params3.clone());
		let tree = Tree_x5::new_sequential(inner_params, Rc::new(()), &leaves.to_vec())?;
		let root = tree.root();
		let path = tree.generate_membership_proof::<TREE_DEPTH>(index);

		Ok((path, root.inner()))
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

	// NOTE: To be used for testing
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

		let mut root_set = Vec::new();
		for _ in 0..INS {
			root_set.push(pub_ins.pop().unwrap());
		}

		let chain_id = pub_ins.pop().unwrap();

		let mut out_commitments = Vec::new();
		for _ in 0..OUTS {
			out_commitments.push(pub_ins.pop().unwrap());
		}

		let mut in_nullifiers = Vec::new();
		for _ in 0..INS {
			in_nullifiers.push(pub_ins.pop().unwrap());
		}

		let ext_data_hash = pub_ins.pop().unwrap();
		let public_amount = pub_ins.pop().unwrap();

		Ok((
			chain_id,
			public_amount,
			root_set,
			in_nullifiers,
			out_commitments,
			ext_data_hash,
		))
	}
}

// const TREE_DEPTH: usize = 30;
// const M: usize = 2;
// const INS: usize = 2;
// const OUTS: usize = 2;
pub type VAnchorProverBn2542x2 = VAnchorProverSetup<Bn254Fr, 30, 2, 2, 2>;
