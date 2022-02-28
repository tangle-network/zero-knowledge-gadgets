use ark_ec::PairingEngine;
use ark_ff::{PrimeField, BigInteger};
use arkworks_gadgets::{poseidon::{field_hasher::{Poseidon, FieldHasher}, constraints::CRHGadget, CRH}};
use ark_bn254::{Fr as Bn254Fr, Bn254};
use ark_std::UniformRand;
use ark_crypto_primitives::Error;
use ark_std::{
    collections::BTreeMap,
    marker::PhantomData,
	rand::{CryptoRng, RngCore},
	vec::Vec,
    rc::Rc,
};
use arkworks_circuits::{setup::common::MixerProof, circuit::mixer::MixerCircuit};
use arkworks_circuits::setup::common::Leaf;
use arkworks_utils::utils::common::{Curve, setup_params_x5_5, setup_params_x5_3};

use arkworks_gadgets::{
    identity::{constraints::CRHGadget as IdentityCRHGadget, CRH as IdentityCRH},
	arbitrary::mixer_data::Input as MixerDataInput,
	leaf::mixer::Private,
	merkle_tree::{Config as MerkleConfig, SparseMerkleTree, Path},
};

use crate::MixerProver;

pub fn create_leaf<F: PrimeField, H: FieldHasher<F>>(hasher: &H, private: &Private<F>) -> Result<F, Error> {
    let leaf = hasher.hash_two(&private.secret(), &private.nullifier())?;
    Ok(leaf)
}

pub fn create_nullifier<F: PrimeField, H: FieldHasher<F>>(hasher: &H, private: &Private<F>) -> Result<F, Error> {
    let nullifier_hash = hasher.hash_two(&private.nullifier(), &private.nullifier())?;
    Ok(nullifier_hash)
}

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

pub type MixerConstraintDataInput<F> = MixerDataInput<F>;

pub fn setup_arbitrary_data<F: PrimeField>(
    recipient: F,
    relayer: F,
    fee: F,
    refund: F,
) -> MixerConstraintDataInput<F> {
    MixerConstraintDataInput::new(recipient, relayer, fee, refund)
}

pub type LeafCRH<F> = IdentityCRH<F>;
pub type LeafCRHGadget<F> = IdentityCRHGadget<F>;

pub type PoseidonCRH_x5_3<F> = CRH<F>;
pub type PoseidonCRH_x5_3Gadget<F> = CRHGadget<F>;

pub type PoseidonCRH_x5_5<F> = CRH<F>;
pub type PoseidonCRH_x5_5Gadget<F> = CRHGadget<F>;

#[derive(Clone, PartialEq)]
pub struct TreeConfig_x5<F: PrimeField>(PhantomData<F>);
impl<F: PrimeField> MerkleConfig for TreeConfig_x5<F> {
	type H = PoseidonCRH_x5_3<F>;
	type LeafH = LeafCRH<F>;

	const HEIGHT: u8 = 30;
}

pub type Circuit_x5<F, const N: usize> = MixerCircuit<
	F,
	PoseidonCRH_x5_5<F>,
	PoseidonCRH_x5_5Gadget<F>,
	TreeConfig_x5<F>,
	LeafCRHGadget<F>,
	PoseidonCRH_x5_3Gadget<F>,
	N,
>;

struct MixerR1CSProver<E: PairingEngine, H: FieldHasher<E::Fr>, const HEIGHT: usize> {
    engine: PhantomData<E>,
    hasher: H,
    default_leaf: [u8; 32],
}

pub type SMT<F, H, const HEIGHT: usize> = SparseMerkleTree::<F, H, HEIGHT>;

impl<E: PairingEngine, H: FieldHasher<E::Fr>, const HEIGHT: usize> MixerR1CSProver<E, H, HEIGHT> {
    pub fn setup_tree_and_create_path(
		&self,
		leaves: &[E::Fr],
		index: u64,
	) -> Result<(SMT<E::Fr, H, HEIGHT>, Path<E::Fr, H, HEIGHT>), Error> {
		// Making the merkle tree
		let smt = create_merkle_tree::<E::Fr, H, HEIGHT>(
            self.hasher,
            leaves,
            &self.default_leaf
        );
		// Getting the proof path
		let path = smt.generate_membership_proof(index);
		Ok((smt, path))
	}
}



impl<E: PairingEngine, H: FieldHasher<E::Fr>, const HEIGHT: usize> MixerProver<E, H, HEIGHT> for MixerR1CSProver<E, H, HEIGHT> {
    fn create_leaf_with_privates<R: RngCore + CryptoRng>(
        &self,
        curve: Curve,
        secret: Option<Vec<u8>>,
        nullifier: Option<Vec<u8>>,
        rng: &mut R,
    ) -> Result<Leaf, Error> {
        let secret_field_elt: E::Fr = match secret {
            Some(secret) => E::Fr::from_le_bytes_mod_order(&secret),
            None => E::Fr::rand(rng),
        };
        let nullifier_field_elt: E::Fr = match nullifier {
            Some(nullifier) => E::Fr::from_le_bytes_mod_order(&nullifier),
            None => E::Fr::rand(rng),
        };

        let private: Private<E::Fr> = Private::new(secret_field_elt, nullifier_field_elt);
        let leaf_field_element = create_leaf(&self.hasher, &private)?;
        let nullifier_hash_field_element = create_nullifier(&self.hasher, &private)?;
        Ok(Leaf {
            secret_bytes: secret_field_elt.into_repr().to_bytes_le(),
            nullifier_bytes: nullifier_field_elt.into_repr().to_bytes_le(),
            leaf_bytes: leaf_field_element.into_repr().to_bytes_le(),
            nullifier_hash_bytes: nullifier_hash_field_element.into_repr().to_bytes_le(),
        })
    }

    fn create_proof<R: RngCore + CryptoRng>(
        &self,
        curve: Curve,
        secret: Vec<u8>,
        nullifier: Vec<u8>,
        leaves: Vec<Vec<u8>>,
        index: u64,
        recipient: Vec<u8>,
        relayer: Vec<u8>,
        fee: u128,
        refund: u128,
        pk: Vec<u8>,
        rng: &mut R,
    ) -> Result<MixerProof, Error> {
        let params3 = setup_params_x5_3::<E::Fr>(curve);
	    let params5 = setup_params_x5_5::<E::Fr>(curve);
        // Get field element version of all the data
        let secret_f = E::Fr::from_le_bytes_mod_order(&secret);
		let nullifier_f = E::Fr::from_le_bytes_mod_order(&nullifier);
		let leaves_f: Vec<E::Fr> = leaves
			.iter()
			.map(|x| E::Fr::from_le_bytes_mod_order(x))
			.collect();
		let recipient_f = E::Fr::from_le_bytes_mod_order(&recipient);
		let relayer_f = E::Fr::from_le_bytes_mod_order(&relayer);
		let fee_f = E::Fr::from(fee);
		let refund_f = E::Fr::from(refund);
        // Create the arbitrary input data
		let arbitrary_input = setup_arbitrary_data::<E::Fr>(
            recipient_f,
            relayer_f,
            fee_f,
            refund_f
        );
        // Generate the leaf
		let Leaf {
            secret_bytes,
            nullifier_bytes,
            leaf_bytes,
            nullifier_hash_bytes,
        } = self.create_leaf_with_privates(curve, Some(secret), Some(nullifier), rng)?;
        // Setup the tree and generate the path
		let (tree, path) = self.setup_tree_and_create_path(&leaves_f, index)?;
		let root = tree.root();

        let leaf_private = Private::new(secret_f, nullifier_f);
		let mc = Circuit_x5::new(
			arbitrary_input,
			leaf_private,
			params5,
			path,
			root,
			nullifier_hash,
		);
		let public_inputs =
			Self::construct_public_inputs(nullifier_hash, root, recipient, relayer, fee, refund);

		let leaf_raw = leaf.into_repr().to_bytes_le();
		let nullifier_hash_raw = nullifier_hash.into_repr().to_bytes_le();
		let root_raw = root.into_repr().to_bytes_le();
		let public_inputs_raw: Vec<Vec<u8>> = public_inputs
			.iter()
			.map(|x| x.into_repr().to_bytes_le())
			.collect();

        let proof = prove_unchecked::<E, _, _>(circuit, &pk, rng)?;


        todo!()
    }
}

type MixerR1CSProver_Bn254_Poseidon_30 = MixerR1CSProver<Bn254, Poseidon<Bn254Fr>, 30>;
