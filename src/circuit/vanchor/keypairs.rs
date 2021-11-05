use crate::leaf::{NewLeafCreation, NewLeafCreationGadget, newleaf};
use ark_crypto_primitives::{CRH, CRHGadget};
use ark_ff::{fields::PrimeField, to_bytes};
use ark_r1cs_std::{ToBytesGadget, fields::fp::FpVar, prelude::UInt8};
use ark_std::marker::PhantomData;

#[derive(Default, Clone)]
pub struct Keypairs<H: CRH, F: PrimeField> {
	pubkey: <H as CRH>::Output,
	data: PhantomData<F>,
}
impl<H: CRH, F: PrimeField> Keypairs<H, F> {
	pub fn public_key(h: H::Parameters, secrets: newleaf::Private<F>) -> Self {
		let bytes = to_bytes![secrets.priv_key].unwrap();
		let pubkey = H::evaluate(&h, &bytes).unwrap();
		Keypairs {
			pubkey,
			data: PhantomData,
		}
	}

}
//LG: NewLeafCreationGadget<F, H, HG, L>,



#[derive(Clone)]
pub struct KeypairsVar<H: CRH, HG: CRHGadget<H, F>,L: NewLeafCreation<H>,LG: NewLeafCreationGadget<F, H, HG, L>,
F: PrimeField> {
	pubkey_var: <HG as CRHGadget<H, F>>::OutputVar,
	privkey_var: FpVar<F>,
	_leaf_creation: PhantomData<L>,
	_leaf_creation_gadget: PhantomData<LG>,
}

impl <H: CRH, HG: CRHGadget<H, F>,L: NewLeafCreation<H>,LG: NewLeafCreationGadget<F, H, HG, L>,
F: PrimeField> KeypairsVar<H,HG,L,LG,F> {

	pub fn public_key_var(h: HG::ParametersVar, secrets: <LG as NewLeafCreationGadget<F, H, HG, L>>::PrivateVar) -> Self {
		let privkey_var = LG::get_privat_key(&secrets).unwrap();
		let mut bytes = Vec::<UInt8<F>>::new();
		bytes.extend(privkey_var.to_bytes().unwrap());
		let pubkey_var = HG::evaluate(&h, &bytes).unwrap();
		KeypairsVar {
			pubkey_var,
			privkey_var,
			_leaf_creation: PhantomData,
			_leaf_creation_gadget: PhantomData,
		}
	}
	
}