use std::marker::PhantomData;

use ark_crypto_primitives::{Error, CRH};
use ark_ff::{fields::PrimeField, to_bytes};

use crate::leaf::vanchor::{Private, VAnchorLeaf};
#[cfg(feature = "r1cs")]
pub mod constraints;

#[derive(Default, Clone)]
pub struct Keypair<F: PrimeField, H2: CRH, H4: CRH, H5: CRH>
{
	pubkey: <H2 as CRH>::Output,
	privkey: F,
	_h4: PhantomData<H4>,
	_h5: PhantomData<H5>,
}

impl<H2: CRH, H4: CRH, H5: CRH, F: PrimeField>
	 Keypair<F, H2, H4, H5>
{
	pub fn new(h: &H2::Parameters, secrets: &Private<F>) -> Result<Self, Error> {
		let privkey = VAnchorLeaf::<F, H2, H4, H5>::get_private_key(&secrets).unwrap();
		let bytes = to_bytes![privkey].unwrap();
		let pubkey = H2::evaluate(&h, &bytes).unwrap();
		Ok(Keypair {
			pubkey,
			privkey,
			_h4: PhantomData,
			_h5: PhantomData,
		})
	}

	pub fn public_key(&self) -> Result<<H2 as CRH>::Output, Error> {
		Ok(self.pubkey.clone())
	}

	pub fn private_key(&self) -> Result<F, Error> {
		Ok(self.privkey)
	}

	pub fn public_key_raw(h: &H2::Parameters, privkey: &F) -> Result<Self, Error> {
		let privkey = *privkey;
		let bytes = to_bytes![privkey].unwrap();
		let pubkey = H2::evaluate(&h, &bytes).unwrap();
		Ok(Keypair {
			pubkey,
			privkey,
			_h4: PhantomData,
			_h5: PhantomData,
		})
	}
}

#[cfg(feature = "default_poseidon")]
#[cfg(test)]
mod test {
	use crate::{leaf::vanchor::{Private, VAnchorLeaf}, poseidon::{sbox::PoseidonSbox, PoseidonParameters, Rounds, CRH}, utils::{
			get_mds_poseidon_bls381_x5_5, get_mds_poseidon_bn254_x5_2,
			get_rounds_poseidon_bls381_x5_5, get_rounds_poseidon_bn254_x5_2,
		}};
	use ark_bn254::Fq;
	use ark_crypto_primitives::crh::CRH as CRHTrait;
	use ark_ff::to_bytes;

	use ark_std::test_rng;

	use super::Keypair;

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

	type PoseidonCRH2 = CRH<Fq, PoseidonRounds2>;
	type PoseidonCRH4 = CRH<Fq, PoseidonRounds4>;
	type PoseidonCRH5 = CRH<Fq, PoseidonRounds5>;

	type Leaf = VAnchorLeaf<Fq, PoseidonCRH2, PoseidonCRH4, PoseidonCRH5>;
	#[test]
	fn should_crate_new_public_key() {
		let rng = &mut test_rng();

		let rounds = get_rounds_poseidon_bn254_x5_2::<Fq>();
		let mds = get_mds_poseidon_bn254_x5_2::<Fq>();
		let params = PoseidonParameters::<Fq>::new(rounds, mds);

		let secrets = Private::generate(rng);
		let prk = Leaf::get_private_key(&secrets).unwrap();
		let privkey = to_bytes![prk].unwrap();
		let pubkey = PoseidonCRH2::evaluate(&params, &privkey).unwrap();

		let keypair =
			Keypair::<Fq, PoseidonCRH2, PoseidonCRH4, PoseidonCRH5>::new(&params, &secrets)
				.unwrap();
		let new_pubkey = keypair.pubkey;

		assert_eq!(new_pubkey, pubkey)
	}
}
