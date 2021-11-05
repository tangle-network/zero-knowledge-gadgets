use crate::leaf::vanchor;
use ark_crypto_primitives::{Error, CRH};
use ark_ff::{fields::PrimeField, to_bytes};

#[derive(Default, Clone)]
pub struct Keypair<H: CRH, F: PrimeField> {
	pubkey: <H as CRH>::Output,
	privkey: F,
}

pub trait KeypairCreation<H: CRH, F: PrimeField>: Sized {
	fn new(h: &H::Parameters, secrets: &vanchor::Private<F>) -> Result<Self, Error>;
	fn public_key(&self) -> Result<<H as CRH>::Output, Error>;
	fn private_key(&self) -> Result<F, Error>;
	fn public_key_raw(h: &H::Parameters, secrets: &F) -> Result<Self, Error>;
}

impl<H: CRH, F: PrimeField> KeypairCreation<H, F> for Keypair<H, F> {
	fn new(h: &H::Parameters, secrets: &vanchor::Private<F>) -> Result<Self, Error> {
		let privkey = secrets.priv_key;
		let bytes = to_bytes![privkey].unwrap();
		let pubkey = H::evaluate(&h, &bytes).unwrap();
		Ok(Keypair { pubkey, privkey })
	}

	fn public_key(&self) -> Result<<H as CRH>::Output, Error> {
		Ok(self.pubkey.clone())
	}

	fn private_key(&self) -> Result<F, Error> {
		Ok(self.privkey)
	}

	fn public_key_raw(h: &H::Parameters, privkey: &F) -> Result<Self, Error> {
		let privkey = *privkey;
		let bytes = to_bytes![privkey].unwrap();
		let pubkey = H::evaluate(&h, &bytes).unwrap();
		Ok(Keypair { pubkey, privkey })
	}
}

#[cfg(feature = "default_poseidon")]
#[cfg(test)]
mod test {
	use crate::{
		leaf::{vanchor::VanchorLeaf, VanchorLeafCreation},
		poseidon::{sbox::PoseidonSbox, PoseidonParameters, Rounds, CRH},
		utils::{get_mds_poseidon_bls381_x5_5, get_rounds_poseidon_bls381_x5_5},
	};
	use ark_bls12_381::Fq;
	use ark_crypto_primitives::crh::CRH as CRHTrait;
	use ark_ff::to_bytes;

	use ark_std::test_rng;

	use super::{Keypair, KeypairCreation};
	#[derive(Default, Clone)]
	struct PoseidonRounds3;

	impl Rounds for PoseidonRounds3 {
		const FULL_ROUNDS: usize = 8;
		const PARTIAL_ROUNDS: usize = 57;
		const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
		const WIDTH: usize = 4;
	}

	type PoseidonCRH3 = CRH<Fq, PoseidonRounds3>;
	type Keypair1 = Keypair<PoseidonCRH3, Fq>;
	type Leaf = VanchorLeaf<Fq, PoseidonCRH3>;
	#[test]
	fn should_crate_new_public_key() {
		let rng = &mut test_rng();

		let rounds = get_rounds_poseidon_bls381_x5_5::<Fq>();
		let mds = get_mds_poseidon_bls381_x5_5::<Fq>();
		let params = PoseidonParameters::<Fq>::new(rounds, mds);

		let secrets = Leaf::generate_secrets(rng).unwrap();
		let privkey = to_bytes![secrets.priv_key].unwrap();
		let pubkey = PoseidonCRH3::evaluate(&params, &privkey).unwrap();

		let keypair = Keypair1::new(&params, &secrets).unwrap();
		let new_pubkey = keypair.pubkey;

		assert_eq!(new_pubkey, pubkey)
	}
}
