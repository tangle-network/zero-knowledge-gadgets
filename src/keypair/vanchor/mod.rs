use ark_crypto_primitives::{Error, CRH};
use ark_ff::{to_bytes, ToBytes};
use ark_std::marker::PhantomData;

#[cfg(feature = "r1cs")]
pub mod constraints;

#[derive(Default)]
pub struct Keypair<B: Clone + ToBytes, H2: CRH> {
	pub private_key: B,
	_h2: PhantomData<H2>,
}

impl<B: Clone + ToBytes, H2: CRH> Keypair<B, H2> {
	pub fn new(private_key: B) -> Self {
		Self {
			private_key,
			_h2: PhantomData,
		}
	}

	pub fn public_key(&self, h: &H2::Parameters) -> Result<H2::Output, Error> {
		let bytes = to_bytes![&self.private_key]?;
		H2::evaluate(&h, &bytes)
	}

	// Computes the signature = hash(privKey, commitment, pathIndices)
	pub fn signature<H4: CRH, H5: CRH>(
		&self,
		commitment: &H5::Output,
		index: &B,
		h_w4: &H4::Parameters,
	) -> Result<H4::Output, Error> {
		let bytes = to_bytes![self.private_key.clone(), commitment, index]?;
		H4::evaluate(&h_w4, &bytes)
	}
}

impl<B: Clone + ToBytes, H2: CRH> Clone for Keypair<B, H2> {
	fn clone(&self) -> Self {
		let private_key = self.private_key.clone();
		Self::new(private_key)
	}
}

#[cfg(feature = "default_poseidon")]
#[cfg(test)]
mod test {
	use crate::{
		poseidon::{sbox::PoseidonSbox, PoseidonParameters, Rounds, CRH},
		utils::{
			get_mds_poseidon_bn254_x5_2, get_mds_poseidon_bn254_x5_4,
			get_rounds_poseidon_bn254_x5_2, get_rounds_poseidon_bn254_x5_4,
		},
	};
	use ark_bn254::Fq;
	use ark_crypto_primitives::crh::CRH as CRHTrait;
	use ark_ff::to_bytes;

	use crate::ark_std::Zero;
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

	use crate::ark_std::UniformRand;
	#[test]
	fn should_crate_new_public_key() {
		let rng = &mut test_rng();

		let rounds = get_rounds_poseidon_bn254_x5_2::<Fq>();
		let mds = get_mds_poseidon_bn254_x5_2::<Fq>();
		let params = PoseidonParameters::<Fq>::new(rounds, mds);
		let private_key = Fq::rand(rng);

		let privkey = to_bytes![private_key].unwrap();
		let pubkey = PoseidonCRH2::evaluate(&params, &privkey).unwrap();

		let keypair = Keypair::<Fq, PoseidonCRH2>::new(private_key.clone());
		let new_pubkey = keypair.public_key(&params).unwrap();

		assert_eq!(new_pubkey, pubkey)
	}
	#[test]
	fn should_crate_new_signature() {
		let rng = &mut test_rng();
		let index = Fq::zero();
		let private_key = Fq::rand(rng);

		let rounds = get_rounds_poseidon_bn254_x5_4::<Fq>();
		let mds = get_mds_poseidon_bn254_x5_4::<Fq>();
		let params4 = PoseidonParameters::<Fq>::new(rounds, mds);

		let commitment = Fq::rand(rng);

		let keypair = Keypair::<Fq, PoseidonCRH2>::new(private_key.clone());

		// Since signature = hash(privKey, commitment, pathIndices)
		let inputs_signature = to_bytes![private_key, commitment, index].unwrap();
		let ev_res = PoseidonCRH4::evaluate(&params4, &inputs_signature).unwrap();
		let signature = keypair
			.signature::<PoseidonCRH4, PoseidonCRH5>(&commitment, &index, &params4)
			.unwrap();
		assert_eq!(ev_res, signature);
	}
}
