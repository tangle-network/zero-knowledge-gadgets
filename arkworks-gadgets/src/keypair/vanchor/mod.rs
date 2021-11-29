use ark_crypto_primitives::{Error, CRH};
use ark_ff::{to_bytes, ToBytes};
use ark_std::marker::PhantomData;

#[cfg(feature = "r1cs")]
pub mod constraints;

#[derive(Default)]
pub struct Keypair<B: Clone + ToBytes, H: CRH> {
	pub private_key: B,
	_h: PhantomData<H>,
}

impl<B: Clone + ToBytes, H: CRH> Keypair<B, H> {
	pub fn new(private_key: B) -> Self {
		Self {
			private_key,
			_h: PhantomData,
		}
	}

	pub fn public_key(&self, h: &H::Parameters) -> Result<H::Output, Error> {
		let bytes = to_bytes![&self.private_key]?;
		H::evaluate(&h, &bytes)
	}

	// Computes the signature = hash(privKey, commitment, pathIndices)
	pub fn signature(
		&self,
		commitment: &H::Output,
		index: &B,
		h_w4: &H::Parameters,
	) -> Result<H::Output, Error> {
		let bytes = to_bytes![self.private_key.clone(), commitment, index]?;
		H::evaluate(&h_w4, &bytes)
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
	use crate::poseidon::CRH;
	use ark_bn254::Fq;
	use ark_crypto_primitives::crh::CRH as CRHTrait;
	use ark_ff::to_bytes;
	use arkworks_utils::utils::common::{setup_params_x5_2, setup_params_x5_4, Curve};

	use crate::ark_std::Zero;
	use ark_std::test_rng;

	use super::Keypair;

	type PoseidonCRH = CRH<Fq>;

	use crate::ark_std::UniformRand;
	#[test]
	fn should_crate_new_public_key() {
		let rng = &mut test_rng();
		let curve = Curve::Bn254;

		let params = setup_params_x5_2(curve);

		let private_key = Fq::rand(rng);

		let privkey = to_bytes![private_key].unwrap();
		let pubkey = PoseidonCRH::evaluate(&params, &privkey).unwrap();

		let keypair = Keypair::<Fq, PoseidonCRH>::new(private_key.clone());
		let new_pubkey = keypair.public_key(&params).unwrap();

		assert_eq!(new_pubkey, pubkey)
	}
	#[test]
	fn should_crate_new_signature() {
		let rng = &mut test_rng();
		let index = Fq::zero();
		let private_key = Fq::rand(rng);
		let curve = Curve::Bn254;

		let params4 = setup_params_x5_4(curve);

		let commitment = Fq::rand(rng);

		let keypair = Keypair::<Fq, PoseidonCRH>::new(private_key.clone());

		// Since signature = hash(privKey, commitment, pathIndices)
		let inputs_signature = to_bytes![private_key, commitment, index].unwrap();
		let ev_res = PoseidonCRH::evaluate(&params4, &inputs_signature).unwrap();
		let signature = keypair.signature(&commitment, &index, &params4).unwrap();
		assert_eq!(ev_res, signature);
	}
}
