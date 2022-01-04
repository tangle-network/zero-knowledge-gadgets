use crate::{mimc::Rounds as MiMCRounds, poseidon::PoseidonParameters};
use ark_crypto_primitives::{Error, SNARK};
use ark_ec::PairingEngine;
use ark_ff::fields::PrimeField;
use ark_groth16::{Groth16, Proof, VerifyingKey};

#[allow(non_camel_case_types)]
#[derive(Default, Clone)]
pub struct MiMCRounds_220_3;

impl crate::mimc::Rounds for MiMCRounds_220_3 {
	const ROUNDS: usize = 220;
	const WIDTH: usize = 3;
}

#[derive(Copy, Clone)]
pub enum Curve {
	Bls381,
	Bn254,
}

#[cfg(all(feature = "poseidon_bls381_x3_3", feature = "poseidon_bn254_x3_3"))]
pub fn setup_params_x3_3<F: PrimeField>(curve: Curve) -> PoseidonParameters<F> {
	// Making params for poseidon in merkle tree
	match curve {
		Curve::Bls381 => crate::utils::bls381_x3_3::get_poseidon_bls381_x3_3(),
		Curve::Bn254 => crate::utils::bn254_x3_3::get_poseidon_bn254_x3_3(),
	}
}

#[cfg(all(feature = "poseidon_bls381_x3_5", feature = "poseidon_bn254_x3_5"))]
pub fn setup_params_x3_5<F: PrimeField>(curve: Curve) -> PoseidonParameters<F> {
	// Making params for poseidon in merkle tree
	match curve {
		Curve::Bls381 => crate::utils::bls381_x3_5::get_poseidon_bls381_x3_5(),
		Curve::Bn254 => crate::utils::bn254_x3_5::get_poseidon_bn254_x3_5(),
	}
}

#[cfg(all(feature = "poseidon_bls381_x5_3", feature = "poseidon_bn254_x5_3"))]
pub fn setup_params_x5_3<F: PrimeField>(curve: Curve) -> PoseidonParameters<F> {
	// Making params for poseidon in merkle tree
	match curve {
		Curve::Bls381 => crate::utils::bls381_x5_3::get_poseidon_bls381_x5_3(),
		Curve::Bn254 => crate::utils::bn254_x5_3::get_poseidon_bn254_x5_3(),
	}
}

#[cfg(feature = "poseidon_bn254_x5_2")]
pub fn setup_params_x5_2<F: PrimeField>(curve: Curve) -> PoseidonParameters<F> {
	// Making params for poseidon in merkle tree
	match curve {
		Curve::Bls381 => {
			unimplemented!("we don't hava parameters for bls381 curve yet");
		}
		Curve::Bn254 => crate::utils::bn254_x5_2::get_poseidon_bn254_x5_2(),
	}
}

#[cfg(feature = "poseidon_bn254_x5_4")]
pub fn setup_params_x5_4<F: PrimeField>(curve: Curve) -> PoseidonParameters<F> {
	// Making params for poseidon in merkle tree
	match curve {
		Curve::Bls381 => {
			unimplemented!("we don't hava parameters for bls381 curve yet");
		}
		Curve::Bn254 => crate::utils::bn254_x5_4::get_poseidon_bn254_x5_4(),
	}
}

#[cfg(all(feature = "poseidon_bls381_x5_5", feature = "poseidon_bn254_x5_5"))]
pub fn setup_params_x5_5<F: PrimeField>(curve: Curve) -> PoseidonParameters<F> {
	// Making params for poseidon in merkle tree
	match curve {
		Curve::Bls381 => crate::utils::bls381_x5_5::get_poseidon_bls381_x5_5(),
		Curve::Bn254 => crate::utils::bn254_x5_5::get_poseidon_bn254_x5_5(),
	}
}

#[cfg(all(feature = "poseidon_bls381_x17_3", feature = "poseidon_bn254_x17_3"))]
pub fn setup_params_x17_3<F: PrimeField>(curve: Curve) -> PoseidonParameters<F> {
	// Making params for poseidon in merkle tree
	match curve {
		Curve::Bls381 => crate::utils::bls381_x17_3::get_poseidon_bls381_x17_3(),
		Curve::Bn254 => crate::utils::bn254_x17_3::get_poseidon_bn254_x17_3(),
	}
}

#[cfg(all(feature = "poseidon_bls381_x17_5", feature = "poseidon_bn254_x17_5"))]
pub fn setup_params_x17_5<F: PrimeField>(curve: Curve) -> PoseidonParameters<F> {
	// Making params for poseidon in merkle tree
	match curve {
		Curve::Bls381 => crate::utils::bls381_x17_5::get_poseidon_bls381_x17_5(),
		Curve::Bn254 => crate::utils::bn254_x17_5::get_poseidon_bn254_x17_5(),
	}
}

#[cfg(feature = "default_mimc")]
pub fn setup_mimc_220<F: PrimeField>(curve: Curve) -> crate::mimc::MiMCParameters<F> {
	match curve {
		Curve::Bls381 => {
			unimplemented!();
		}
		Curve::Bn254 => crate::mimc::MiMCParameters::<F>::new(
			F::zero(),
			MiMCRounds_220_3::ROUNDS,
			MiMCRounds_220_3::WIDTH,
			MiMCRounds_220_3::WIDTH,
			crate::utils::get_rounds_mimc_220(),
		),
	}
}

pub fn verify_groth16<E: PairingEngine>(
	vk: &VerifyingKey<E>,
	public_inputs: &[E::Fr],
	proof: &Proof<E>,
) -> Result<bool, Error> {
	let res = Groth16::<E>::verify(vk, public_inputs, proof)?;
	Ok(res)
}
