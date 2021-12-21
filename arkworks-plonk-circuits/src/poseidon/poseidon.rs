use ark_crypto_primitives::crh::poseidon::Poseidon;
use ark_ec::{models::TEModelParameters, PairingEngine};
use ark_ff::PrimeField;
use ark_plonk::{
	circuit::Circuit, constraint_system::StandardComposer, error::Error, prelude::Variable,
};
use ark_std::{marker::PhantomData, vec::Vec, One, Zero};

use crate::poseidon::sbox::{PoseidonSbox, SboxConstraints};

#[derive(Debug, Default)]
pub struct PoseidonParameters<F: PrimeField> {
	/// The round key constants
	pub round_keys: Vec<F>,
	/// The MDS matrix to apply in the mix layer.
	pub mds_matrix: Vec<Vec<F>>,
	/// Number of full SBox rounds
	pub full_rounds: u8,
	/// Number of partial rounds
	pub partial_rounds: u8,
	/// The size of the permutation, in field elements.
	pub width: u8,
	/// The S-box to apply in the sub words layer.
	pub sbox: PoseidonSbox,
}

pub struct PoseidonParametersVar {
	/// The round key constants
	pub round_keys: Vec<Variable>,
	/// The MDS matrix to apply in the mix layer.
	pub mds_matrix: Vec<Vec<Variable>>,
	/// Number of full SBox rounds
	pub full_rounds: u8,
	/// Number of partial rounds
	pub partial_rounds: u8,
	/// The size of the permutation, in field elements.
	pub width: u8,
	/// The S-box to apply in the sub words layer.
	pub sbox: PoseidonSbox,
}

#[derive(Debug, Default)]
struct PoseidonCircuit<E: PairingEngine, P: TEModelParameters<BaseField = E::Fr>> {
	pub a: E::Fr,
	pub b: E::Fr,
	pub c: E::Fr,
	pub params: PoseidonParameters<E::Fr>,
	pub _marker: PhantomData<P>,
}

pub fn hash<E: PairingEngine, P: TEModelParameters<BaseField = E::Fr>>(
	state_var: Vec<Variable>,
	params: PoseidonParametersVar,
	composer: &mut StandardComposer<E, P>,
) -> Result<Variable, Error> {
	let mut state = state_var.clone();
	// COMPUTE HASH
	let nr = params.full_rounds + params.partial_rounds;
	for r in 0..nr {
		state.iter_mut().enumerate().for_each(|(i, a)| {
			let c_temp = params.round_keys[(r as usize * params.width as usize + i)];
			// a = a + c_temp
			*a = composer.add(
				(E::Fr::one(), *a),
				(E::Fr::one(), c_temp),
				E::Fr::zero(),
				None,
			);
		});

		let half_rounds = params.full_rounds / 2;
		if r < half_rounds || r >= half_rounds + params.partial_rounds {
			state
				.iter_mut()
				.try_for_each(|a| params.sbox.synthesize_sbox(a, composer).map(|f| *a = f))?;
		} else {
			state[0] = params.sbox.synthesize_sbox(&state[0], composer)?;
		}

		state = state
			.iter()
			.enumerate()
			.map(|(i, _)| {
				state
					.iter()
					.enumerate()
					.fold(composer.zero_var(), |acc, (j, a)| {
						let m = &params.mds_matrix[i][j];

						let mul_result = composer.mul(E::Fr::one(), *a, *m, E::Fr::zero(), None);

						let add_result = composer.add(
							(E::Fr::one(), acc),
							(E::Fr::one(), mul_result),
							E::Fr::zero(),
							None,
						);

						add_result
					})
			})
			.collect();
	}

	let computed_hash = state.get(0).cloned().ok_or(Error::CircuitInputsNotFound)?;
	Ok(computed_hash)
}

impl<E: PairingEngine, P: TEModelParameters<BaseField = E::Fr>> Circuit<E, P>
	for PoseidonCircuit<E, P>
{
	const CIRCUIT_ID: [u8; 32] = [0xff; 32];

	fn gadget(&mut self, composer: &mut StandardComposer<E, P>) -> Result<(), Error> {
		// ADD INPUTS
		let a = composer.add_input(self.a);
		let b = composer.add_input(self.b);
		let state_zero = composer.add_input(E::Fr::zero());

		let mut round_key_vars = vec![];
		for i in 0..self.params.round_keys.len() {
			let round_key = composer.add_input(self.params.round_keys[i]);
			round_key_vars.push(round_key);
		}

		let mut mds_matrix_vars = vec![];
		for i in 0..self.params.mds_matrix.len() {
			let mut mds_row_vars = vec![];
			for j in 0..self.params.mds_matrix[i].len() {
				let mds_entry = composer.add_input(self.params.mds_matrix[i][j]);
				mds_row_vars.push(mds_entry);
			}
			mds_matrix_vars.push(mds_row_vars);
		}

		let params = PoseidonParametersVar {
			round_keys: round_key_vars,
			mds_matrix: mds_matrix_vars,
			full_rounds: self.params.full_rounds,
			partial_rounds: self.params.partial_rounds,
			width: self.params.width,
			sbox: self.params.sbox,
		};

		let state = vec![state_zero, a, b];
		let computed_hash = hash(state, params, composer)?;

		let add_result = composer.add(
			(E::Fr::one(), computed_hash),
			(E::Fr::one(), composer.zero_var()),
			E::Fr::zero(),
			Some(-self.c),
		);
		composer.assert_equal(add_result, composer.zero_var());
		Ok(())
	}

	fn padded_circuit_size(&self) -> usize {
		1 << 11
	}
}

#[cfg(test)]
mod tests {
	//copied from ark-plonk
	use super::*;
	use ark_bn254::{Bn254, Fr as Bn254Fr};
	use ark_crypto_primitives::crh::TwoToOneCRH;
	use ark_ed_on_bn254::{EdwardsParameters as JubjubParameters, Fq};
	use ark_ff::{BigInteger, Field};
	use ark_plonk::{
		circuit::{self, FeIntoPubInput},
		prelude::*,
		proof_system::{Prover, Verifier},
	};
	use ark_poly::polynomial::univariate::DensePolynomial;
	use ark_poly_commit::{
		kzg10::{self, Powers, UniversalParams, KZG10},
		sonic_pc::SonicKZG10,
		PolynomialCommitment,
	};
	use ark_std::{test_rng, One};
	use arkworks_utils::utils::common::{setup_params_x3_5, setup_params_x5_3};

	type PoseidonCRH3 = arkworks_gadgets::poseidon::CRH<Fq>;
	type StandardComposerBn254 =
		ark_plonk::constraint_system::StandardComposer<Bn254, JubjubParameters>;

	/// Takes a generic gadget function with no auxillary input and
	/// tests whether it passes an end-to-end test
	pub(crate) fn gadget_tester<
		E: PairingEngine,
		P: TEModelParameters<BaseField = E::Fr>,
		C: Circuit<E, P>,
	>(
		circuit: &mut C,
		n: usize,
	) -> Result<(), Error> {
		let rng = &mut test_rng();
		// Common View
		let universal_params = KZG10::<E, DensePolynomial<E::Fr>>::setup(2 * n, false, rng)?;
		// Provers View
		let (proof, public_inputs) = {
			// Create a prover struct
			let mut prover = Prover::new(b"demo");

			// Additionally key the transcript
			prover.key_transcript(b"key", b"additional seed information");

			// Add gadgets
			circuit.gadget(&mut prover.mut_cs())?;

			// Commit Key
			let (ck, _) = SonicKZG10::<E, DensePolynomial<E::Fr>>::trim(
				&universal_params,
				prover.circuit_size().next_power_of_two(),
				0,
				None,
			)
			.unwrap();
			let powers = Powers {
				powers_of_g: ck.powers_of_g.into(),
				powers_of_gamma_g: ck.powers_of_gamma_g.into(),
			};
			// Preprocess circuit
			prover.preprocess(&powers)?;

			// Once the prove method is called, the public inputs are cleared
			// So pre-fetch these before calling Prove
			let public_inputs = prover.mut_cs().construct_dense_pi_vec();
			//? let lookup_table = prover.mut_cs().lookup_table.clone();

			// Compute Proof
			(prover.prove(&powers)?, public_inputs)
		};
		// Verifiers view
		//
		// Create a Verifier object
		let mut verifier = Verifier::new(b"demo");

		// Additionally key the transcript
		verifier.key_transcript(b"key", b"additional seed information");

		// Add gadgets
		circuit.gadget(&mut verifier.mut_cs())?;

		// Compute Commit and Verifier Key
		let (sonic_ck, sonic_vk) = SonicKZG10::<E, DensePolynomial<E::Fr>>::trim(
			&universal_params,
			verifier.circuit_size().next_power_of_two(),
			0,
			None,
		)
		.unwrap();
		let powers = Powers {
			powers_of_g: sonic_ck.powers_of_g.into(),
			powers_of_gamma_g: sonic_ck.powers_of_gamma_g.into(),
		};

		let vk = kzg10::VerifierKey {
			g: sonic_vk.g,
			gamma_g: sonic_vk.gamma_g,
			h: sonic_vk.h,
			beta_h: sonic_vk.beta_h,
			prepared_h: sonic_vk.prepared_h,
			prepared_beta_h: sonic_vk.prepared_beta_h,
		};

		// Preprocess circuit
		verifier.preprocess(&powers)?;

		// Verify proof
		Ok(verifier.verify(&proof, &vk, &public_inputs)?)
	}

	#[test]
	fn should_verify_plonk_poseidon_x5_3() {
		let curve = arkworks_utils::utils::common::Curve::Bn254;

		let util_params = setup_params_x5_3(curve);
		let params = PoseidonParameters {
			round_keys: util_params.clone().round_keys,
			mds_matrix: util_params.clone().mds_matrix,
			full_rounds: util_params.clone().full_rounds,
			partial_rounds: util_params.clone().partial_rounds,
			sbox: PoseidonSbox::Exponentiation(5),
			width: util_params.clone().width,
		};

		let left_input = Fq::one().into_repr().to_bytes_le();
		let right_input = Fq::one().double().into_repr().to_bytes_le();
		let poseidon_res =
			<PoseidonCRH3 as TwoToOneCRH>::evaluate(&util_params, &left_input, &right_input)
				.unwrap();
		println!("RESULT: {:?}", poseidon_res.to_string());
		let mut circuit = PoseidonCircuit::<Bn254, JubjubParameters> {
			a: Fq::from_le_bytes_mod_order(&left_input),
			b: Fq::from_le_bytes_mod_order(&right_input),
			c: poseidon_res,
			params,
			_marker: std::marker::PhantomData,
		};

		let rng = &mut test_rng();
		let u_params: UniversalParams<Bn254> =
			KZG10::<Bn254, DensePolynomial<Bn254Fr>>::setup(1 << 12, false, rng).unwrap();

		let (pk, vd) = circuit.compile(&u_params).unwrap();

		// PROVER
		let proof = {
			let util_params = setup_params_x5_3(curve);
			let params = PoseidonParameters {
				round_keys: util_params.round_keys,
				mds_matrix: util_params.mds_matrix,
				full_rounds: util_params.full_rounds,
				partial_rounds: util_params.partial_rounds,
				sbox: PoseidonSbox::Exponentiation(5),
				width: util_params.width,
			};

			let mut circuit = PoseidonCircuit::<Bn254, JubjubParameters> {
				a: Fq::from_le_bytes_mod_order(&left_input),
				b: Fq::from_le_bytes_mod_order(&right_input),
				c: poseidon_res,
				params,
				_marker: std::marker::PhantomData,
			};
			circuit.gen_proof(&u_params, pk, b"Poseidon Test").unwrap()
		};

		// VERIFIER
		let public_inputs: Vec<PublicInputValue<JubjubParameters>> = vec![poseidon_res.into_pi()];

		let VerifierData { key, pi_pos } = vd;

		circuit::verify_proof(
			&u_params,
			key,
			&proof,
			&public_inputs,
			&pi_pos,
			b"Poseidon Test",
		)
		.unwrap();
	}

	#[test]
	fn test_correct_poseidon_hash() {
		let curve = arkworks_utils::utils::common::Curve::Bn254;

		let util_params = setup_params_x3_5(curve);
		let params = PoseidonParameters {
			round_keys: util_params.clone().round_keys,
			mds_matrix: util_params.clone().mds_matrix,
			full_rounds: util_params.clone().full_rounds,
			partial_rounds: util_params.clone().partial_rounds,
			sbox: PoseidonSbox::Exponentiation(3),
			width: util_params.clone().width,
		};

		let left_input = Fq::one().double().into_repr().to_bytes_le();
		let right_input = Fq::one().double().into_repr().to_bytes_le();
		let poseidon_res =
			<PoseidonCRH3 as TwoToOneCRH>::evaluate(&util_params, &left_input, &right_input)
				.unwrap();
		println!("RESULT: {:?}", poseidon_res.to_string());
		let mut circuit = PoseidonCircuit::<Bn254, JubjubParameters> {
			a: Fq::from_le_bytes_mod_order(&left_input),
			b: Fq::from_le_bytes_mod_order(&right_input),
			c: poseidon_res,
			params,
			_marker: std::marker::PhantomData,
		};

		let res = gadget_tester(&mut circuit, 2000);
		assert!(res.is_ok(), "{:?}", res.err().unwrap());
	}
}
