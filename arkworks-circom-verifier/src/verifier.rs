// Some parts of this file are used from https://github.com/gakonst/ark-circom
use ark_bn254::{Bn254, Fq, Fq2, Fr as BnFr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ff::BigInteger256;

use ark_crypto_primitives::Error;
use ark_serialize::CanonicalDeserialize;
use ark_std::{str::FromStr, string::ToString};
use arkworks_gadgets::prelude::ark_groth16::ProvingKey;
use arkworks_utils::prelude::ark_groth16::{Proof, VerifyingKey};

use crate::utils::BinFile;
use arkworks_circuits::setup::common::verify_groth16;
use num_bigint::BigUint;
use serde_json::Value;
use std::io::{Read, Result as IoResult, Seek};

pub fn fq_from_str(s: &str) -> Fq {
	BigInteger256::try_from(BigUint::from_str(s).unwrap())
		.unwrap()
		.into()
}

pub fn fr_from_str(s: &str) -> BnFr {
	BigInteger256::try_from(BigUint::from_str(s).unwrap())
		.unwrap()
		.into()
}

pub fn json_to_g1(json: &Value, key: &str) -> G1Affine {
	let els: Vec<String> = json
		.get(key)
		.unwrap()
		.as_array()
		.unwrap()
		.iter()
		.map(|i| i.as_str().unwrap().to_string())
		.collect();
	G1Affine::from(G1Projective::new(
		fq_from_str(&els[0]),
		fq_from_str(&els[1]),
		fq_from_str(&els[2]),
	))
}

pub fn json_to_g2(json: &Value, key: &str) -> G2Affine {
	let els: Vec<Vec<String>> = json
		.get(key)
		.unwrap()
		.as_array()
		.unwrap()
		.iter()
		.map(|i| {
			i.as_array()
				.unwrap()
				.iter()
				.map(|x| x.as_str().unwrap().to_string())
				.collect::<Vec<String>>()
		})
		.collect();

	let x = Fq2::new(fq_from_str(&els[0][0]), fq_from_str(&els[0][1]));
	let y = Fq2::new(fq_from_str(&els[1][0]), fq_from_str(&els[1][1]));
	let z = Fq2::new(fq_from_str(&els[2][0]), fq_from_str(&els[2][1]));
	G2Affine::from(G2Projective::new(x, y, z))
}

pub fn json_to_fq(json: &Value, key: &str) -> Vec<Fq> {
	let els: Vec<Fq> = json
		.get(key)
		.unwrap()
		.as_array()
		.unwrap()
		.iter()
		.map(|i| fq_from_str(&i.as_str().unwrap().to_string()))
		.collect();
	els
}

pub fn json_to_fr(json: &Value, key: &str) -> BnFr {
	let els = json.get(key).unwrap();

	fr_from_str(&els.as_str().unwrap().to_string())
}

pub fn json_to_fr_vec(json: &Value, key: &str) -> Vec<BnFr> {
	let els: Vec<BnFr> = json
		.get(key)
		.unwrap()
		.as_array()
		.unwrap()
		.iter()
		.map(|i| fr_from_str(&i.as_str().unwrap().to_string()))
		.collect();
	els
}

pub fn parse_proof_bn254_json(json: &Value) -> Proof<Bn254> {
	let pi_a = json_to_g1(json, "pi_a");
	let pi_b = json_to_g2(json, "pi_b");
	let pi_c = json_to_g1(json, "pi_c");

	Proof {
		a: pi_a,
		b: pi_b,
		c: pi_c,
	}
}

pub fn parse_public_inputs_bn254_json(json: &Value) -> Vec<BnFr> {
	let public_amount = json_to_fr(json, "publicAmount");
	let ext_data_hash = json_to_fr(json, "extDataHash");
	let nullifier_hash = json_to_fr_vec(json, "inputNullifier");
	let output_commitment = json_to_fr_vec(json, "outputCommitment");
	let chain_id = json_to_fr(json, "chainID");
	let root_set = json_to_fr_vec(json, "roots");

	let mut public_inputs = vec![public_amount];
	public_inputs.push(ext_data_hash);
	public_inputs.extend(nullifier_hash);
	public_inputs.extend(output_commitment);
	public_inputs.push(chain_id);
	public_inputs.extend(root_set);

	public_inputs
}

pub fn verify(public_inputs: Vec<BnFr>, vk: &[u8], proof: &[u8]) -> Result<bool, Error> {
	let vk = VerifyingKey::<Bn254>::deserialize(vk)?;
	let proof = Proof::<Bn254>::deserialize(proof)?;
	verify_groth16(&vk, &public_inputs, &proof)
}

/// Reads a SnarkJS ZKey file into an Arkworks ProvingKey.
pub fn read_zkey<R: Read + Seek>(reader: &mut R) -> IoResult<ProvingKey<Bn254>> {
	let mut binfile = BinFile::new(reader)?;
	let proving_key = binfile.proving_key()?;
	Ok(proving_key)
}

#[cfg(test)]
mod test {
	use super::*;
	use ark_serialize::CanonicalSerialize;
	use ark_std::fs::File;

	#[test]
	fn should_verify_proof() {
		//let path = "./arkworks-circom-verifier/src/vanchor_circuit_final_2_2.zkey";
		let path = "./test-vectors/vanchor_circuit_final_2_2.zkey";
		let mut file = File::open(path).unwrap();
		let params = read_zkey(&mut file).unwrap();
		//let mut _wtns =
		// WitnessCalculator::new("./src/poseidon_vanchor_2_2.wasm").unwrap();
		// let mut _inputs: HashMap<String, Vec<num_bigint::BigInt>> = HashMap::new();
		let json = ark_std::fs::read_to_string("./test-vectors/proof.json").unwrap();
		let json: Value = serde_json::from_str(&json).unwrap();
		let proof = parse_proof_bn254_json(&json);

		let json = ark_std::fs::read_to_string("./test-vectors/inputs.json").unwrap();
		let json: Value = serde_json::from_str(&json).unwrap();
		let mut proof_serialized = Vec::new();
		Proof::<Bn254>::serialize(&proof, &mut proof_serialized).unwrap();

		let mut pvk_serialized = Vec::new();
		VerifyingKey::<Bn254>::serialize(&params.vk, &mut pvk_serialized).unwrap();
		let inputs = parse_public_inputs_bn254_json(&json);
		//let verified = verify_proof(&pvk, &proof, &inputs).unwrap();
		let verified = verify(inputs, &pvk_serialized, &proof_serialized).unwrap();
		assert!(verified);
	}

	#[test]
	fn should_fail_with_invalid_public_input() {
		//let path = "./arkworks-circom-verifier/src/vanchor_circuit_final_2_2.zkey";
		let path = "./test-vectors/vanchor_circuit_final_2_2.zkey";
		let mut file = File::open(path).unwrap();
		let params = read_zkey(&mut file).unwrap();
		//let mut _wtns =
		// WitnessCalculator::new("./src/poseidon_vanchor_2_2.wasm").unwrap();
		// let mut _inputs: HashMap<String, Vec<num_bigint::BigInt>> = HashMap::new();
		let json = ark_std::fs::read_to_string("./test-vectors/proof.json").unwrap();
		let json: Value = serde_json::from_str(&json).unwrap();
		let proof = parse_proof_bn254_json(&json);

		let json = ark_std::fs::read_to_string("./test-vectors/inputs.json").unwrap();
		let json: Value = serde_json::from_str(&json).unwrap();
		let mut proof_serialized = Vec::new();
		Proof::<Bn254>::serialize(&proof, &mut proof_serialized).unwrap();

		let mut pvk_serialized = Vec::new();
		VerifyingKey::<Bn254>::serialize(&params.vk, &mut pvk_serialized).unwrap();
		let inputs = parse_public_inputs_bn254_json(&json);
		let inputs = inputs[1..].to_vec();
		//let verified = verify_proof(&pvk, &proof, &inputs).unwrap();
		let verified = verify(inputs, &pvk_serialized, &proof_serialized);
		assert!(verified.is_err());
	}

	#[test]
	fn should_fail_with_invalid_proof() {
		//let path = "./arkworks-circom-verifier/src/vanchor_circuit_final_2_2.zkey";
		let path = "./test-vectors/vanchor_circuit_final_2_2.zkey";
		let mut file = File::open(path).unwrap();
		let params = read_zkey(&mut file).unwrap();
		//let mut _wtns =
		// WitnessCalculator::new("./src/poseidon_vanchor_2_2.wasm").unwrap();
		// let mut _inputs: HashMap<String, Vec<num_bigint::BigInt>> = HashMap::new();
		let json = ark_std::fs::read_to_string("./test-vectors/proof_wrong.json").unwrap();
		let json: Value = serde_json::from_str(&json).unwrap();
		let proof = parse_proof_bn254_json(&json);

		let json = ark_std::fs::read_to_string("./test-vectors/inputs.json").unwrap();
		let json: Value = serde_json::from_str(&json).unwrap();
		let mut proof_serialized = Vec::new();
		Proof::<Bn254>::serialize(&proof, &mut proof_serialized).unwrap();

		let mut pvk_serialized = Vec::new();
		VerifyingKey::<Bn254>::serialize(&params.vk, &mut pvk_serialized).unwrap();
		let inputs = parse_public_inputs_bn254_json(&json);
		//let verified = verify_proof(&pvk, &proof, &inputs).unwrap();
		let verified = verify(inputs, &pvk_serialized, &proof_serialized).unwrap();
		assert!(!verified);
	}
}
