use ark_std::vec;

use ark_std::{One, Zero};
use crate::{common::*};
use ark_serialize::CanonicalDeserialize;
use arkworks_utils::{
    poseidon::PoseidonParameters,
    utils::common::{
        setup_params_x5_2, setup_params_x5_3, setup_params_x5_4, setup_params_x5_5, Curve,
    },
};

use ark_bn254::{Bn254, Fr as BnFr};
use ark_ff::UniformRand;
use ark_groth16::{Groth16, Proof, VerifyingKey};

use ark_std::str::FromStr;
use ark_snark::SNARK;
use ark_std::test_rng;

#[test]
fn should_create_proof_for_random_circuit() {
    let rng = &mut test_rng();
    let curve = Curve::Bn254;
    let params2 = setup_params_x5_2::<BnFr>(curve);
    let params3 = setup_params_x5_3::<BnFr>(curve);
    let params4 = setup_params_x5_4::<BnFr>(curve);
    let params5 = setup_params_x5_5::<BnFr>(curve);

    // Set up a random circuit and make pk/vk pair
    let prover = VAnchorProverBn2542x2::new(params2, params3, params4, params5);
    let random_circuit = prover.clone().setup_random_circuit(rng).unwrap();
    let (proving_key, verifying_key) = setup_keys::<Bn254, _, _>(random_circuit, rng).unwrap();

    // Make a proof now
    let public_amount = BnFr::from(10u32);
    let ext_data_hash = BnFr::rand(rng);

    // Input Utxos
    let in_chain_id = BnFr::from(0u32);
    let in_amount = BnFr::from(5u32);
    let index = BnFr::from(0u32);
    let in_utxo1 = prover
        .new_utxo(in_chain_id, in_amount, Some(index), None, None, rng)
        .unwrap();
    let in_utxo2 = prover
        .new_utxo(in_chain_id, in_amount, Some(index), None, None, rng)
        .unwrap();
    let in_utxos = [in_utxo1, in_utxo2];

    // Output Utxos
    let out_chain_id = BnFr::from(0u32);
    let out_amount = BnFr::from(10u32);
    let out_utxo1 = prover
        .new_utxo(out_chain_id, out_amount, None, None, None, rng)
        .unwrap();
    let out_utxo2 = prover
        .new_utxo(out_chain_id, out_amount, None, None, None, rng)
        .unwrap();
    let out_utxos = [out_utxo1, out_utxo2];

    let leaf0 = in_utxo1.commitment;
    let (in_path0, _) = prover.setup_tree(&vec![leaf0], 0).unwrap();
    let root0 = in_path0.root_hash(&leaf0).unwrap().inner();
    let leaf1 = in_utxo2.commitment;
    let (in_path1, _) = prover.setup_tree(&vec![leaf1], 0).unwrap();
    let root1 = in_path1.root_hash(&leaf1).unwrap().inner();

    let in_leaves = [vec![leaf0], vec![leaf1]];
    let in_indices = [0; 2];
    let in_root_set = [root0, root1];

    let (circuit, .., pub_ins) = prover
        .setup_circuit_with_utxos(
            public_amount,
            ext_data_hash,
            in_root_set,
            in_indices,
            in_leaves,
            in_utxos,
            out_utxos,
        )
        .unwrap();

    let proof = prove::<Bn254, _, _>(circuit, &proving_key, rng).unwrap();
    let res = verify::<Bn254>(&pub_ins, &verifying_key, &proof).unwrap();

    assert!(res);
}

#[test]
fn should_create_circuit_and_prove_groth16_2_input_2_output() {
    let rng = &mut test_rng();
    let curve = Curve::Bn254;
    let params2: PoseidonParameters<BnFr> = setup_params_x5_2(curve);
    let params3: PoseidonParameters<BnFr> = setup_params_x5_3(curve);
    let params4: PoseidonParameters<BnFr> = setup_params_x5_4(curve);
    let params5: PoseidonParameters<BnFr> = setup_params_x5_5(curve);
    let prover = VAnchorProverBn2542x2::new(params2, params3, params4, params5);

    let public_amount = BnFr::from(10u32);
    let ext_data_hash = BnFr::rand(rng);

    // Input Utxos
    let in_chain_id = BnFr::from(0u32);
    let in_amount = BnFr::from(5u32);
    let index = BnFr::from(0u32);
    let in_utxo1 = prover
        .new_utxo(in_chain_id, in_amount, Some(index), None, None, rng)
        .unwrap();
    let in_utxo2 = prover
        .new_utxo(in_chain_id, in_amount, Some(index), None, None, rng)
        .unwrap();
    let in_utxos = [in_utxo1, in_utxo2];

    // Output Utxos
    let out_chain_id = BnFr::from(0u32);
    let out_amount = BnFr::from(10u32);
    let out_utxo1 = prover
        .new_utxo(out_chain_id, out_amount, None, None, None, rng)
        .unwrap();
    let out_utxo2 = prover
        .new_utxo(out_chain_id, out_amount, None, None, None, rng)
        .unwrap();
    let out_utxos = [out_utxo1, out_utxo2];

    let leaf0 = in_utxo1.commitment;
    let (in_path0, _) = prover.setup_tree(&vec![leaf0], 0).unwrap();
    let root0 = in_path0.root_hash(&leaf0).unwrap().inner();
    let leaf1 = in_utxo2.commitment;
    let (in_path1, _) = prover.setup_tree(&vec![leaf1], 0).unwrap();
    let root1 = in_path1.root_hash(&leaf1).unwrap().inner();

    let in_leaves = [vec![leaf0], vec![leaf1]];
    let in_indices = [0; 2];
    let in_root_set = [root0, root1];

    let (circuit, .., pub_ins) = prover
        .setup_circuit_with_utxos(
            public_amount,
            ext_data_hash,
            in_root_set,
            in_indices,
            in_leaves,
            in_utxos,
            out_utxos,
        )
        .unwrap();

    let (proving_key, verifying_key) = setup_keys::<Bn254, _, _>(circuit.clone(), rng).unwrap();
    let proof = prove::<Bn254, _, _>(circuit, &proving_key, rng).unwrap();
    let res = verify::<Bn254>(&pub_ins, &verifying_key, &proof).unwrap();

    assert!(res);
}

#[test]
fn should_fail_with_invalid_root() {
    let rng = &mut test_rng();
    let curve = Curve::Bn254;
    let params2: PoseidonParameters<BnFr> = setup_params_x5_2(curve);
    let params3: PoseidonParameters<BnFr> = setup_params_x5_3(curve);
    let params4: PoseidonParameters<BnFr> = setup_params_x5_4(curve);
    let params5: PoseidonParameters<BnFr> = setup_params_x5_5(curve);
    let prover = VAnchorProverBn2542x2::new(params2, params3, params4, params5);

    let public_amount = BnFr::from(10u32);
    let ext_data_hash = BnFr::rand(rng);

    // Input Utxos
    let in_chain_id = BnFr::from(0u32);
    let in_amount = BnFr::from(5u32);
    let index = BnFr::from(0u32);
    let in_utxo1 = prover
        .new_utxo(in_chain_id, in_amount, Some(index), None, None, rng)
        .unwrap();
    let in_utxo2 = prover
        .new_utxo(in_chain_id, in_amount, Some(index), None, None, rng)
        .unwrap();
    let in_utxos = [in_utxo1, in_utxo2];

    // Output Utxos
    let out_chain_id = BnFr::from(0u32);
    let out_amount = BnFr::from(10u32);
    let out_utxo1 = prover
        .new_utxo(out_chain_id, out_amount, None, None, None, rng)
        .unwrap();
    let out_utxo2 = prover
        .new_utxo(out_chain_id, out_amount, None, None, None, rng)
        .unwrap();
    let out_utxos = [out_utxo1, out_utxo2];

    let leaf0 = in_utxos[0].commitment;
    let leaf1 = in_utxos[1].commitment;

    let in_leaves = [vec![leaf0], vec![leaf1]];
    let in_indices = [0; 2];

    // Invalid root set
    let in_root_set = [BnFr::rand(rng); 2];

    let (circuit, .., pub_ins) = prover
        .setup_circuit_with_utxos(
            public_amount,
            ext_data_hash,
            in_root_set,
            in_indices,
            in_leaves,
            in_utxos,
            out_utxos,
        )
        .unwrap();

    let (proving_key, verifying_key) = setup_keys::<Bn254, _, _>(circuit.clone(), rng).unwrap();
    let proof = prove::<Bn254, _, _>(circuit, &proving_key, rng).unwrap();
    let res = verify::<Bn254>(&pub_ins, &verifying_key, &proof).unwrap();

    assert!(!res);
}

#[test]
fn should_fail_with_invalid_nullifier() {
    let rng = &mut test_rng();
    let curve = Curve::Bn254;
    let params2: PoseidonParameters<BnFr> = setup_params_x5_2(curve);
    let params3: PoseidonParameters<BnFr> = setup_params_x5_3(curve);
    let params4: PoseidonParameters<BnFr> = setup_params_x5_4(curve);
    let params5: PoseidonParameters<BnFr> = setup_params_x5_5(curve);
    let prover = VAnchorProverBn2542x2::new(params2, params3, params4, params5);

    let public_amount = BnFr::from(10u32);
    let ext_data_hash = BnFr::rand(rng);

    // Input Utxos
    let in_chain_id = BnFr::from(0u32);
    let in_amount = BnFr::from(5u32);
    let index = BnFr::from(0u32);
    let mut in_utxo1 = prover
        .new_utxo(in_chain_id, in_amount, Some(index), None, None, rng)
        .unwrap();
    let in_utxo2 = prover
        .new_utxo(in_chain_id, in_amount, Some(index), None, None, rng)
        .unwrap();

    // Adding invalid nullifier
    in_utxo1.nullifier = Some(BnFr::rand(rng));

    let in_utxos = [in_utxo1, in_utxo2];

    // Output Utxos
    let out_chain_id = BnFr::from(0u32);
    let out_amount = BnFr::from(10u32);
    let out_utxo1 = prover
        .new_utxo(out_chain_id, out_amount, None, None, None, rng)
        .unwrap();
    let out_utxo2 = prover
        .new_utxo(out_chain_id, out_amount, None, None, None, rng)
        .unwrap();
    let out_utxos = [out_utxo1, out_utxo2];

    let leaf0 = in_utxos[0].commitment;
    let (in_path0, _) = prover.setup_tree(&vec![leaf0], 0).unwrap();
    let root0 = in_path0.root_hash(&leaf0).unwrap().inner();
    let leaf1 = in_utxos[1].commitment;
    let (in_path1, _) = prover.setup_tree(&vec![leaf1], 0).unwrap();
    let root1 = in_path1.root_hash(&leaf1).unwrap().inner();

    let in_leaves = [vec![leaf0], vec![leaf1]];
    let in_indices = [0; 2];
    let in_root_set = [root0, root1];

    let (circuit, .., pub_ins) = prover
        .setup_circuit_with_utxos(
            public_amount,
            ext_data_hash,
            in_root_set,
            in_indices,
            in_leaves,
            in_utxos,
            out_utxos,
        )
        .unwrap();

    let (proving_key, verifying_key) = setup_keys::<Bn254, _, _>(circuit.clone(), rng).unwrap();
    let proof = prove::<Bn254, _, _>(circuit, &proving_key, rng).unwrap();
    let res = verify::<Bn254>(&pub_ins, &verifying_key, &proof).unwrap();

    assert!(!res);
}

#[test]
#[ignore]
fn should_fail_with_same_nullifier() {
    let rng = &mut test_rng();
    let curve = Curve::Bn254;
    let params2: PoseidonParameters<BnFr> = setup_params_x5_2(curve);
    let params3: PoseidonParameters<BnFr> = setup_params_x5_3(curve);
    let params4: PoseidonParameters<BnFr> = setup_params_x5_4(curve);
    let params5: PoseidonParameters<BnFr> = setup_params_x5_5(curve);
    let prover = VAnchorProverBn2542x2::new(params2, params3, params4, params5);

    let public_amount = BnFr::from(0u32);
    let ext_data_hash = BnFr::rand(rng);

    // Input Utxos
    let in_chain_id = BnFr::from(0u32);
    let in_amount = BnFr::from(5u32);
    let index = BnFr::from(0u32);
    let in_utxo1 = prover
        .new_utxo(in_chain_id, in_amount, Some(index), None, None, rng)
        .unwrap();

    // Both inputs are the same -- attempt of double spending
    let in_utxos = [in_utxo1, in_utxo1];

    // Output Utxos
    let out_chain_id = BnFr::from(0u32);
    let out_amount = BnFr::from(10u32);
    let out_utxo1 = prover
        .new_utxo(out_chain_id, out_amount, None, None, None, rng)
        .unwrap();
    let out_utxo2 = prover
        .new_utxo(out_chain_id, out_amount, None, None, None, rng)
        .unwrap();
    let out_utxos = [out_utxo1, out_utxo2];

    let leaf0 = in_utxos[0].commitment;
    let (in_path0, _) = prover.setup_tree(&vec![leaf0], 0).unwrap();
    let root0 = in_path0.root_hash(&leaf0).unwrap().inner();
    let leaf1 = in_utxos[1].commitment;
    let (in_path1, _) = prover.setup_tree(&vec![leaf1], 0).unwrap();
    let root1 = in_path1.root_hash(&leaf1).unwrap().inner();

    let in_leaves = [vec![leaf0], vec![leaf1]];
    let in_indices = [0; 2];
    let in_root_set = [root0, root1];

    let (circuit, .., pub_ins) = prover
        .setup_circuit_with_utxos(
            public_amount,
            ext_data_hash,
            in_root_set,
            in_indices,
            in_leaves,
            in_utxos,
            out_utxos,
        )
        .unwrap();

    let (proving_key, verifying_key) = setup_keys::<Bn254, _, _>(circuit.clone(), rng).unwrap();
    let proof = prove::<Bn254, _, _>(circuit, &proving_key, rng).unwrap();
    let res = verify::<Bn254>(&pub_ins, &verifying_key, &proof).unwrap();

    assert!(!res);
}

#[test]
fn should_fail_with_inconsistent_input_output_values() {
    let rng = &mut test_rng();
    let curve = Curve::Bn254;
    let params2: PoseidonParameters<BnFr> = setup_params_x5_2(curve);
    let params3: PoseidonParameters<BnFr> = setup_params_x5_3(curve);
    let params4: PoseidonParameters<BnFr> = setup_params_x5_4(curve);
    let params5: PoseidonParameters<BnFr> = setup_params_x5_5(curve);
    let prover = VAnchorProverBn2542x2::new(params2, params3, params4, params5);

    let public_amount = BnFr::from(10u32);
    let ext_data_hash = BnFr::rand(rng);

    // Input Utxos
    let in_chain_id = BnFr::from(0u32);
    // Input amount too high
    let in_amount = BnFr::from(10u32);
    let index = BnFr::from(0u32);
    let in_utxo1 = prover
        .new_utxo(in_chain_id, in_amount, Some(index), None, None, rng)
        .unwrap();
    let in_utxo2 = prover
        .new_utxo(in_chain_id, in_amount, Some(index), None, None, rng)
        .unwrap();
    let in_utxos = [in_utxo1, in_utxo2];

    // Output Utxos
    let out_chain_id = BnFr::from(0u32);
    let out_amount = BnFr::from(10u32);
    let out_utxo1 = prover
        .new_utxo(out_chain_id, out_amount, None, None, None, rng)
        .unwrap();
    let out_utxo2 = prover
        .new_utxo(out_chain_id, out_amount, None, None, None, rng)
        .unwrap();
    let out_utxos = [out_utxo1, out_utxo2];

    let leaf0 = in_utxos[0].commitment;
    let (in_path0, _) = prover.setup_tree(&vec![leaf0], 0).unwrap();
    let root0 = in_path0.root_hash(&leaf0).unwrap().inner();
    let leaf1 = in_utxos[1].commitment;
    let (in_path1, _) = prover.setup_tree(&vec![leaf1], 0).unwrap();
    let root1 = in_path1.root_hash(&leaf1).unwrap().inner();

    let in_leaves = [vec![leaf0], vec![leaf1]];
    let in_indices = [0; 2];
    let in_root_set = [root0, root1];

    let (circuit, .., pub_ins) = prover
        .setup_circuit_with_utxos(
            public_amount,
            ext_data_hash,
            in_root_set,
            in_indices,
            in_leaves,
            in_utxos,
            out_utxos,
        )
        .unwrap();

    let (proving_key, verifying_key) = setup_keys::<Bn254, _, _>(circuit.clone(), rng).unwrap();
    let proof = prove::<Bn254, _, _>(circuit, &proving_key, rng).unwrap();
    let res = verify::<Bn254>(&pub_ins, &verifying_key, &proof).unwrap();

    assert!(!res);
}

#[test]
fn should_fail_with_big_amount() {
    let rng = &mut test_rng();
    let curve = Curve::Bn254;
    let params2: PoseidonParameters<BnFr> = setup_params_x5_2(curve);
    let params3: PoseidonParameters<BnFr> = setup_params_x5_3(curve);
    let params4: PoseidonParameters<BnFr> = setup_params_x5_4(curve);
    let params5: PoseidonParameters<BnFr> = setup_params_x5_5(curve);
    let prover = VAnchorProverBn2542x2::new(params2, params3, params4, params5);

    // 2^248
    let limit = BnFr::from_str(
        "452312848583266388373324160190187140051835877600158453279131187530910662656",
    )
    .unwrap();

    let public_amount = BnFr::zero();
    let ext_data_hash = BnFr::rand(rng);

    // Input Utxos
    let in_chain_id = BnFr::from(0u32);
    let in_amount = BnFr::from(limit + BnFr::one());
    let index = BnFr::from(0u32);
    let in_utxo1 = prover
        .new_utxo(in_chain_id, in_amount, Some(index), None, None, rng)
        .unwrap();
    let in_utxo2 = prover
        .new_utxo(in_chain_id, in_amount, Some(index), None, None, rng)
        .unwrap();
    let in_utxos = [in_utxo1, in_utxo2];

    // Output Utxos
    let out_chain_id = BnFr::from(0u32);
    let out_amount = BnFr::from(10u32);
    let out_utxo1 = prover
        .new_utxo(out_chain_id, out_amount, None, None, None, rng)
        .unwrap();
    let out_utxo2 = prover
        .new_utxo(out_chain_id, out_amount, None, None, None, rng)
        .unwrap();
    let out_utxos = [out_utxo1, out_utxo2];

    let leaf0 = in_utxos[0].commitment;
    let (in_path0, _) = prover.setup_tree(&vec![leaf0], 0).unwrap();
    let root0 = in_path0.root_hash(&leaf0).unwrap().inner();
    let leaf1 = in_utxos[1].commitment;
    let (in_path1, _) = prover.setup_tree(&vec![leaf1], 0).unwrap();
    let root1 = in_path1.root_hash(&leaf1).unwrap().inner();

    let in_leaves = [vec![leaf0], vec![leaf1]];
    let in_indices = [0; 2];
    let in_root_set = [root0, root1];

    let (circuit, .., pub_ins) = prover
        .setup_circuit_with_utxos(
            public_amount,
            ext_data_hash,
            in_root_set,
            in_indices,
            in_leaves,
            in_utxos,
            out_utxos,
        )
        .unwrap();

    let (proving_key, verifying_key) = setup_keys::<Bn254, _, _>(circuit.clone(), rng).unwrap();
    let proof = prove::<Bn254, _, _>(circuit, &proving_key, rng).unwrap();
    let res = verify::<Bn254>(&pub_ins, &verifying_key, &proof).unwrap();

    assert!(!res);
}

#[test]
fn should_fail_with_invalid_public_input() {
    let rng = &mut test_rng();
    let curve = Curve::Bn254;
    let params2: PoseidonParameters<BnFr> = setup_params_x5_2(curve);
    let params3: PoseidonParameters<BnFr> = setup_params_x5_3(curve);
    let params4: PoseidonParameters<BnFr> = setup_params_x5_4(curve);
    let params5: PoseidonParameters<BnFr> = setup_params_x5_5(curve);
    let prover = VAnchorProverBn2542x2::new(params2, params3, params4, params5);

    let public_amount = BnFr::from(0u32);
    let ext_data_hash = BnFr::rand(rng);

    // Input Utxos
    let in_chain_id = BnFr::from(0u32);
    let in_amount = BnFr::from(5u32);
    let index = BnFr::from(0u32);
    let in_utxo1 = prover
        .new_utxo(in_chain_id, in_amount, Some(index), None, None, rng)
        .unwrap();
    let in_utxo2 = prover
        .new_utxo(in_chain_id, in_amount, Some(index), None, None, rng)
        .unwrap();
    let in_utxos = [in_utxo1, in_utxo2];

    // Output Utxos
    let out_chain_id = BnFr::from(0u32);
    let out_amount = BnFr::from(10u32);
    let out_utxo1 = prover
        .new_utxo(out_chain_id, out_amount, None, None, None, rng)
        .unwrap();
    let out_utxo2 = prover
        .new_utxo(out_chain_id, out_amount, None, None, None, rng)
        .unwrap();
    let out_utxos = [out_utxo1, out_utxo2];

    let leaf0 = in_utxos[0].commitment;
    let (in_path0, _) = prover.setup_tree(&vec![leaf0], 0).unwrap();
    let root0 = in_path0.root_hash(&leaf0).unwrap().inner();
    let leaf1 = in_utxos[1].commitment;
    let (in_path1, _) = prover.setup_tree(&vec![leaf1], 0).unwrap();
    let root1 = in_path1.root_hash(&leaf1).unwrap().inner();

    let in_leaves = [vec![leaf0], vec![leaf1]];
    let in_indices = [0; 2];
    let in_root_set = [root0, root1];

    let (circuit, .., pub_ins) = prover
        .setup_circuit_with_utxos(
            public_amount,
            ext_data_hash,
            in_root_set,
            in_indices,
            in_leaves,
            in_utxos,
            out_utxos,
        )
        .unwrap();

    let truncated_public_inputs = &pub_ins[2..];
    let (proving_key, verifying_key) = setup_keys::<Bn254, _, _>(circuit.clone(), rng).unwrap();
    let proof = prove::<Bn254, _, _>(circuit, &proving_key, rng).unwrap();

    let vk = VerifyingKey::<Bn254>::deserialize(&verifying_key[..]).unwrap();
    let proof = Proof::<Bn254>::deserialize(&proof[..]).unwrap();
    let res = Groth16::<Bn254>::verify(&vk, truncated_public_inputs, &proof);

    assert!(res.is_err());
}
