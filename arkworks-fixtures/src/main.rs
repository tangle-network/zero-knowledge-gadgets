use arkworks_circuits::setup::common::{setup_keys, setup_keys_unchecked};
use arkworks_circuits::setup::anchor::AnchorProverSetupBn254_30;
use arkworks_utils::utils::common::{setup_params_x5_3, setup_params_x5_4, Curve};
use ark_std::test_rng;
use ark_bn254::Fr as Bn254Fr;
use ark_bn254::Bn254;
use std::fs::write;
use std::env::current_dir;

fn main() {
	let mut rng = test_rng();
	let curve = Curve::Bn254;
	let params3 = setup_params_x5_3::<Bn254Fr>(curve);
	let params4 = setup_params_x5_4::<Bn254Fr>(curve);

	let prover = AnchorProverSetupBn254_30::new(params3, params4);
	let (circuit, ..) = prover.setup_random_circuit(&mut rng).unwrap();

	let (pk, vk) = setup_keys::<Bn254, _, _>(circuit.clone(), &mut rng).unwrap();
	let (pk_unchecked, vk_unchecked) = setup_keys_unchecked::<Bn254, _, _>(circuit, &mut rng).unwrap();

	let current_path = current_dir().unwrap();
	let path = format!("{}/data", current_path.display());
	write(format!("{}/pk.bin", path), pk).unwrap();
	write(format!("{}/vk.bin", path), vk).unwrap();
	write(format!("{}/pk_unchecked.bin", path), pk_unchecked).unwrap();
	write(format!("{}/vk_unchecked.bin", path), vk_unchecked).unwrap();

}
