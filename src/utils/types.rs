use crate::utils::PoseidonSbox;
use ark_ff::fields::PrimeField;
use ark_std::vec::Vec;

/// The Poseidon permutation.
#[derive(Default, Clone)]
pub struct PoseidonParameters<F: PrimeField> {
	/// The round key constants
	pub round_keys: Vec<F>,
	/// The MDS matrix to apply in the mix layer.
	pub mds_matrix: Vec<Vec<F>>,
	/// Number of full SBox rounds
	pub full_rounds: usize,
	/// Number of partial rounds
	pub partial_rounds: usize,
	/// The size of the permutation, in field elements.
	pub width: usize,
	/// The S-box to apply in the sub words layer.
	pub exponentiation: usize,
	/// The S-box to apply in the sub words layer.
	pub sbox: PoseidonSbox,
}
