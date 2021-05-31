pub mod bridge_data;

#[cfg(feature = "r1cs")]
pub mod constraints;

pub trait Arbitrary {
	type Input: Clone + Default;
}
