pub mod mixer_data;

#[cfg(feature = "r1cs")]
pub mod constraints;

pub trait Arbitrary {
	type Input: Clone + Default;
}
