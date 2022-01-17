# Build each crate with isolated features
cargo build --release --no-default-features
cargo build --release --no-default-features --features r1cs
cargo build --release --no-default-features --features default_poseidon
cargo build --release --no-default-features --features default_mimc
cargo build --release --all-features