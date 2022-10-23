BASEDIR=$(dirname "$0")

cargo test --release --features plonk --features r1cs && \
cargo test --manifest-path $BASEDIR/../plonk-circuits/Cargo.toml --release && \
cargo test --manifest-path $BASEDIR/../plonk-gadgets/Cargo.toml --release
