# Build each crate with isolated features
BASEDIR=$(dirname "$0")

# Native Gadgets
cargo build -p arkworks-native-gadgets --release --no-default-features && \
cargo build -p arkworks-native-gadgets --release --no-default-features --features parallel && \
cargo build -p arkworks-native-gadgets --release --all-features && \

# R1CS Gadgets
cargo build -p arkworks-r1cs-gadgets --release --no-default-features && \
cargo build -p arkworks-r1cs-gadgets --release --no-default-features --features parallel && \
cargo build -p arkworks-r1cs-gadgets --release --all-features && \

# R1CS Circuits
cargo build -p arkworks-r1cs-circuits --release --no-default-features && \
cargo build -p arkworks-r1cs-circuits --release --no-default-features --features parallel && \
cargo build -p arkworks-r1cs-circuits --release --all-features && \

# Arkworks Utils
cargo build -p arkworks-utils --release --no-default-features && \
cargo build -p arkworks-utils --release --no-default-features --features parallel && \
cargo build -p arkworks-utils --release --all-features && \

# Arkworks Setups
cargo build -p arkworks-setups --release --no-default-features && \
cargo build -p arkworks-setups --release --no-default-features --features parallel && \
cargo build -p arkworks-setups --release --no-default-features --features aead && \
cargo build -p arkworks-setups --release --all-features

# PLONK gadgets
cargo build --manifest-path $BASEDIR/../arkworks-plonk-gadgets/Cargo.toml --release --no-default-features && \
cargo build --manifest-path $BASEDIR/../arkworks-plonk-gadgets/Cargo.toml --release && \

# PLONK circuits
cargo build --manifest-path $BASEDIR/../arkworks-plonk-gadgets/Cargo.toml --release --no-default-features && \
cargo build --manifest-path $BASEDIR/../arkworks-plonk-gadgets/Cargo.toml --release