# Build each crate with isolated features

# Native Gadgets
cargo build -p arkworks-native-gadgets --release --no-default-features && \
cargo build -p arkworks-native-gadgets --release --no-default-features --features parallel && \
cargo build -p arkworks-native-gadgets --release --all-features && \

# PLONK gadgets
cargo build -p arkworks-plonk-gadgets --release --no-default-features && \
cargo build -p arkworks-plonk-gadgets --release && \

# PLONK circuits
cargo build -p arkworks-plonk-circuits --release --no-default-features && \
cargo build -p arkworks-plonk-circuits --release && \

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
cargo build -p arkworks-setups --release --all-features