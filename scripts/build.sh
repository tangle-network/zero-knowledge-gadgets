# Build each crate with isolated features

# PLONK circuits
cargo build -p arkworks-plonk-circuits --release --no-default-features && \
cargo build -p arkworks-plonk-circuits --release && \

# Arkworks Circuits
cargo build -p arkworks-circuits --release --no-default-features && \
cargo build -p arkworks-circuits --release --all-features && \

# Arkworks Gadgets
cargo build -p arkworks-gadgets --release --no-default-features && \
cargo build -p arkworks-gadgets --release --no-default-features --features r1cs && \
cargo build -p arkworks-gadgets --release --all-features && \

# Arkworks Utils
cargo build -p arkworks-utils --release --no-default-features && \
cargo build -p arkworks-utils --release --no-default-features --features r1cs && \
cargo build -p arkworks-utils --release --no-default-features --features default_poseidon && \
cargo build -p arkworks-utils --release --no-default-features --features default_mimc && \
cargo build -p arkworks-utils --release --all-features