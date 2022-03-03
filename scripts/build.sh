# Build each crate with isolated features

# PLONK circuits
cargo build -p arkworks-plonk-circuits --release --no-default-features && \
cargo build -p arkworks-plonk-circuits --release && \

# PLONK gadgets
cargo build -p arkworks-plonk-gadgets --release --no-default-features && \
cargo build -p arkworks-plonk-gadgets --release && \

# R1CS Circuits
cargo build -p arkworks-r1cs-circuits --release --no-default-features && \
cargo build -p arkworks-r1cs-circuits --release --all-features && \

# R1CS Gadgets
cargo build -p arkworks-r1cs-gadgets --release --no-default-features && \
cargo build -p arkworks-r1cs-gadgets --release --no-default-features --features r1cs && \
cargo build -p arkworks-r1cs-gadgets --release --all-features && \

# Arkworks Utils
cargo build -p arkworks-utils --release --no-default-features && \
cargo build -p arkworks-utils --release --no-default-features --features r1cs && \
cargo build -p arkworks-utils --release --no-default-features --features default_poseidon && \
cargo build -p arkworks-utils --release --no-default-features --features default_mimc && \
cargo build -p arkworks-utils --release --all-features