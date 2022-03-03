cargo build \
--target wasm32-unknown-unknown \
--release \
--no-default-features \
--workspace \
--exclude arkworks-circom-verifier \
--exclude arkworks-benchmarks \
--exclude arkworks-plonk-circuits \
--exclude arkworks-plonk-gadgets