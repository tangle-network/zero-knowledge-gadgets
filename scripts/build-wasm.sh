cargo build \
--target wasm32-unknown-unknown \
--release \
--no-default-features \
--workspace \
--exclude arkworks-circom-verifier \
--exclude akworks-plonk-circuits \
--exclude arkworks-benchmarks
