<h1 align="center">arkworks/../../../../../../../arkworks/native-gadgets/Cargo.tomlgadgets 🕸️ </h1>
<div align="center">
<a href="https://www.webb.tools/">
    <img alt="Webb Logo" src="./assets/webb-icon.svg" width="15%" height="30%" />
  </a>
  </div>
<p align="center">
    <strong>Gadgets and circuits written using the <a href="https://github.com/arkworks/../../../../../../../arkworks/native-gadgets/Cargo.tomlrs"> arkworks </a> libraries for Webb and more. 🚀  </strong>
</p>

<div align="center" >

[![GitHub tags (latest by date)](https://img.shields.io/github/v/tag/webb-tools/zero-knowledge-gadgets?style=flat-square)](https://github.com/webb-tools/zero-knowledge-gadgets/tags/latest)
[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/webb-tools/zero-knowledge-gadgets/Set-Up%20&%20Build%20&%20Test?style=flat-square)](https://github.com/webb-tools/zero-knowledge-gadgets/actions)
[![Codecov](https://img.shields.io/codecov/c/gh/webb-tools/zero-knowledge-gadgets?style=flat-square&token=JDMTR41O4W)](https://codecov.io/gh/webb-tools/relayer)
[![License Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square)](https://opensource.org/licenses/Apache-2.0)
[![Twitter](https://img.shields.io/twitter/follow/webbprotocol.svg?style=flat-square&label=Twitter&color=1DA1F2)](https://twitter.com/webbprotocol)
[![Discord](https://img.shields.io/discord/833784453251596298.svg?style=flat-square&label=Discord&logo=discord)](https://discord.gg/cv8EfJu3Tn)

</div>

<!-- TABLE OF CONTENTS -->
<h2 id="table-of-contents"> 📖 Table of Contents</h2>

<details open="open">
  <summary>Table of Contents</summary>
  <ul>
    <li><a href="#build"> Build</a></li>
    <li><a href="#publishing">Publishing to crates.io</a></li>
    <li><a href="#overview"> Project Overview </a></li>
	<ul>
        <li><a href="#gadgets">Gadgets</a></li>
        <li><a href="#circuits">Circuits</a></li>
        <li><a href="#api">API</a></li>
		<ul>
		<li><a href="#provers">Provers</a></li>
		<li><a href="#verifiers">Verifiers</a></li>
		</ul>
      </ul>
    <li><a href="#circuit">Circuits</a></li>
	<ul>
        <li><a href="#mixer">Mixer</a></li>
		<ul>
		<li><a href="#mleaf">Leaf Structure</a></li>
		<li><a href="#mpublic">Public Input Structure</a></li>
		</ul>
		<li><a href="#anchor">Anchor</a></li>
		<ul>
		<li><a href="#aleaf">Leaf Structure</a></li>
		<li><a href="#apublic">Public Input Structure</a></li>
		</ul>
		 <li><a href="#vanchor">VAnchor</a></li>
		<ul>
		<li><a href="#utxo">UTXOs</a></li>
		<li><a href="#vpublic">Public Inputs</a></li>
		</ul>
      </ul>
    <li><a href="#usage"> Usage Examples</a></li>
	<ul>
      <ul>
		 <li><a href="#mexample">Mixer Usage Example</a></li>
		</ul>
		<ul>
		 <li><a href="#aexample">Anchor Usage Example</a></li>
		</ul>
		<ul>
		 <li><a href="#vexample">VAnchor Usage Example</a></li>
		</ul>
		<ul>
		 <li><a href="#merkle">Merkle Tree Usage Example</a></li>
		</ul>
		<ul>
		 <li><a href="#param">Parameter Generation</a></li>
		</ul>
		</ul>
		<li><a href="#smart"> Usage in Smart Contracts</a></li>
		<li><a href="#grat"> Gratitude</a></li>
	</li>
</details>

<h2 id="build"> Build </h2>

To build the project run:
```
./scripts/build.sh
```
To build for wasm target, run:
```
./scripts/build-wasm.sh
```

To run the unit tests, run:

```
./scripts/test.sh
```

> **Note: All commands should be run from the root directory.**

<h2 id="publishing"> Publishing to crates.io </h2>

For version management, we use [cargo-workspaces](https://github.com/pksunkara/cargo-workspaces). We use the following flow:

1. Use `cargo-workspaces` to bump the version of all crates, using the command `cargo ws version`. This will bump the version of all the crates in the workspace, which include:
   - arkworks/../../../../../../../arkworks/native-gadgets/Cargo.tomlnative-gadgets
   - arkworks/../../../../../../../arkworks/native-gadgets/Cargo.tomlr1cs-gadgets
   - arkworks/../../../../../../../arkworks/native-gadgets/Cargo.tomlr1cs-circuits
   - arkworks/../../../../../../../arkworks/native-gadgets/Cargo.tomlsetups
   - arkworks/../../../../../../../arkworks/native-gadgets/Cargo.tomlutils
2. The previous step will only update the crates themself, but not their dependencies. So, for example, if `arkworks/../../../../../../../arkworks/native-gadgets/Cargo.tomlsetups` depend on `arkworks/../../../../../../../arkworks/native-gadgets/Cargo.tomlutils`, the dependency version will not be updated. **We have to do this manually.**
3. Commit all the changes.
4. Publish the crates with following command: `cargo ws publish --allow-branch [current_branch] --from-git`.

   The `--allow-branch` allows us to publish the crates on any branch. By default, it's only allowed on `master`. If you wish to publish from the `master`, this option is not needed.

   The `--from-git` flag specifies that the crates should be published as is, bypassing the additional version bump that comes with the `cargo ws publish` command.

<h1 id="overview"> Overview </h1>

This repo contains zero-knowledge gadgets & circuits for different end applications such as a mixer and an anchor that can be integrated into compatible blockchain and smart contract protocols. The repo is split into three main parts:

- Intermediate modular gadgets
- The circuits that consume these gadgets
- Basic utilities used by the gadgets and the circuits (like parameters for Poseidon hash function)

<h2 id="gadgets"> Gadgets </h2>

You can think of gadgets as intermediate computations and constraint systems that you compose to build a more complete zero-knowledge proof of knowledge statement. They can also be used as-is by simply extending the arkworks `ConstraintSynthesizer`. An example using dummy computations can be found in the [dummy circuit](https://github.com/webb-tools/zero-knowledge-gadgets/blob/master/arkworks/../../../../../../../arkworks/native-gadgets/Cargo.tomlr1cs-circuits/src/basic.rs).

In this repo you will find gadgets for:

- Poseidon [Native](https://github.com/webb-tools/zero-knowledge-gadgets/tree/master/arkworks/../../../../../../../arkworks/native-gadgets/Cargo.tomlnative-gadgets/src/poseidon), [R1CS](https://github.com/webb-tools/zero-knowledge-gadgets/tree/master/arkworks/../../../../../../../arkworks/native-gadgets/Cargo.tomlr1cs-gadgets/src/poseidon), [PLONK](https://github.com/webb-tools/zero-knowledge-gadgets/tree/master/arkworks/../../../../../../../arkworks/native-gadgets/Cargo.tomlplonk-gadgets/src/poseidon)
- Merkle tree [Native](https://github.com/webb-tools/zero-knowledge-gadgets/blob/master/arkworks/../../../../../../../arkworks/native-gadgets/Cargo.tomlnative-gadgets/src/merkle_tree.rs), [R1CS](https://github.com/webb-tools/zero-knowledge-gadgets/blob/master/arkworks/../../../../../../../arkworks/native-gadgets/Cargo.tomlr1cs-gadgets/src/merkle_tree.rs), [PLONK](https://github.com/webb-tools/zero-knowledge-gadgets/blob/master/arkworks/../../../../../../../arkworks/native-gadgets/Cargo.tomlplonk-gadgets/src/merkle_tree.rs)
- Set [R1CS](https://github.com/webb-tools/zero-knowledge-gadgets/blob/master/arkworks/../../../../../../../arkworks/native-gadgets/Cargo.tomlr1cs-gadgets/src/set.rs), [PLONK](https://github.com/webb-tools/zero-knowledge-gadgets/blob/master/arkworks/../../../../../../../arkworks/native-gadgets/Cargo.tomlplonk-gadgets/src/set.rs)

Poseidon hashing function matches the [circom implementation](https://github.com/iden3/circomlib/blob/master/circuits/poseidon.circom). Implemented based on this paper: https://eprint.iacr.org/2019/458.pdf.

Set membership - Used for proving that some value is inside the set in a zero-knowledge manner. That is done by first calculating the differences (denoted as `diffs`) from the `target` (a value that we are checking the membership of) and each value from the set. We then calculate the sum of products of a target and each element in the set. If one value from the `diffs` is 0 (meaning that its equal to `target`) the product will be zero, thus meaning that the `target` is in the set.

<h2 id="circuits"> Circuits </h2>

In this repo you will find circuits for:

- Mixer [R1CS](https://github.com/webb-tools/zero-knowledge-gadgets/blob/master/arkworks/../../../../../../../arkworks/native-gadgets/Cargo.tomlr1cs-circuits/src/mixer.rs), [PLONK](https://github.com/webb-tools/zero-knowledge-gadgets/blob/master/arkworks/../../../../../../../arkworks/native-gadgets/Cargo.tomlplonk-circuits/src/mixer.rs)
- Anchor [R1CS](https://github.com/webb-tools/zero-knowledge-gadgets/blob/master/arkworks/../../../../../../../arkworks/native-gadgets/Cargo.tomlr1cs-circuits/src/anchor.rs), [PLONK](https://github.com/webb-tools/zero-knowledge-gadgets/blob/master/arkworks/../../../../../../../arkworks/native-gadgets/Cargo.tomlplonk-circuits/src/anchor.rs)
- VAnchor [R1CS](https://github.com/webb-tools/zero-knowledge-gadgets/blob/master/arkworks/../../../../../../../arkworks/native-gadgets/Cargo.tomlr1cs-circuits/src/vanchor.rs), [PLONK](https://github.com/webb-tools/zero-knowledge-gadgets/blob/master/arkworks/../../../../../../../arkworks/native-gadgets/Cargo.tomlplonk-circuits/src/vanchor.rs)

<h2 id="api"> Setup API </h2>

For the circuits implemented in this repo, we have setups in the [setup](https://github.com/webb-tools/zero-knowledge-gadgets/tree/master/arkworks/../../../../../../../arkworks/native-gadgets/Cargo.tomlcircuits/src/setup) directory. This folder contains circuit-specific setup helpers for creating proofs for each circuit as well as helpers for Poseidon, Merkle tree, proving/verifying key generation, verifier helper, etc.

Each application-specific folder in `arkworks/../../../../../../../arkworks/native-gadgets/Cargo.tomlsetups/[r1cs | plonk]` encapsulates the API for the full setup of a zero-knowledge proof for that circuit. There are currently application-specific gadgets for:

- Mixers: [R1CS](https://github.com/webb-tools/zero-knowledge-gadgets/tree/master/arkworks/../../../../../../../arkworks/native-gadgets/Cargo.tomlsetups/src/r1cs/mixer), PLONK (TBA)
- Anchors: [R1CS](https://github.com/webb-tools/zero-knowledge-gadgets/tree/master/arkworks/../../../../../../../arkworks/native-gadgets/Cargo.tomlsetups/src/r1cs/anchor), PLONK (TBA)
- VAnchors: [R1CS](https://github.com/webb-tools/zero-knowledge-gadgets/tree/master/arkworks/../../../../../../../arkworks/native-gadgets/Cargo.tomlsetups/src/r1cs/vanchor), PLONK (TBA)

For tests and instantiations of the gadgets used to compose each of these larger-scale application gadgets, refer to the test.rs files within that directory. Most of the tests and implementations in this repo use Groth16 proofs and setups for the zero-knowledge gadgets. Occasionally Marlin zkSNARKs are used for intermediate gadget tests. There are no application-specific instantiations of gadgets that use Marlin however but pull requests are welcome to create them.

<h3 id="provers"> Provers </h3>

Provers for these zero-knowledge gadgets are meant to be used by client or server applications. These are compute-intensive and require access to random number generators.

<h3 id="verifiers"> Verifiers </h3>

Verifiers for these zero-knowledge gadgets are meant to be used by client, server, or blockchain applications. These verifiers are WASM compatible and can be embedded in WASM-friendly environments like blockchains that allow smart contracts which are written in Rust. The APIs are consistent across a particular proving system such as Groth16 and are straightforward to integrate into blockchain runtimes such as [Substrate](https://github.com/paritytech/substrate).

<h1 id="circuit"> Circuits </h1>

<h2 id= "mixer"> Mixer </h2>

The mixer gadget is built to be deployed on Rust-based blockchain protocols. The motivation is that there will be an on-chain Merkle tree & escrow system where users must deposit assets to insert a leaf into the Merkle tree. This is considered a **deposit** into the mixer. Next, the user can generate a zero-knowledge proof of membership of a leaf in the Merkle tree by instantiating a Mixer circuit, populating it with the leaves on-chain, providing private and public inputs locally to the helper utilities generated from our API, and subsequently generating a zero-knowledge proof. They can then submit this proof on-chain to an on-chain verifier. This is considered a **withdrawal** from the mixer. We provide an example instantiation of the mixer circuit setup, proof process, and proof verification process below. But first, we remark on the structure of the mixer to illuminate some of our design decisions.

Any instantiation of a zero-knowledge mixer circuit requires that all data provided is formatted as expected. What this means is that there is a specific structure of data that must be provided to the prover. This extends as far down to the preimage of the leaves such that if data does not adhere to the expected format or protocol then it will be impossible to generate compatible zero-knowledge proofs for on-chain verification for such proofs.

<h3 id="mleaf" > Leaf structure </h3>

The structure of the mixer leaf is a hash of 2 random field elements (the secret and the nullifier) from a field (BLS381 or BN254) based on the instantiation of your circuit.

<h3 id="mpublic"> Public input structure </h3>

The structure of public inputs must be the ordered array of the following data taken from Tornado Cash's design & architecture.

1. Nullifier hash
2. Merkle root
3. Arbitrary Input (Not included in the computation)

These parameters are provided to zero-knowledge proofs as public inputs and are geared towards on-chain customizability.

- Nullifier hash is the hash of the randomly generated nullifier. We are hashing it so that the preimage remains hidden, to prevent front-run attacks.
- Merkle root is the root hash of the Merkle tree we are proving the leaf membership in.
- For an on-chain cryptocurrency mixer, we must provide a private transaction relaying service that the user decides a prior, as well as paying the fee for that service. This data is included in arbitrary input -- by doing a hash of these values (relayer address, fee, recipient, etc.).

It's worth mentioning that all the values included in arbitrary input bind the proof to those values. This helps prevent tampering if for example, a user wants to change the recipient after proof generation. If the public inputs change for a proof submitted on-chain, the proof will fail with the underlying security of the zkSNARK. We leverage this design to provide the right incentives for users and relayers of the end application, an on-chain cryptocurrency mixer.

<h2 id="anchor"> Anchor </h2>

Anchor protocol is very similar to the mixer. Instead of proving the membership inside one Merkle tree, we are proving the inclusion in one of many Merkle trees. These trees can live on many different blockchains, and if the Merkle tree states are synced across chains, this will allow us to make cross-chain anonymous transactions. A higher-level overview of how Anchor works:

1. We are computing the leaf commitment using the Poseidon hash function passing: `secret` (private input), `nullifier` (private input) and chain id (public input).
2. We are computing the nullifier hash using the Poseidon hash function, passing: `nullifier` (private input)
3. We are calculating the root hash using the calculated leaf and the path (private input)
4. We are checking if the calculated root is inside the set (public input) using the SetGadget.

<h3 id="aleaf"> Leaf structure </h3>

Leaf structure is similar to that of a mixer, except we are also introducing a chain id as public input. Chain id ensures that you can only withdraw on one chain, thus preventing double-spending. So, an Anchor leaf consists of a `secret` (random value), `nullifier` (random value) and `chain_id`.

<h3 id="apublic"> Public input structure </h3>

1. Chain Id
1. Nullifier hash
1. Merkle root set
1. Arbitrary Input

- Chain Id - ensures that you only withdraw on one chain and prevents double-spending.
- Nullifier hash is the same as in the mixer, except it's used in a multi-chain context. Meaning it will be registered on a chain that has an Id the same as Chain Id (our public input).
- Merkle root set is an array of root hashes. It consists of a local root (root on the chain the withdrawal is made) and roots from other chains that are connected to the local one.
- Arbitrary Input has the same purpose as the Mixers. It consists of: Recipient, Relayer, Fee, Refund, and Commitment (Commitment is used for refreshing your leaf -- meaning inserting a new leaf as a replacement for the old one if the value of commitment is non-zero).

<h2 id="vanchor"> VAnchor </h2>

VAnchor is short for Variable Anchor as it introduces the concept of variable deposit amounts. It supports anonymous join-split functionality which allows joining multiple previous deposits into multiple new deposits. VAnchor also supports cross-chain transactions. Higher-level overview of how VAnchor works:

1. Using the input Utxos and corresponding Merkle paths, we are calculating the root hashes for each Utxo.
2. We are checking if the root hash of each Utxo is a member of a root set. We are doing this with SetGadget.
3. Using the output Utxos we are proving the leaf creation from passed private inputs.
4. We are making sure that the sum of input amounts plus the public amount is equal to the sum of output amounts.

<h3 id="utxo"> UTXOs </h3>

UTXOs stand for unspent transaction outputs. Each UTXO represents a shielded balance that can be spent in the system. To create new UTXOs one must prove ownership over existing UTXOs that have at least as much balance as the newly created ones.

UTXOs contains a value, denoting the amount contained in the UTXO, the chain ID where the UTXO is meant to be spent, and secret data relevant for creating zero-knowledge proofs of ownership and membership over.

UTXOs are deposited and stored in on-chain Merkle trees first by serializing its components and then by hashing the serialized data before insertion. Each hash can be considered a commitment to a UTXO. To create new UTXOs from old ones, users must submit valid zero-knowledge proofs that satisfy constraints around the consistency of values and membership within a set of Merkle roots.

<h3 id="vpublic"> Public inputs </h3>

1. Public amount
2. Arbitrary input
3. Array of Nullifier hashes for each Utxo
4. Array of Leaf commitments for each Utxo
5. Chain id where the transaction is made
6. Merkle root set

- Public amount specifies the amount being deposited or withdrawn. A negative value means that we are withdrawing and positive means we are depositing.
- Arbitrary input is not included in the computation.
- Array of nullifier hashes relates to the input Utxos, or the Utxos we want to spend
- Array of leaf commitments relates to the output Utxos, or the Utxos we want to deposit
- Chain Id and Merkle root set remain the same as in the Anchor

<h1 id="usage"> Example usage of the API </h1>

<h2 id="mexample"> Mixer - Generating leaf commitments and zero-knowledge proof </h2>

```rust
use arkworks_setups::{
	common::{Leaf, MixerProof},
	r1cs::mixer::MixerR1CSProver,
	Curve, MixerProver,
};

// Setting up the constants
// Default leaf in Merkle Tree
const DEFAULT_LEAF: [u8; 32] = [0u8; 32];
// Merkle tree heigth (or depth)
const TREE_HEIGHT: usize = 30;

// Setting up the types
type Bn254 = ark_bn254::Bn254;
type MixerR1CSProver_Bn254_30 = MixerR1CSProver<Bn254, TREE_HEIGHT>;

// Random leaf creating
let Leaf {
	secret_bytes,
	nullifier_bytes,
	leaf_bytes,
	nullifier_hash_bytes,
	..
} = MixerR1CSProver_Bn254_30::create_random_leaf(curve, rng)?

// Or in case you want to specify you own secret and nullifier
let Leaf {
	leaf_bytes,
	nullifier_hash_bytes,
	..
} = MixerR1CSProverBn254_30::create_leaf_with_privates(
	curve,
	secret_bytes,
	nullifier_bytes,
)?;

// Proof generation
let MixerProof {
	proof,
	..
} = MixerR1CSProver_Bn254_30::create_proof(
	curve,
	secret_bytes,
	nullifier_bytes,
	leaves,
	index,
	recipient_bytes,
	relayer_bytes,
	fee_value,
	refund_value,
	pk_bytes,
	DEFAULT_LEAF,
	rng,
)?;
```

<h2 id="aexample"> Anchor - Generating leaf commitments and zero-knowledge proof </h2>

```rust
use arkworks_native_gadgets::poseidon::Poseidon;
use arkworks_setups::{
	common::{
		setup_params,
		setup_tree_and_create_path,
		AnchorProof,
		Leaf,
	},
	r1cs::anchor::AnchorR1CSProver,
	AnchorProver, Curve,
};

// Setting up the constants
// Default leaf used in Merkle Tree
const DEFAULT_LEAF: [u8; 32] = [0u8; 32];
// Merkle tree depth (or height)
const TREE_DEPTH: usize = 30;
// Number of anchors (Merkle trees we are proving the membership in)
const ANCHOR_CT: usize = 2;

type Bn254 = ark_bn254::Bn254;
type AnchorR1CSProver_Bn254_30_2 = AnchorR1CSProver<
	Bn254,
	TREE_DEPTH,
	ANCHOR_CT
>;

// Creating a leaf
let Leaf {
	secret_bytes,
	nullifier_bytes,
	leaf_bytes,
	nullifier_hash_bytes,
	..
} = AnchorR1CSProver_Bn254_30_2::create_random_leaf(
	curve,
	chain_id,
	rng
)?;

// Or in case you want to specify you own secret and nullifier
let Leaf {
	leaf_bytes,
	nullifier_hash_bytes,
	..
} = AnchorR1CSProver_Bn254_30_2::create_leaf_with_privates(
	curve,
	chain_id,
	secret_bytes,
	nullifier_bytes,
)?;

// Creating the proof
let AnchorProof {
	proof,
	..
} = AnchorR1CSProver_Bn254_30_2::create_proof(
	curve,
	chain_id,
	secret_bytes,
	nullifier_bytes,
	leaves,
	index,
	roots_raw,
	recipient_bytes,
	relayer_bytes,
	fee_value,
	refund_value,
	commitment_bytes,
	pk_bytes,
	DEFAULT_LEAF,
	rng,
)?
```

<h2 id="vexample"> VAnchor - Generating Utxos and zero-knowledge proof </h2>

```rust
use arkworks_setups::{
	common::{
		prove_unchecked,
		setup_params,
		setup_tree_and_create_path
	},
	r1cs::vanchor::VAnchorR1CSProver,
	utxo::Utxo,
	Curve, VAnchorProver,
};

// Default leaf for the Merkle Tree
const DEFAULT_LEAF: [u8; 32] = [0u8; 32];
// Merkle tree depth (or heigth)
const TREE_DEPTH: usize = 30;
// Number of anchors (Merkle trees we are proving the membership in)
const ANCHOR_CT: usize = 2;
// Number of input transactions
const NUM_INS: usize = 2;
// Number of output transactions
const NUM_OUTS: usize = 2;

type Bn254 = ark_bn254::Bn254;

type VAnchorProver_Bn254_30_2x2 = VAnchorR1CSProver<
	Bn254,
	TREE_DEPTH,
	ANCHOR_CT,
	NUM_INS,
	NUM_OUTS
>;

// Input Utxo number 1
let in_utxo_1 = VAnchorProver_Bn254_30_2x2::create_random_utxo(
	curve,
	in_chain_id_1,
	in_amount_1,
	in_index_1,
	rng,
)?;

// Input Utxo number 2
let in_utxo_2 = VAnchorProver_Bn254_30_2x2::create_random_utxo(
	curve,
	in_chain_id_2,
	in_amount_2,
	in_index_2,
	rng,
)?;

// Output Utxo number 1
let out_utxo_1 = VAnchorProver_Bn254_30_2x2::create_random_utxo(
	curve,
	out_chain_id_1,
	out_amount_1,
	out_index_1,
	rng,
)?;

// Output Utxo number 2
let out_utxo_2 = VAnchorProver_Bn254_30_2x2::create_random_utxo(
	curve,
	out_chain_id_2,
	out_amount_2,
	out_index_2,
	rng,
)?;

// Making an array of Utxos
let in_utxos = [in_utxo_1, in_utxo_2];
let out_utxos = [out_utxo_1, out_utxo_2];

// Generating proof
let VAnchorProof {
	proof,
	..
} = VAnchorProver_Bn254_30_2x2::create_proof(
	curve,
	chain_id,
	public_amount,
	ext_data_hash,
	in_root_set,
	in_indices,
	in_leaves,
	in_utxos,
	out_utxos,
	pk_bytes,
	DEFAULT_LEAF,
	rng,
)?;
```

<h2 id="merkle"> Merkle Tree - Generating the Sparse Merkle Tree and Merkle path </h2>

```rust
// NOTE: This is optional and for tests only.
// There should be an on-chain mechanism for
// storing the roots of connected anchors,
// and way of fetching them before passing them
// into the circuits
let params3 = setup_params::<Bn254Fr>(curve, 5, 3);
let poseidon3 = Poseidon::new(params3);
let (tree, path) = setup_tree_and_create_path::<
	Bn254Fr,
	Poseidon<Bn254Fr>,
	TREE_DEPTH
>(
	&poseidon3,
	&leaves_f,
	index,
	&DEFAULT_LEAF,
)?;
let root = tree.root();
// or
let root = path.calculate_root(&leaf, &poseidon3)?
```

<h2 id="param"> Parameter generation </h2>

Parameter for the sage [script](https://github.com/webb-tools/bulletproof-gadgets/tree/main/src/crypto_constants/data/poseidon).

<h1 id="smart"> Usage in smart contracts </h1>

4 things need to be prepared before using the circuits inside an on-chain smart contract application or similar.

1. Generated proving and verifying keys.
2. Storing the verifying key inside on-chain storage.
3. An on-chain Merkle Tree data structure.
4. A data structure for used nullifier hashes inside on-chain storage.
5. Functionality for long-term storage of encrypted notes that contain the preimage of the leaf commitments.

Once these points are satisfied, we can successfully implement a Mixer/Anchor/VAnchor application. In the example of Mixer, the order of events goes as follows:

1. A user sends the proof along with public inputs:
   - Nullifier Hash
   - Merkle root
   - Arbitrary data
2. We check if the root is the same as the on-chain Merkle root.
3. We verify the proof using the on-chain verifying key.
4. We register the nullifier hash as used, to prevent a double-spending attack.

Examples of implementations of these protocols:

- Mixer - [Substrate Pallet](https://github.com/webb-tools/protocol-substrate/blob/main/pallets/mixer/src/lib.rs), [Cosmos (CosmWasm smart contracts)](https://github.com/webb-tools/protocol-cosmwasm/blob/main/contracts/mixer/src/contract.rs)
- Anchor - [Substrate Pallet](https://github.com/webb-tools/protocol-substrate/blob/main/pallets/anchor/src/lib.rs), [Cosmos (CosmWasm smart contracts)](https://github.com/webb-tools/protocol-cosmwasm/blob/main/contracts/anchor/src/contract.rs), [Ethereum (Solidity smart contracts)](https://github.com/webb-tools/protocol-solidity/tree/main/contracts/anchors)
- VAnchor [Substrate Pallet](https://github.com/webb-tools/protocol-substrate/blob/main/pallets/vanchor/src/lib.rs), [Ethereum (Solidity smart contracts)](https://github.com/webb-tools/protocol-solidity/tree/main/contracts/vanchors)

Links to relayer services for these protocols:

- [Mixer/Anchor](https://github.com/webb-tools/relayer/blob/main/src/handler.rs)

Links to trusted setup ceremony examples:

- [aleo-setup](https://github.com/AleoHQ/aleo-setup)
- [celo-setup](https://github.com/celo-org/snark-setup)

<h1 id="smart"> Test </h1>

- You can run all the `arkworks/../../../../../../../arkworks/native-gadgets/Cargo.tomlsetups` test by running the command
   `cargo test --features r1cs,plonk --release`

- You can run a specific test by specifying the name of the test to run with the command 
   `cargo test setup_and_prove_2_anchors --features r1cs,plonk --release`


<h1 id="grat"> Gratitude </h1>

We are grateful to the arkworks community for their open-source first approach to zero-knowledge infrastructure. Many of the gadgets here leverage tools that are found in other repos and that are open source. Specifically, we leverage the sparse Merkle tree data structures from the [ivls](https://github.com/arkworks/../../../../../../../arkworks/native-gadgets/Cargo.tomlrs/ivls/tree/master/src/building_blocks/mt/merkle_sparse_tree) project on incrementally verifiable computation. This work would not have been possible without that.

Many thanks to the following people for help and insights in both learning and implementing these gadgets & circuits:

- [@weikengchen](https://github.com/weikengchen)
- [@Pratyush](https://github.com/Pratyush)
