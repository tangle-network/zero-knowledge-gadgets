# arkworks-gadgets

Gadgets and constraints written using the [arkworks](https://github.com/arkworks-rs) libraries for Webb and more.

## Gratitude

We are grateful to the arkworks community for their open-source first approach to zero-knowledge infrastructure. Many of the gadgets here leverage tools that are found in other repos and that are open source. Specifically, we leverage the sparse merkle tree data structures from the [ivls](https://github.com/arkworks-rs/ivls/tree/master/src/building_blocks/mt/merkle_sparse_tree) project on incrementally verifiable computation. This work would not have been possible without that.

Many thanks to the following people for help and insights in both learning and implementing these gadgets & circuits:

- [@weikengchen](https://github.com/weikengchen)
- [@Pratyush](https://github.com/Pratyush)

# Overview

This repo contains zero-knowledge gadgets & circuits for different end applications such as a mixer and a anchor that can be integrated into compatible blockchain and smart contract protocols. The repo is split into three main parts: 
- Intermediate modular gadgets
- The circuits that consume these gadgets
- Basic utilities used by the gadgets and the circuits (like parameters for poseidon hash function)

## Gadgets

You can think of gadgets as intermediate computations and constraint systems that you compose to build a more complete zero-knowledge proof of knowledge statement. They can also be used as is by simply extending the arkworks `ConstraintSynthesizer`. An example using dummy computations can be found in the [dummy circuit](https://github.com/webb-tools/arkworks-gadgets/blob/master/arkworks-circuits/src/circuit/basic.rs).

In this repo you will find gadgets for:

- [x] [Poseidon hashing](https://github.com/webb-tools/arkworks-gadgets/tree/master/arkworks-gadgets/src/poseidon)
- [x] [MiMC hashing](https://github.com/webb-tools/arkworks-gadgets/tree/master/arkworks-gadgets/src/mimc)
- [x] [Leaf commitment construction for various leaf schemas (for mixers and anchors)](https://github.com/webb-tools/arkworks-gadgets/tree/master/arkworks-gadgets/src/leaf)
- [x] [Merkle tree membership and construction](https://github.com/webb-tools/arkworks-gadgets/tree/master/arkworks-gadgets/src/merkle_tree)
- [x] [Set](https://github.com/webb-tools/arkworks-gadgets/tree/master/arkworks-gadgets/src/set)
- [x] [Arbitrary computation](https://github.com/webb-tools/arkworks-gadgets/tree/master/arkworks-gadgets/src/arbitrary)

- Poseidon hashing function matches the [circom implementation](https://github.com/iden3/circomlib/blob/master/circuits/poseidon.circom). Implemented based on this paper: https://eprint.iacr.org/2019/458.pdf.
- MiMC hashing function matches the [circom implementation](https://github.com/iden3/circomlib/blob/master/circuits/mimc.circom)
- Set membership - Used for proving that some value is inside the set in a zero-knowladge manner. That is done by first calculating the differences (denoted as `diffs`) from the `target` (value that we are checking the membership of) and each value from the set. We then calculate the sum of products of a target and each element in the set. If one value from the `diffs` is 0 (meaning that its equal to `target`) the product will be zero, thus meaning that the `target` is in the set.

## Circuits

In this repo you will find circuits for:

- [x] [Poseidon preimage proofs](https://github.com/webb-tools/arkworks-gadgets/blob/master/arkworks-circuits/src/circuit/poseidon.rs) - using a Poseidon hash gadget
- [x] [Mixer](https://github.com/webb-tools/arkworks-gadgets/blob/master/arkworks-circuits/src/circuit/mixer.rs) - using a hash gadget, mixer leaf commitment gadget, merkle tree membership gadget, and arbitrary computations.
- [x] [Anchor](https://github.com/webb-tools/arkworks-gadgets/blob/master/arkworks-circuits/src/circuit/anchor.rs) - using a hash gadget, anchor leaf commitment gadget, merkle tree construction gadget, set membership gadget, and arbitrary computations.
- [x] [VAnchor](https://github.com/webb-tools/arkworks-gadgets/blob/master/arkworks-circuits/src/circuit/vanchor.rs) - using a hash gadget, vanchor leaf commitment gadget, merkle tree construction gadget, set membership gadget, and arbitrary computations.

## Setup Helpers

For the circuits implemented in this repo, we have setups in the [setup](https://github.com/webb-tools/arkworks-gadgets/tree/master/arkworks-circuits/src/setup) directory. This folder contains circuit-specific setup helpers for creating your provers and verifiers for your circuits from the previous section.

The circuit-specific files of the setup section contain tests and circuit definitions that instantiate circuits w/ different configurations of hash gadgets, merkle tree gadgets and elliptic curves. This is the primary place where one fixes the exact instantiations of a specific circuit.

Each application-specific file in `arkworks-circuits/src/setup` encapsulates the full-setup of a zero-knowledge gadget's prover and verifier. There are currently application-specific gadgets for:

- zero-knowledge mixers
- zero-knowledge anchors
- zero-knowladge variable anchors

For tests and instantiations of the gadgets used to compose each of these larger scale application gadgets, refer to the individual directories and their tests. Most all of the tests and implementations in this repo use Groth16 proofs and setups for the zero-knowledge gadgets. Occasionally Marlin zkSNARKs are used for intermediate gadget tests. There are no application-specific instantiations of gadgets that use Marlin however, but pull requests are welcome to create them.

### Provers

Provers for these zero-knowledge gadgets are meant to be used by client or server applications. These are compute intensive and require access to random number generators.

### Verifiers

Verifiers for these zero-knowledge gadgets are meant to be used by client, server, or blockchain applications. These verifiers are WASM compatible and can be embedded in WASM friendly environments like blockchains that allow smart contracts which are written in Rust. The APIs are consistent across a particular proving system such as Groth16 and are straightforward to integrate into blockchain runtimes such as [Substrate](https://github.com/paritytech/substrate).

# Circuits

## Mixer

The mixer gadget is built to be deployed on Rust based blockchain protocols. The motivation is that there will be an on-chain merkle tree & escrow system where users must deposit assets into in order to insert a leaf into the merkle tree. This is considered a **deposit** into the mixer. Next, the user can generate a zero-knowledge proof of membership of a leaf in the merkle tree by instantiating a Mixer circuit, populating it with the leaves on-chain, providing private and public inputs locally to the helper utilities generated from our API, and subsequently generating a zero-knowledge proof. They can then submit this proof on-chain to an on-chain verifier. This is considered a **withdrawal** from the mixer. We provide an example instantiation of the mixer circuit setup, proof process, and proof verification process below. But first, we remark on the structure of the mixer in order to illuminate some of our design decisions.

Any instantiation of a zero-knowledge mixer circuit requires that all data provided is formatted as expected. What this means is that there is a specific structure of data that must be provided to the prover. This extends as far down to the preimage of the leaves such that if data does not adhere to the expected format or protocol then it will be impossible to generate compatible zero-knowledge proofs for on-chain verification for such proofs.

### Leaf structure

The structure of our leaves must be the hash of 2 random field elements (the secret and the nullifier)) from a compatible field (BLS381, BN254) based on the instantiation of your circuit. You can find more details about the leaf structures by investigating the [`mixer_leaf`](https://github.com/webb-tools/arkworks-gadgets/blob/master/arkworks-gadgets/src/leaf/mixer/constraints.rs).

### Public input structure

The structure of public inputs must be the ordered array of the following data taken from Tornado Cash's design & architecture.

1. Nullifier hash
2. Merkle root
3. Recipient
4. Relayer
5. Fee
6. Refund

You can find more details about the arbitrary data structures by investigating the [`mixer_data`](https://github.com/webb-tools/arkworks-gadgets/blob/master/arkworks-gadgets/src/arbitrary/mixer_data/constraints.rs).

These parameters are provided to zero-knowledge proofs as public inputs and are geared towards on-chain customizability.

- Nullifier hash is the hash of the randomly generated nullifier. We are hashing it so that the preimage remains hidden, to prevent front-run attacks.
- Merkle root is the root hash of the merkle tree we are proving the leaf membership in.
- For an on-chain cryptocurrency mixer, we must know where we are withdrawing tokens to. This is the purpose of the recipient.
- For an on-chain cryptocurrency mixer, we must provide a private transaction relaying service that the user decides a priori. This is the purpose of the relayer.
- For a given relayer, a fee may be asked to be paid on behalf of relaying the private transaction. This is the purpose of the fee.
- For now, the refund is not used in any context and is merely an artifact to maintain stability with Tornado Cash's public inputs structure.

It's worth mentioning that all inputs provided to the zero-knowledge proof generation bind the proof to those inputs. This helps prevent tampering if for example a user wants to change the recipient after proof generation. If the public inputs change for a proof submitted on-chain, the proof will fail with the underlying security of the zkSNARK. We leverage this design to provide the right incentives for users and relayers of the end application, an on-chain cryptocurrency mixer.

## Anchor

Anchor protocol is very similar to mixer. Instead of proving that the membership inside one merkle tree, we are proving the membership in many merkle trees. These trees can live on many different blockchains, and if the merkle tree states are synced across chains, this will allow us to make cross-chain anonymous transactions.

### Leaf structure

Leaf structure is similar to that of a mixer, except we are also introducing a chain id as a public input. Chain id ensures that you can only withdraw on one chain, thus preventing double spending. So, an Anchor leaf consists of a `secret` (random value), `nullifier` (random value) and `chain_id`.

### Public input structure

1. Chain Id
1. Nullifier hash
2. Merkle root set
3. Recipient
4. Relayer
5. Fee
6. Refund
7. Commitment

- Chain Id - ensures that you only withdraw on one chain and prevents double-spending.
- Nullifier hash is the same as in the mixer, except it's used in a multi-chain context. Meaning it will be registered on a chain that has an Id same as Chain Id (our public input).
- Merkle root set is an array of root hashes. It consists of a local root (root on the chain the withdraw is made) and roots from other chains that are connected to local one.
- Recipient, Relayer, Fee and Refund has the same purpose as the ones in the Mixer.
- Commitment is used for refreshing your leaf -- meaning inserting a new leaf as a replacement for the old one, if the value of commitment is non-zero.

## VAnchor

# Usage

## Creating a Mixer w/ Poseidon using exponentiation 5

For example, we might be interested in creating a mixer circuit and generating zero-knowledge proofs of membership for leaves we've inserted into the mixer's underlying merkle tree. In order to do so we will have to instantiate the individual gadgets, supply them to a Mixer circuit, and generate the trusted setup parameters for a Groth16 style proof.

### Defining our interfaces and structs

```rust
/// import all dependencies...

/// Mixer leaf gadget instatiation using Poseidon w/ exponentiation 5 and width 5 (what this leaf requires)
pub type MixerConstraintData<F> = MixerData<F>;
pub type MixerConstraintDataInput<F> = MixerDataInput<F>;
pub type MixerConstraintDataGadget<F> = MixerDataGadget<F>;
pub type Leaf_x5<F> = MixerLeaf<F, PoseidonCRH<F>>;
pub type LeafGadget_x5<F> = MixerLeafGadget<F, PoseidonCRH<F>, PoseidonCRHGadget<F>, Leaf_x5<F>>;

/// Merkle tree gadget configuration instantiation using the Poseidon w/ exponentiation 5 and widht 3 merkle tree hasher.
#[derive(Clone)]
pub struct TreeConfig_x5<F: PrimeField>(PhantomData<F>);
impl<F: PrimeField> MerkleConfig for TreeConfig_x5<F> {
	type H = PoseidonCRH<F>;
	type LeafH = IdentityCRH<F>;

	const HEIGHT: u8 = 30;
}

/// Tree type to be used for setup specific macros
pub type Tree_x5<F> = SparseMerkleTree<TreeConfig_x5<F>>;

/// Mixer circuit instantiation using the Poseidon gadgets for leaves and merkle tree, respectively.
pub type Circuit_x5<F, const N: usize> = MixerCircuit<
	F,
	MixerConstraintData<F>,
	MixerConstraintDataGadget<F>,
	PoseidonCRH<F>,
	PoseidonCRHGadget<F>,
	TreeConfig_x5<F>,
	LeafCRHGadget<F>,
	PoseidonCRHGadget<F>,
	Leaf_x5<F>,
	LeafGadget_x5<F>,
	N,
>;
```

### Instantiating helpers and prover/verifiers (This feature is still under construction - use with caution)

```rust
/// With the generated functionality we can now create example circuits and
/// generate zero-knowledge proofs against them. We show an example below.
/// Examples are also available as tests in the `src/setup/mixer.rs` files for this
/// circuit we have set up.

/// Generate all values for the circuit's public inputs.
let rng = &mut test_rng();
let curve = Curve::Bn254;

let recipient = Bn254Fr::one();
let relayer = Bn254Fr::zero();
let fee = Bn254Fr::zero();
let refund = Bn254Fr::zero();

/// Generate a circuit instance w/ leaves and supplied public inputs.
/// This will also generate a leaf commitment and return both the leaf
/// and the corresponding values for generating zero-knowledge proofs.
let params3 = setup_params_x5_3::<Bn254Fr>(curve);
let params5 = setup_params_x5_5::<Bn254Fr>(curve);
let prover = MixerProverSetupBn254_30::new(params3, params5);

let (leaf_privates, leaf_hash, ..) = prover.setup_leaf(rng).unwrap();
let secret = leaf_privates.secret();
let nullifier = leaf_privates.nullifier();
let leaves = vec![leaf_hash];
let index = 0;
let (circuit, .., public_inputs) = prover
	.setup_circuit_with_privates(
		secret, nullifier, &leaves, index, recipient, relayer, fee, refund,
	)
	.unwrap();

/// create prover and verifier keys for Groth16 zkSNARK
let (pk, vk) = setup_keys::<Bn254, _, _>(circuit.clone(), rng).unwrap();
/// generate the proof
let proof = prove::<Bn254, _, _>(circuit, &pk, rng).unwrap();

/// verify the proof
let res = verify::<Bn254>(&public_inputs, &vk, &proof).unwrap();
```

## Parameter generation

Parameter for the sage [script](https://github.com/webb-tools/bulletproof-gadgets/tree/main/src/crypto_constants/data/poseidon).
