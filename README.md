# arkworks-gadgets

Gadgets and constraints written using the [arkworks](https://github.com/arkworks-rs) libraries for Webb and more.

## Gratitude
We are grateful to the arkworks community for their open-source first approach to zero-knowledge infrastructure. Many of the gadgets here leverage tools that are found in other repos and that are open source. Specifically, we leverage the sparse merkle tree data structures from the [ivls](https://github.com/arkworks-rs/ivls/tree/master/src/building_blocks/mt/merkle_sparse_tree) project on incrementally verifiable computation. This work would not have been possible without that.

Many thanks to the following people for help and insights in both learning and implementing these gadgets & circuits:
- @weikengchen
- @Pratyush

# Overview
This repo contains zero-knowledge gadgets & circuits for different end applications such as a mixer and a bridge that can be integrated into compatible blockchain and smart contract protocols. The repo is split into two main parts: the intermediate modular gadgets and the circuits that consume these gadgets.

## Gadgets
In this repo you will find gadgets for:
- [x] [Poseidon hashing](https://github.com/webb-tools/arkworks-gadgets/tree/master/src/poseidon)
- [x] [MiMC hashing](https://github.com/webb-tools/arkworks-gadgets/tree/master/src/mimc)
- [x] [Leaf commitment construction for various leaf schemas (for mixers and bridges)](https://github.com/webb-tools/arkworks-gadgets/tree/master/src/leaf)
- [x] [Merkle tree membership and construction](https://github.com/webb-tools/arkworks-gadgets/tree/master/src/merkle_tree)
- [x] [Set membership](https://github.com/webb-tools/arkworks-gadgets/tree/master/src/set)
- [x] [Arbitrary computation (no constraints applied)](https://github.com/webb-tools/arkworks-gadgets/tree/master/src/arbitrary)

You can think of gadgets as intermediate computations and constraint systems that you compose to build a more complete zero-knowledge proof of knowledge statement. They can also be used as is by simply extending the arkworks `ConstraintSynthesizer`. An example using dummy computations can be found in the [dummy circuit](https://github.com/webb-tools/arkworks-gadgets/blob/master/src/circuit/basic.rs).

## Circuits
In this repo you will find circuits for:
- [x] [Poseidon preimage proofs](https://github.com/webb-tools/arkworks-gadgets/blob/master/src/circuit/poseidon.rs) - using a Poseidon hash gadget
- [x] [Mixer](https://github.com/webb-tools/arkworks-gadgets/blob/master/src/circuit/mixer.rs) - using a hash gadget, mixer leaf commitment gadget, merkle tree membership gadget, and arbitrary computations.
- [x] [Bridge](https://github.com/webb-tools/arkworks-gadgets/blob/master/src/circuit/bridge.rs) - using a hash gadget, bridge leaf commitment gadget, merkle tree construction gadget, set membership gadget, and arbitrary computations.

## Setup
In order to deploy zero-knowledge circuits in end applications, you have to set them up. Often times you may hear the term "trusted setup" thrown about. For the circuits implemented in this repo, we have Groth16 style setups in the [setup](https://github.com/webb-tools/arkworks-gadgets/tree/master/src/setup) directory. This folder contains circuit-specific setup helpers for creating your provers and verifiers for your circuits from the previous section.

The circuit-specific files of the setup section contain tests and circuit definitions that instantiate circuits w/ different configurations of hash gadgets and merkle tree gadgets. This is the primary place where one fixes the exact instantiations of a specific circuit.

Each application-specific file in `src/setup` encapsulates the full-setup of a zero-knowledge gadget's prover and verifier. There are currently application-specific gadgets for:
- zero-knowledge mixers
- zero-knowledge bridges

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
The structure of our leaves must be the hash of 3 random field elements from a compatible field (BLS381, BN254) based on the instantiation of your circuit. You can find more details about the leaf structures by investigating the [`mixer_leaf`](https://github.com/webb-tools/arkworks-gadgets/blob/master/src/leaf/mixer/constraints.rs).

### Public input structure
The structure of public inputs must be the ordered array of the following data taken from Tornado Cash's design & architecture.
1. Recipient
2. Relayer
3. Fee
4. Refund

You can find more details about the arbitrary data structures by investigating the [`mixer_data`](https://github.com/webb-tools/arkworks-gadgets/blob/master/src/arbitrary/mixer_data/constraints.rs).

These parameters are provided to zero-knowledge proofs as public inputs and are geared towards on-chain customizability.
- For an on-chain cryptocurrency mixer, we must know where we are withdrawing tokens to. This is the purpose of the recipient.
- For an on-chain cryptocurrency mixer, we must provide a private transaction relaying service that the user decides a priori. This is the purpose of the relayer.
- For a given relayer, a fee may be asked to be paid on behalf of relaying the private transaction. This is the purpose of the fee.
- For now, the refund is not used in any context and is merely an artifact to maintain stability with Tornado Cash's public inputs structure.

It's worth mentioning that all inputs provided to the zero-knowledge proof generation bind the proof to those inputs. This helps prevent tampering if for example a user wants to change the recipient after proof generation. If the public inputs change for a proof submitted on-chain, the proof will fail with the underlying security of the zkSNARK. We leverage this design to provide the right incentives for users and relayers of the end application, an on-chain cryptocurrency mixer.

# Usage
## Creating a Mixer w/ Poseidon using exponentiation 5
For example, we might be interested in creating a mixer circuit and generating zero-knowledge proofs of membership for leaves we've inserted into the mixer's underlying merkle tree. In order to do so we will have to instantiate the individual gadgets, supply them to a Mixer circuit, and generate the trusted setup parameters for a Groth16 style proof.
### Defining our interfaces and structs
```rust
/// import all dependencies...

/// We first define the Poseidon instantiation, which requires
/// setting the parameters of the particular Poseidon hash
/// implementation we want to use. We will instantiate 2 types
/// of Poseidon hashers, one for hashing leaf commitments, and
/// the other for hasing nodes to build the merkle tree. Since
/// these have different elements and structures we must define
/// two hash functions for each, separately.
///
/// Poseidon parameters w/ exponentiation 5 has a width of 3 for hashing
/// merkle tree elements together.
#[derive(Default, Clone)]
pub struct PoseidonRounds_x5_3;

impl Rounds for PoseidonRounds_x5_3 {
	const FULL_ROUNDS: usize = 8;
	const PARTIAL_ROUNDS: usize = 57;
	const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
	const WIDTH: usize = 3;
}

/// Poseidon parameters w/ exponentiation 5 has a width of 5 for hashing
/// mixer data into leaf commitments.
#[derive(Default, Clone)]
pub struct PoseidonRounds_x5_5;

impl Rounds for PoseidonRounds_x5_5 {
	const FULL_ROUNDS: usize = 8;
	const PARTIAL_ROUNDS: usize = 60;
	const SBOX: PoseidonSbox = PoseidonSbox::Exponentiation(5);
	const WIDTH: usize = 5;
}

/// Poseidon hash function & gadget instantiation for merkle tree hasher
pub type PoseidonCRH_x5_3<F> = CRH<F, PoseidonRounds_x5_3>;
pub type PoseidonCRH_x5_3Gadget<F> = CRHGadget<F, PoseidonRounds_x5_3>;

/// Poseidon hash function & gadget instantiation for merkle tree hasher
pub type PoseidonCRH_x5_5<F> = CRH<F, PoseidonRounds_x5_5>;
pub type PoseidonCRH_x5_5Gadget<F> = CRHGadget<F, PoseidonRounds_x5_5>;

/// Mixer leaf gadget instatiation using Poseidon w/ exponentiation 5 and width 5 (what this leaf requires)
pub type MixerConstraintData<F> = MixerData<F>;
pub type MixerConstraintDataInput<F> = MixerDataInput<F>;
pub type MixerConstraintDataGadget<F> = MixerDataGadget<F>;
pub type Leaf_x5<F> = MixerLeaf<F, PoseidonCRH_x5_5<F>>;
pub type LeafGadget_x5<F> = MixerLeafGadget<F, PoseidonCRH_x5_5<F>, PoseidonCRH_x5_5Gadget<F>, Leaf_x5<F>>;

/// Merkle tree gadget configuration instantiation using the Poseidon w/ exponentiation 5 and widht 3 merkle tree hasher.
#[derive(Clone)]
pub struct TreeConfig_x5<F: PrimeField>(PhantomData<F>);
impl<F: PrimeField> MerkleConfig for TreeConfig_x5<F> {
	type H = PoseidonCRH_x5_3<F>;
	type LeafH = LeafCRH<F>;

	const HEIGHT: u8 = 30;
}

/// Tree type to be used for setup specific macros
pub type Tree_x5<F> = SparseMerkleTree<TreeConfig_x5<F>>;

/// Mixer circuit instantiation using the Poseidon gadgets for leaves and merkle tree, respectively.
pub type Circuit_x5<F, const N: usize> = MixerCircuit<
	F,
	MixerConstraintData<F>,
	MixerConstraintDataGadget<F>,
	PoseidonCRH_x5_5<F>,
	PoseidonCRH_x5_5Gadget<F>,
	TreeConfig_x5<F>,
	LeafCRHGadget<F>,
	PoseidonCRH_x5_3Gadget<F>,
	Leaf_x5<F>,
	LeafGadget_x5<F>,
	N,
>;
```
### Instantiating helpers and prover/verifiers
```rust
/// This macro generates setup functions for creating leaf commitments
/// compatible with the Poseidon w/ exponentiation 5 and width 5 hasher.
/// We use this macro's generated functions to create leaves. These leaves
/// are meant to be inserted into a corresponding merkle tree defined below.
impl_setup_mixer_leaf!(
	leaf: Leaf_x5,
	crh: PoseidonCRH_x5_5,
	params: PoseidonParameters
);

/// This macro generates setup functions for creating a merkle tree
/// with the intended configuration. The macro's generated functions
/// provide us utilities for building the merkle tree and getting the
/// path of elements in the tree that we want to generate proofs for.
impl_setup_tree!(
	tree: Tree_x5,
	config: TreeConfig_x5,
	params: PoseidonParameters
);

/// With all the generated functions thus far, we can generate the setup
/// functionality for instantiating circuit instances, which provide us with
/// the arguments and structs necessary for generating zero-knowledge proofs.
/// We must provide this macro with the parameters used for each hash function
/// denoted by `setup_params_x5_X` for each Poseidon hash instantiation we
/// made above and functions for setting up the corresponding leaf and merkle tree
/// structure used in the `Circuit_x5` definition.
impl_setup_mixer_circuit!(
	circuit: Circuit_x5,
	params3_fn: setup_params_x5_3,
	params5_fn: setup_params_x5_5,
	leaf_setup_fn: setup_leaf_x5,
	tree_setup_fn: setup_tree_and_create_path_tree_x5
);

/// This macro generates us groth16 helpers for generating provers/verifiers
/// to generate proofs and verify proofs from our zero-knowledge circuit.
impl_groth16_api_wrappers!(circuit: Circuit_x5);
```
### Putting it all together
```rust
/// With the generated functionality we can now create example circuits and
/// generate zero-knowledge proofs against them. We show an example below.
/// Examples are also available as tests in the `src/setup/mixer.rs` files for this
/// circuit we have set up.

/// Generate all values for the circuit's public inputs.
let mut rng = test_rng();
let curve = Curve::Bls381;
let recipient = Bls381::from(0u8);
let relayer = Bls381::from(0u8);
let fee = Bls381::from(0u8);
let refund = Bls381::from(0u8);
let leaves = Vec::new();

/// Generate a circuit instance w/ leaves and supplied public inputs.
/// This will also generate a leaf commitment and return both the leaf
/// and the corresponding values for generating zero-knowledge proofs.
let (circuit, leaf, nullifier_hash, root, public_inputs) = setup_circuit_x5(
    &leaves,
    0,
    recipient,
    relayer,
    fee,
    refund,
    &mut rng,
    curve
);

/// create prover and verifier keys for Groth16 zkSNARK
let (pk, vk) = setup_circuit_groth16(&mut rng, circuit.clone());
/// generate the proof
let proof = prove_groth16_circuit_x5::<_, Bls12_381, LEN>(&pk, circuit.clone(), &mut rng);
/// verify the proof
let res = verify_groth16::<Bls12_381>(&vk, &public_inputs, &proof);
```

## Parameter generation
Parameter for the sage [script](https://github.com/webb-tools/bulletproof-gadgets/tree/main/src/crypto_constants/data/poseidon).
