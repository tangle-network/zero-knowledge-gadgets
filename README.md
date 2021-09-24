# arkworks-gadgets

Gadgets and constraints written using the [arkworks](https://github.com/arkworks-rs) libraries for Webb and more.

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

# Usage
## Creating a Mixer w/ Poseidon using exponentiation 5
For example, we might be interested in creating a mixer circuit and generating zero-knowledge proofs of membership for leaves we've inserted into the mixer's underlying merkle tree. In order to do so we will have to instantiate the individual gadgets, supply them to a Mixer circuit, and generate the trusted setup parameters for a Groth16 style proof.
### Defining our interfaces and structs
```
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
```
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
```
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

### Params for `bls381_x3_3.rs`

```
exponentiation = 3
width = 3
full rounds = 8
partial rounds = 84
prime field =
0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
```

Running:

```
sage generate_parameters_grain.sage 1 0 255 3 8 84 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
```

### Params for `bls381_x3_5.rs`

```
exponentiation = 3
width = 5
full rounds = 8
partial rounds = 85
prime field = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
```

Running:

```
sage generate_parameters_grain.sage 1 0 255 5 8 85 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
```

### Params for `bls381_x5_3.rs`

```
exponentiation = 5
width = 3
full rounds = 8
partial rounds = 57
prime field = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
```

Running:

```
sage generate_parameters_grain.sage 1 0 255 3 8 57 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
```

### Params for `bls381_x5_5.rs`

```
exponentiation = 5
width = 5
full rounds = 8
partial rounds = 60
prime field = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
```

Running:

```
sage generate_parameters_grain.sage 1 0 255 5 8 60 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
```

### Params for `bls381_x17_3.rs`

```
exponentiation = 17
width = 3
full rounds = 8
partial rounds = 33
prime field = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
```

Running:

```
sage generate_parameters_grain.sage 1 0 255 17 8 33 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001

```



### Params for `bls381_x17_5.rs`

```
exponentiation = 17
width = 5
full rounds = 8
partial rounds = 35
prime field = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
```

Running:

```
sage generate_parameters_grain.sage 1 0 255 17 8 35 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001

```
