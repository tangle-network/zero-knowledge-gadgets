# arkworks-gadgets

Gadgets and constraints written using the [arkworks](https://github.com/arkworks-rs) libraries for Webb and more.

# Overview
The zero-knowledge gadgets contained in this repo are built with an eye towards composability. There are gadgets that:
- Hash a set of elements for building preimage gadgets & proofs
- Hash a leaf with a set of elements for building  merkle tree membership gadgets & proofs
- Check membership of an element in a set for building set membership gadgets & proofs
- Combine each of the above to build mixers & bridge gadgets and proofs for Webb applications.

## Usage
In order to use these gadgets, the `src/setup` directory should be your friend. It instantiates the provers and verifiers for various end-application gadgets and the parameters needed for each instantiation. For information details about parameters that go into specific instantiations of these circuits (e.g. for hashing), please refer to the **Parameter generation** section below.

Each application-specific file in `src/setup` encapsulates the full-setup of a zero-knowledge gadget's prover and verifier. There are currently application-specific gadgets for:
- zero-knowledge mixers
- zero-knowledge bridges

For tests and instantiations of the gadgets used to compose each of these larger scale application gadgets, refer to the individual directories and their tests. Most all of the tests and implementations in this repo use Groth16 proofs and setups for the zero-knowledge gadgets. Occasionally Marlin zkSNARKs are used for intermediate gadget tests. There are no application-specific instantiations of gadgets that use Marlin however, but pull requests are welcome to create them.

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
