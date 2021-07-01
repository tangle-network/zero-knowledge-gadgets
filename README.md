# arkworks-gadgets

Gadgets and constraints written using the [arkworks](https://github.com/arkworks-rs) libraries for Webb and more.

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
