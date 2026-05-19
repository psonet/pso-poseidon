# P.S.O. Poseidon

[![crates.io](https://img.shields.io/crates/v/pso-poseidon.svg)](https://crates.io/crates/pso-poseidon)
[![release](https://img.shields.io/github/v/release/psonet/pso-poseidon.svg)](https://github.com/psonet/pso-poseidon/releases)
[![CI](https://github.com/psonet/pso-poseidon/actions/workflows/ci.yml/badge.svg)](https://github.com/psonet/pso-poseidon/actions/workflows/ci.yml)

<!-- cargo-rdme start -->

**pso-poseidon** is a [Poseidon](https://eprint.iacr.org/2019/458) hash
implementation in Rust created for [PSO](https://github.com/psonet) based on [light-poseidon](https://github.com/Lightprotocol/light-poseidon/) library.

## Parameters

The library provides pre-generated parameters over the BN254 curve, however
it can work with any parameters provided as long as developers take care
of generating the round constants.

Parameters provided by the library are:

* *x^5* S-boxes
* width - *2 ≤ t ≤ 13*
* inputs - *1 ≤ n ≤ 12*
* 8 full rounds and partial rounds depending on *t*: *[56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65]*

## Output type

`Poseidon` type implements two traits which serve the purpose
of returning the calculated hash in different representations:

* `PoseidonHasher` with the `hash` method which returns
  `ark_ff::PrimeField`. Might be useful if you want
  to immediately process the result with an another library which works with
  `ark_ff::PrimeField` types.

## Examples

With `PoseidonHasher` trait and `ark_ff::PrimeField` result:

```rust
use ark_bn254::Fr;
use ark_ff::PrimeField;
use pso_poseidon::{Poseidon, PoseidonHasher};

let mut poseidon = Poseidon::<Fr>::new_circom(2).unwrap();

let input1 = Fr::from_le_bytes_mod_order(&[1u8; 32]);
let input2 = Fr::from_le_bytes_mod_order(&[2u8; 32]);

let hash = poseidon.hash(&[input1, input2]).unwrap();

// Do something with `hash`.
```

## Field Arithmetic

This library uses [ark-ff](https://github.com/arkworks-rs/algebra) for field arithmetic. While ark-ff carries an academic disclaimer, it is widely adopted in production by major projects including [Aleo](https://github.com/AleoNet/snarkVM), [Penumbra](https://github.com/penumbra-zone/penumbra), [Mina (Kimchi)](https://github.com/o1-labs/proof-systems), and [Espresso Systems](https://github.com/EspressoSystems).

## Implementation

The implementation is compatible with the
[original SageMath implementation](https://extgit.iaik.tugraz.at/krypto/hadeshash/-/tree/master/),
but it was also inspired by the following ones:

* [circomlibjs](https://github.com/iden3/circomlibjs)
* [zero-knowledge-gadgets](https://github.com/webb-tools/zero-knowledge-gadgets)
* [light-poseidon](https://github.com/Lightprotocol/light-poseidon/)

## Security

This library has been audited by [Veridise](https://veridise.com/). You can
read the audit report [here](https://github.com/Lightprotocol/light-poseidon/blob/main/assets/audit.pdf).

<!-- cargo-rdme end -->