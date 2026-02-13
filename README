# P.S.O. Poseidon

<!-- cargo-rdme start -->

**pso-poseidon** is a [Poseidon](https://eprint.iacr.org/2019/458) hash
implementation in Rust created for [PSO](https://github.com/psobn) based on [light-poseidon](https://github.com/Lightprotocol/light-poseidon/) library.

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

[`Poseidon`](https://docs.rs/light-poseidon/latest/light_poseidon/struct.Poseidon.html) type implements two traits which serve the purpose
of returning the calculated hash in different representations:

* [`PoseidonHasher`](https://docs.rs/light-poseidon/latest/light_poseidon/trait.PoseidonHasher.html) with the `hash` method which returns
  [`ff::PrimeField`](ark_ff::PrimeField). Might be useful if you want
  to immediately process the result with an another library which works with
  [`ff::PrimeField`](ark_ff::PrimeField) types.

## Examples

With [`PoseidonHasher`](https://docs.rs/light-poseidon/latest/light_poseidon/trait.PoseidonHasher.html) trait and
[`ff::PrimeField`](ark_ff::PrimeField) result:

```rust
use halo2_axiom::halo2curves::bn256::Fr;
use halo2_axiom::halo2curves::ff::PrimeField;
use light_poseidon::{Poseidon, PoseidonHasher, parameters::bn254_x5};

let mut poseidon = Poseidon::<Fr>::new_circom(2).unwrap();

let input1 = Fr::from_bytes(&[1u8; 32]).unwrap();
let input2 = Fr::from_bytes(&[2u8; 32]).unwrap();

let hash = poseidon.hash(&[input1, input2]).unwrap();

// Do something with `hash`.
```

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