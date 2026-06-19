//! **pso-poseidon** is a [Poseidon](https://eprint.iacr.org/2019/458) hash
//! implementation in Rust created for [PSO](https://github.com/psonet) based on [light-poseidon](https://github.com/Lightprotocol/light-poseidon/) library.
//!
//! # Parameters
//!
//! The library provides pre-generated parameters over the BN254 curve, however
//! it can work with any parameters provided as long as developers take care
//! of generating the round constants.
//!
//! Parameters provided by the library are:
//!
//! * *x^5* S-boxes
//! * width - *2 ≤ t ≤ 13*
//! * inputs - *1 ≤ n ≤ 12*
//! * 8 full rounds and partial rounds depending on *t*: *[56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65]*
//!
//! # Output type
//!
//! `Poseidon` type implements two traits which serve the purpose
//! of returning the calculated hash in different representations:
//!
//! * `PoseidonHasher` with the `hash` method which returns
//!   `ark_ff::PrimeField`. Might be useful if you want
//!   to immediately process the result with an another library which works with
//!   `ark_ff::PrimeField` types.
//!
//! # Examples
//!
//! With `PoseidonHasher` trait and `ark_ff::PrimeField` result:
//!
//! ```rust
//! use ark_bn254::Fr;
//! use ark_ff::PrimeField;
//! use pso_poseidon::{Poseidon, PoseidonHasher};
//!
//! let mut poseidon = Poseidon::<Fr>::new_circom(2).unwrap();
//!
//! let input1 = Fr::from_le_bytes_mod_order(&[1u8; 32]);
//! let input2 = Fr::from_le_bytes_mod_order(&[2u8; 32]);
//!
//! let hash = poseidon.hash(&[input1, input2]).unwrap();
//!
//! // Do something with `hash`.
//! ```
//!
//! # Poseidon2
//!
//! [`Poseidon2`] is a separate, generic BN254 **Poseidon2** hash, bit-compatible
//! with noir's in-circuit `poseidon2` (Barretenberg's permutation + sponge). Use
//! it for off-circuit hashing that must reproduce an in-circuit Poseidon2 result.
//! It shares no parameters with the circom-compatible `Poseidon` above —
//! Poseidon2 is a distinct construction. BN254 is built in via
//! `Poseidon2::<Fr>::new()`; other fields supply their own constants.
//!
//! ```rust
//! use ark_bn254::Fr;
//! use pso_poseidon::{Poseidon2, PoseidonHasher};
//!
//! let mut poseidon2 = Poseidon2::<Fr>::new();
//! let _hash = poseidon2.hash(&[Fr::from(1u64), Fr::from(2u64)]).unwrap();
//! ```
//!
//! # Field Arithmetic
//!
//! This library uses [ark-ff](https://github.com/arkworks-rs/algebra) for field arithmetic. While ark-ff carries an academic disclaimer, it is widely adopted in production by major projects including [Aleo](https://github.com/AleoNet/snarkVM), [Penumbra](https://github.com/penumbra-zone/penumbra), [Mina (Kimchi)](https://github.com/o1-labs/proof-systems), and [Espresso Systems](https://github.com/EspressoSystems).
//!
//! # Implementation
//!
//! The implementation is compatible with the
//! [original SageMath implementation](https://extgit.iaik.tugraz.at/krypto/hadeshash/-/tree/master/),
//! but it was also inspired by the following ones:
//!
//! * [circomlibjs](https://github.com/iden3/circomlibjs)
//! * [zero-knowledge-gadgets](https://github.com/webb-tools/zero-knowledge-gadgets)
//! * [light-poseidon](https://github.com/Lightprotocol/light-poseidon/)
//!
//! # Security
//!
//! This library has been audited by [Veridise](https://veridise.com/). You can
//! read the audit report [here](https://github.com/Lightprotocol/light-poseidon/blob/main/assets/audit.pdf).

use ark_ff::PrimeField;

use thiserror::Error;

mod poseidon;
pub use poseidon::{Poseidon, PoseidonParameters};

/// bb-compatible Poseidon2 (matches noir's in-circuit `poseidon2`).
pub mod poseidon2;
pub use poseidon2::Poseidon2;

pub const HASH_LEN: usize = 32;
pub const MAX_X5_LEN: usize = 13;

#[derive(Error, Debug, PartialEq)]
pub enum PoseidonError {
    #[error("Invalid number of inputs: {inputs}. Maximum allowed is {max_limit} ({width} - 1).")]
    InvalidNumberOfInputs {
        inputs: usize,
        max_limit: usize,
        width: usize,
    },
    #[error("Input is an empty slice.")]
    EmptyInput,
    #[error("Invalid length of the input: {len}. The length matching the modulus of the prime field is: {modulus_bytes_len}.")]
    InvalidInputLength {
        len: usize,
        modulus_bytes_len: usize,
    },
    #[error("Failed to convert bytes {bytes:?} into a prime field element")]
    BytesToPrimeFieldElement { bytes: Vec<u8> },
    #[error("Input is larger than the modulus of the prime field.")]
    InputLargerThanModulus,
    #[error("Failed to convert a vector of bytes into an array.")]
    VecToArray,
    #[error("Failed to convert the number of inputs from u64 to u8.")]
    U64Tou8,
    #[error("Failed to convert bytes to BigInt")]
    BytesToBigInt,
    #[error("Invalid width: {width}. Choose a width between 2 and 16 for 1 to 15 inputs.")]
    InvalidWidthCircom { width: usize, max_limit: usize },
}

pub trait PoseidonHasher<F: PrimeField> {
    /// Calculates a Poseidon hash for the given input of prime fields and
    /// returns the result as a prime field.
    ///
    /// # Examples
    ///
    /// Example with two simple big-endian byte inputs (converted to prime
    /// fields) and BN254-based parameters provided by the library.
    ///
    /// ```rust
    /// use ark_bn254::Fr;
    /// use ark_ff::PrimeField;
    /// use pso_poseidon::{Poseidon, PoseidonHasher};
    ///
    /// let mut poseidon = Poseidon::<Fr>::new_circom(2).unwrap();
    ///
    /// let input1 = Fr::from_le_bytes_mod_order(&[1u8; 32]);
    /// let input2 = Fr::from_le_bytes_mod_order(&[2u8; 32]);
    ///
    /// let hash = poseidon.hash(&[input1, input2]).unwrap();
    /// ```
    fn hash(&mut self, inputs: &[F]) -> Result<F, PoseidonError>;
}
