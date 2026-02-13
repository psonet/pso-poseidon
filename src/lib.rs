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
//! [`Poseidon`](crate::Poseidon) type implements two traits which serve the purpose
//! of returning the calculated hash in different representations:
//!
//! * [`PoseidonHasher`](crate::PoseidonHasher) with the `hash` method which returns
//!   [`halo2_axiom::halo2curves::ff::PrimeField`](halo2_axiom::halo2curves::ff::PrimeField).
//!   Might be useful if you want to immediately process the result with another library
//!   that uses Halo2 field types.
//!
//! # Examples
//!
//! With [`PoseidonHasher`](crate::PoseidonHasher) trait and
//! [`halo2_axiom::halo2curves::ff::PrimeField`](halo2_axiom::halo2curves::ff::PrimeField) result:
//!
//! ```rust
//! use halo2_axiom::halo2curves::bn256::Fr;
//! use halo2_axiom::halo2curves::ff::PrimeField;
//! use light_poseidon::{Poseidon, PoseidonHasher, parameters::bn254_x5};
//!
//! let mut poseidon = Poseidon::<Fr>::new_circom(2).unwrap();
//!
//! let input1 = Fr::from_bytes(&[1u8; 32]).unwrap();
//! let input2 = Fr::from_bytes(&[2u8; 32]).unwrap();
//!
//! let hash = poseidon.hash(&[input1, input2]).unwrap();
//!
//! // Do something with `hash`.
//! ```
//!
//! # Implementation
//!
//! The implementation is compatible with the
//! [original SageMath implementation](https://extgit.iaik.tugraz.at/krypto/hadeshash/-/tree/master/),
//! but it was also inspired by the following ones:
//!
//! * [circomlibjs](https://github.com/iden3/circomlibjs)                  
//! * [zero-knowledge-gadgets](https://github.com/webb-tools/zero-knowledge-gadgets
//! * [light-poseidon](https://github.com/Lightprotocol/light-poseidon/)   
//!
//! # Security
//!
//! This library has been audited by [Veridise](https://veridise.com/). You can
//! read the audit report [here](https://github.com/Lightprotocol/light-poseidon/blob/main/assets/audit.pdf).

use ff::PrimeField;
use halo2_axiom::halo2curves::bn256::Fr;

use thiserror::Error;

pub mod params;

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

/// Parameters for the Poseidon hash algorithm.
pub struct PoseidonParameters<F: PrimeField> {
    /// Round constants.
    pub ark: Vec<F>,
    /// MDS matrix.
    pub mds: Vec<Vec<F>>,
    /// Number of full rounds (where S-box is applied to all elements of the
    /// state).
    pub full_rounds: usize,
    /// Number of partial rounds (where S-box is applied only to the first
    /// element of the state).
    pub partial_rounds: usize,
    /// Number of prime fields in the state.
    pub width: usize,
    /// Exponential used in S-box to power elements of the state.
    pub alpha: u64,
}

impl<F: PrimeField> PoseidonParameters<F> {
    pub fn new(
        ark: Vec<F>,
        mds: Vec<Vec<F>>,
        full_rounds: usize,
        partial_rounds: usize,
        width: usize,
        alpha: u64,
    ) -> Self {
        Self {
            ark,
            mds,
            full_rounds,
            partial_rounds,
            width,
            alpha,
        }
    }
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
    /// use halo2_axiom::halo2curves::bn256::Fr;
    /// use halo2_axiom::halo2curves::ff::PrimeField;
    /// use light_poseidon::{Poseidon, PoseidonHasher, parameters::bn254_x5};
    ///
    /// let mut poseidon = Poseidon::<Fr>::new_circom(2).unwrap();
    ///
    /// let input1 = Fr::from_bytes(&[1u8; 32]).unwrap();
    /// let input2 = Fr::from_bytes(&[2u8; 32]).unwrap();
    ///
    /// let hash = poseidon.hash(&[input1, input2]).unwrap();
    ///
    fn hash(&mut self, inputs: &[F]) -> Result<F, PoseidonError>;
}

/// A stateful sponge performing Poseidon hash computation.
pub struct Poseidon<F: PrimeField> {
    params: PoseidonParameters<F>,
    domain_tag: F,
    state: Vec<F>,
}

impl<F: PrimeField> Poseidon<F> {
    /// Returns a new Poseidon hasher based on the given parameters.
    ///
    /// Optionally, a domain tag can be provided. If it is not provided, it
    /// will be set to zero.
    pub fn new(params: PoseidonParameters<F>) -> Self {
        Self::with_domain_tag(params, F::ZERO)
    }

    fn with_domain_tag(params: PoseidonParameters<F>, domain_tag: F) -> Self {
        let width = params.width;
        Self {
            domain_tag,
            params,
            state: Vec::with_capacity(width),
        }
    }

    #[inline(always)]
    fn apply_ark(&mut self, round: usize) {
        self.state.iter_mut().enumerate().for_each(|(i, a)| {
            let c = self.params.ark[round * self.params.width + i];
            *a += c;
        });
    }

    #[inline(always)]
    fn apply_sbox_full(&mut self) {
        self.state.iter_mut().for_each(|a| {
            *a = a.pow([self.params.alpha]);
        });
    }

    #[inline(always)]
    fn apply_sbox_partial(&mut self) {
        self.state[0] = self.state[0].pow([self.params.alpha]);
    }

    #[inline(always)]
    fn apply_mds(&mut self) {
        self.state = self
            .state
            .iter()
            .enumerate()
            .map(|(i, _)| {
                self.state
                    .iter()
                    .enumerate()
                    .fold(F::ZERO, |acc, (j, a)| acc + *a * self.params.mds[i][j])
            })
            .collect();
    }
}

impl<F: PrimeField> PoseidonHasher<F> for Poseidon<F> {
    fn hash(&mut self, inputs: &[F]) -> Result<F, PoseidonError> {
        if inputs.len() != self.params.width - 1 {
            return Err(PoseidonError::InvalidNumberOfInputs {
                inputs: inputs.len(),
                max_limit: self.params.width - 1,
                width: self.params.width,
            });
        }

        self.state.push(self.domain_tag);

        for input in inputs {
            self.state.push(*input);
        }

        let all_rounds = self.params.full_rounds + self.params.partial_rounds;
        let half_rounds = self.params.full_rounds / 2;

        // full rounds + partial rounds
        for round in 0..half_rounds {
            self.apply_ark(round);
            self.apply_sbox_full();
            self.apply_mds();
        }

        for round in half_rounds..half_rounds + self.params.partial_rounds {
            self.apply_ark(round);
            self.apply_sbox_partial();
            self.apply_mds();
        }

        for round in half_rounds + self.params.partial_rounds..all_rounds {
            self.apply_ark(round);
            self.apply_sbox_full();
            self.apply_mds();
        }

        let result = self.state[0];
        self.state.clear();
        Ok(result)
    }
}

macro_rules! impl_hash_bytes {
    ($fn_name:ident, $bytes_to_prime_field_element_fn:ident, $to_bytes_fn:ident) => {
        fn $fn_name(&mut self, inputs: &[&[u8]]) -> Result<[u8; HASH_LEN], PoseidonError> {
            let inputs: Result<Vec<_>, _> = inputs
                .iter()
                .map(|input| validate_bytes_length::<F>(input))
                .collect();
            let inputs = inputs?;
            let inputs: Result<Vec<_>, _> = inputs
                .iter()
                .map(|input| $bytes_to_prime_field_element_fn(input))
                .collect();
            let inputs = inputs?;
            let hash = self.hash(&inputs)?;

            hash.into_bigint()
                .$to_bytes_fn()
                .try_into()
                .map_err(|_| PoseidonError::VecToArray)
        }
    };
}

impl<F: PrimeField> Poseidon<F> {
    pub fn new_circom(nr_inputs: usize) -> Result<Poseidon<Fr>, PoseidonError> {
        Self::with_domain_tag_circom(nr_inputs, Fr::zero())
    }

    pub fn with_domain_tag_circom(
        nr_inputs: usize,
        domain_tag: Fr,
    ) -> Result<Poseidon<Fr>, PoseidonError> {
        let width = nr_inputs + 1;
        if width > MAX_X5_LEN {
            return Err(PoseidonError::InvalidWidthCircom {
                width,
                max_limit: MAX_X5_LEN,
            });
        }

        let params = params::get_poseidon_parameters::<Fr>(
            (width).try_into().map_err(|_| PoseidonError::U64Tou8)?,
        )?;
        Ok(Poseidon::<Fr>::with_domain_tag(params, domain_tag))
    }
}

mod test {
    use super::*;

    /// Checks the hash of byte slices consistng of ones and twos.
    #[test]
    fn test_poseidon_bn254_x5_fq_input_ones_twos() {
        let input1 = Fr::from_bytes(&[1u8; 32]).unwrap();
        let input2 = Fr::from_bytes(&[2u8; 32]).unwrap();
        let mut hasher = Poseidon::<Fr>::new_circom(2).unwrap();

        let hash = hasher.hash(&[input1, input2]).unwrap();

        assert_eq!(
            hash.to_bytes(),
            [
                144, 25, 130, 41, 200, 53, 231, 38, 27, 206, 162, 156, 254, 132, 123, 32, 25, 99, 242, 85, 3, 94, 235, 125, 28, 140, 138, 143, 147, 225, 84, 13
            ]
        );
    }
}