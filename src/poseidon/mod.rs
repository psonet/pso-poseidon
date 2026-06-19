//! Circom-compatible Poseidon — the original PSO hash.
//!
//! The permutation and pre-generated BN254 parameters live here; the
//! [`PoseidonHasher`](crate::PoseidonHasher) trait this implements is defined in
//! the crate root and shared with [`Poseidon2`](crate::Poseidon2).

use ark_bn254::Fr;
#[cfg(test)]
use ark_ff::BigInteger;
use ark_ff::PrimeField;

use crate::{PoseidonError, PoseidonHasher, MAX_X5_LEN};

mod constants;

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

impl<F: PrimeField> Poseidon<F> {
    pub fn new_circom(nr_inputs: usize) -> Result<Poseidon<Fr>, PoseidonError> {
        Self::with_domain_tag_circom(nr_inputs, Fr::from(0u64))
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

        let params = constants::get_poseidon_parameters::<Fr>(
            (width).try_into().map_err(|_| PoseidonError::U64Tou8)?,
        )?;
        Ok(Poseidon::<Fr>::with_domain_tag(params, domain_tag))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// Checks the hash of byte slices consistng of ones and twos.
    #[test]
    fn test_poseidon_bn254_x5_fq_input_ones_twos() {
        let input1 = Fr::from_le_bytes_mod_order(&[1u8; 32]);
        let input2 = Fr::from_le_bytes_mod_order(&[2u8; 32]);
        let mut hasher = Poseidon::<Fr>::new_circom(2).unwrap();

        let hash = hasher.hash(&[input1, input2]).unwrap();

        assert_eq!(
            hash.into_bigint().to_bytes_le(),
            [
                144, 25, 130, 41, 200, 53, 231, 38, 27, 206, 162, 156, 254, 132, 123, 32, 25, 99,
                242, 85, 3, 94, 235, 125, 28, 140, 138, 143, 147, 225, 84, 13
            ]
        );
    }
}
