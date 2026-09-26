//! A Poseidon2 hash generic over the prime field, with BN254 built in.
//! [`Poseidon2::permutation`] matches `bn254_blackbox_solver::poseidon2` (the
//! `Poseidon2Permutation` blackbox). Two sponges are built on it:
//!
//! - [`PoseidonHasher::hash`](crate::PoseidonHasher) — `iv = len << 64` in the
//!   capacity, absorb in `RATE` blocks with a permutation after each full
//!   block, then **always** a final permutation, squeeze `state[0]`. This is
//!   the framing psonet's circuits use (`pso-circuit-core/src/hash2.nr`) and
//!   must not change.
//! - [`Poseidon2::hash_noir`] — the sponge of `noir-lang/poseidon`'s
//!   `Poseidon2::hash` and Barretenberg: identical, except the final
//!   permutation is skipped when the last block was full (`len` a non-zero
//!   multiple of 3). Use it to reproduce circuits built on that library.
//!
//! The two agree unless `len` is a non-zero multiple of 3.
//!
//! Width `t = 4`, S-box `x^5`, `R_F = 8` full + `R_P = 56` partial rounds. The
//! BN254 constants are vendored verbatim in the private `constants` submodule;
//! a Poseidon2 over any other field must supply its own [`Poseidon2Config`].

use ark_ff::PrimeField;

use crate::{PoseidonError, PoseidonHasher};

mod constants;
pub use constants::Poseidon2Config;

/// Sponge rate (state width 4 = rate 3 + capacity 1).
const RATE: usize = 3;
/// Permutation state width.
const T: usize = 4;

/// A Poseidon2 hasher generic over the prime field `F`, mirroring
/// [`crate::Poseidon`].
///
/// The round constants and matrix diagonal are field-specific, so a hasher
/// borrows a `'static` [`Poseidon2Config<F>`](Poseidon2Config). BN254 is built
/// in via [`Poseidon2::<Fr>::new`](Poseidon2::new) and is bit-compatible with
/// noir's in-circuit `poseidon2`; any other field is reached through
/// [`with_config`](Poseidon2::with_config) with constants generated for that
/// field.
#[derive(Clone, Copy)]
pub struct Poseidon2<F: PrimeField> {
    config: &'static Poseidon2Config<F>,
}

impl<F: PrimeField> Poseidon2<F> {
    /// A Poseidon2 hasher using the given (field-specific) constants.
    pub fn with_config(config: &'static Poseidon2Config<F>) -> Self {
        Self { config }
    }

    /// `x^5` S-box.
    #[inline(always)]
    fn single_box(x: F) -> F {
        let s = x * x; // x^2
        s * s * x // x^5
    }

    fn s_box(state: &mut [F; T]) {
        for x in state.iter_mut() {
            *x = Self::single_box(*x);
        }
    }

    fn add_round_constants(&self, state: &mut [F; T], round: usize) {
        for (s, c) in state
            .iter_mut()
            .zip(self.config.round_constant[round].iter())
        {
            *s += *c;
        }
    }

    /// External linear layer — bb's 4×4 matrix, copied step-for-step from the
    /// barretenberg / `bn254_blackbox_solver` implementation.
    fn matrix_multiplication_4x4(input: &mut [F; T]) {
        let t0 = input[0] + input[1];
        let t1 = input[2] + input[3];
        let mut t2 = input[1] + input[1];
        t2 += t1;
        let mut t3 = input[3] + input[3];
        t3 += t0;
        let mut t4 = t1 + t1;
        t4 += t4;
        t4 += t3;
        let mut t5 = t0 + t0;
        t5 += t5;
        t5 += t2;
        let t6 = t3 + t5;
        let t7 = t2 + t4;
        input[0] = t6;
        input[1] = t5;
        input[2] = t7;
        input[3] = t4;
    }

    /// Internal linear layer — diagonal matrix plus the state sum.
    fn internal_m_multiplication(&self, state: &mut [F; T]) {
        let mut sum = F::ZERO;
        for x in state.iter() {
            sum += *x;
        }
        let diag = &self.config.internal_matrix_diagonal;
        for (i, x) in state.iter_mut().enumerate() {
            *x *= diag[i];
            *x += sum;
        }
    }

    /// The Poseidon2 permutation on a width-4 state.
    pub fn permutation(&self, inputs: &[F; T]) -> [F; T] {
        let cfg = self.config;
        let mut state = *inputs;
        Self::matrix_multiplication_4x4(&mut state);

        // First half of the external (full) rounds.
        let rf_first = (cfg.rounds_f / 2) as usize;
        for r in 0..rf_first {
            self.add_round_constants(&mut state, r);
            Self::s_box(&mut state);
            Self::matrix_multiplication_4x4(&mut state);
        }

        // Internal (partial) rounds — S-box on element 0 only.
        let p_end = rf_first + cfg.rounds_p as usize;
        for r in rf_first..p_end {
            state[0] += cfg.round_constant[r][0];
            state[0] = Self::single_box(state[0]);
            self.internal_m_multiplication(&mut state);
        }

        // Second half of the external rounds.
        let num_rounds = (cfg.rounds_f + cfg.rounds_p) as usize;
        for r in p_end..num_rounds {
            self.add_round_constants(&mut state, r);
            Self::s_box(&mut state);
            Self::matrix_multiplication_4x4(&mut state);
        }
        state
    }

    /// Poseidon2 sponge exactly as `noir-lang/poseidon`'s
    /// `Poseidon2::hash(input, len)` and Barretenberg compute it: `iv = len << 64`
    /// seeds the capacity, rate blocks of [`RATE`] are absorbed with a
    /// permutation after each full block, and a final permutation runs only if
    /// the last block was partial (or `len == 0`). Differs from
    /// [`PoseidonHasher::hash`](crate::PoseidonHasher) when `len` is a non-zero
    /// multiple of [`RATE`].
    pub fn hash_noir(&self, inputs: &[F]) -> F {
        let len = inputs.len();
        let iv = F::from(len as u64) * F::from(1u128 << 64);
        let mut state = [F::ZERO, F::ZERO, F::ZERO, iv];
        let full = len / RATE;
        for block in 0..full {
            state[0] += inputs[block * RATE];
            state[1] += inputs[block * RATE + 1];
            state[2] += inputs[block * RATE + 2];
            state = self.permutation(&state);
        }
        for i in 0..(len % RATE) {
            state[i] += inputs[full * RATE + i];
        }
        if len == 0 || !len.is_multiple_of(RATE) {
            state = self.permutation(&state);
        }
        state[0]
    }

    /// Fixed-arity Poseidon2 sponge of `inputs` in psonet's framing:
    /// `iv = (len << 64)` seeds the capacity; the rate is absorbed in blocks of
    /// [`RATE`], then a final permutation always squeezes `state[0]`. Matches
    /// `pso-circuit-core/src/hash2.nr`; see [`Poseidon2::hash_noir`] for the
    /// `noir-lang/poseidon` variant.
    fn sponge(&self, inputs: &[F]) -> F {
        let len = inputs.len();
        // iv = len << 64
        let iv = F::from(len as u64) * F::from(1u128 << 64);
        let mut state = [F::ZERO, F::ZERO, F::ZERO, iv];

        let full = len / RATE;
        for block in 0..full {
            state[0] += inputs[block * RATE];
            state[1] += inputs[block * RATE + 1];
            state[2] += inputs[block * RATE + 2];
            state = self.permutation(&state);
        }
        for i in 0..(len % RATE) {
            state[i] += inputs[full * RATE + i];
        }
        self.permutation(&state)[0]
    }
}

impl Poseidon2<ark_bn254::Fr> {
    /// A BN254 Poseidon2 hasher. The permutation is Barretenberg's; see the
    /// module docs for which sponge matches which in-circuit hash.
    pub fn new() -> Self {
        Self::with_config(&constants::BN254_CONFIG)
    }
}

impl Default for Poseidon2<ark_bn254::Fr> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: PrimeField> PoseidonHasher<F> for Poseidon2<F> {
    /// Hashes `inputs` with the Poseidon2 sponge. Always `Ok` — the sponge is
    /// infallible — so the `Result` exists only for trait symmetry with
    /// [`crate::Poseidon`].
    fn hash(&mut self, inputs: &[F]) -> Result<F, PoseidonError> {
        Ok(self.sponge(inputs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_ff::MontFp;

    /// Known-answer for the permutation, from `bn254_blackbox_solver`'s own
    /// `smoke_test` (the C++ barretenberg reference value).
    #[test]
    fn permutation_kat_zeroes() {
        let out = Poseidon2::<Fr>::new().permutation(&[Fr::from(0u64); 4]);
        let expected = [
            MontFp!("0x18dfb8dc9b82229cff974efefc8df78b1ce96d9d844236b496785c698bc6732e"),
            MontFp!("0x095c230d1d37a246e8d2d5a63b165fe0fade040d442f61e25f0590e5fb76f839"),
            MontFp!("0x0bb9545846e1afa4fa3c97414a60a20fc4949f537a68cceca34c5ce71e28aa59"),
            MontFp!("0x18a4f34c9c6f99335ff7638b82aeed9018026618358873c982bbdde265b2ed6d"),
        ];
        assert_eq!(
            out, expected,
            "Poseidon2 permutation must match barretenberg"
        );
    }

    /// Sponge KAT — ground truth from `nargo execute` of the same
    /// `poseidon2_permutation` framing the circuits use (iv = len<<64; hash_3
    /// absorb-permute then squeeze-permute). Locks the off-circuit hash to the
    /// in-circuit computation.
    #[test]
    fn hash_kat_from_noir() {
        let mut hasher = Poseidon2::<Fr>::new();
        let h2 = hasher.hash(&[Fr::from(1u64), Fr::from(2u64)]).unwrap();
        assert_eq!(
            h2,
            MontFp!("0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383"),
            "hash_2 must match noir"
        );
        let h3 = hasher
            .hash(&[Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)])
            .unwrap();
        assert_eq!(
            h3,
            MontFp!("0x16f5da1a6b40e7d71bcdf29687e7908cdf74da44c09058fe36a0a99e269c6972"),
            "hash_3 must match noir"
        );
    }

    /// `with_config` using the built-in BN254 constants must match `new`.
    #[test]
    fn with_config_matches_new() {
        let inputs = [Fr::from(7u64), Fr::from(8u64), Fr::from(9u64)];
        let via_new =
            Poseidon2::<Fr>::new().permutation(&[inputs[0], inputs[1], inputs[2], Fr::from(0u64)]);
        let via_cfg = Poseidon2::with_config(&constants::BN254_CONFIG).permutation(&[
            inputs[0],
            inputs[1],
            inputs[2],
            Fr::from(0u64),
        ]);
        assert_eq!(via_new, via_cfg);
    }
    /// `hash_noir` known answers: `nargo test` printing
    /// `noir-lang/poseidon` v0.3.0 `Poseidon2::hash([1..=n], n)` for n = 0..=7.
    #[test]
    fn hash_noir_kat_from_noir_lang_poseidon() {
        let expected: [Fr; 8] = [
            MontFp!("0x18dfb8dc9b82229cff974efefc8df78b1ce96d9d844236b496785c698bc6732e"),
            MontFp!("0x168758332d5b3e2d13be8048c8011b454590e06c44bce7f702f09103eef5a373"),
            MontFp!("0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383"),
            MontFp!("0x23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8"),
            MontFp!("0x130bf204a32cac1f0ace56c78b731aa3809f06df2731ebcf6b3464a15788b1b9"),
            MontFp!("0x2247be7014a54d17342a7ef677f58d28877780d203860396967f5d0a18d259db"),
            MontFp!("0x07f57fcda925c06dc0a311f3f17fa0218e079b514552744a25ba8a74ee8c9e7a"),
            MontFp!("0x16f929bc0d216df4b05bdc44222463edf2b9791bd949ab926eebda06a502d238"),
        ];
        let p = Poseidon2::<Fr>::new();
        for (n, want) in expected.iter().enumerate() {
            let input: Vec<Fr> = (1..=n as u64).map(Fr::from).collect();
            assert_eq!(p.hash_noir(&input), *want, "n = {n}");
        }
    }

    /// The two sponges agree except when the length is a non-zero multiple of 3.
    #[test]
    fn hash_and_hash_noir_differ_only_on_full_last_block() {
        let mut p = Poseidon2::<Fr>::new();
        for n in 0..=9u64 {
            let input: Vec<Fr> = (1..=n).map(Fr::from).collect();
            let same = p.hash(&input).unwrap() == p.hash_noir(&input);
            assert_eq!(same, n == 0 || !n.is_multiple_of(3), "n = {n}");
        }
    }
}
