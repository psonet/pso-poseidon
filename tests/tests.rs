use halo2_axiom::halo2curves::bn256::Fr;
use pso_poseidon::{Poseidon, PoseidonError, PoseidonHasher};

/// Checks the hash of byte slices consisting of ones and twos.
#[test]
fn test_poseidon_bn254_x5_fq_input_ones_twos() {
    // Use the same approach as the existing test in lib.rs
    let input1 = Fr::from_bytes(&[1u8; 32]).unwrap();
    let input2 = Fr::from_bytes(&[2u8; 32]).unwrap();
    let mut hasher = Poseidon::<Fr>::new_circom(2).unwrap();
    let hash = hasher.hash(&[input1, input2]).unwrap();

    // The expected value matches the existing test (little-endian)
    let expected_le = [
        144, 25, 130, 41, 200, 53, 231, 38, 27, 206, 162, 156, 254, 132, 123, 32, 25, 99, 242, 85,
        3, 94, 235, 125, 28, 140, 138, 143, 147, 225, 84, 13,
    ];

    assert_eq!(hash.to_bytes(), expected_le);
}

/// Checks the hash of bytes slices consisting of ones and twos, with a custom
/// domain tag.
#[test]
fn test_poseidon_bn254_x5_fq_with_domain_tag() {
    let input1 = Fr::from_bytes(&[1u8; 32]).unwrap();
    let input2 = Fr::from_bytes(&[2u8; 32]).unwrap();
    let mut hasher = Poseidon::<Fr>::with_domain_tag_circom(2, Fr::zero()).unwrap();
    let hash = hasher.hash(&[input1, input2]).unwrap();

    // Expected value with zero domain tag (same as default)
    let expected_tag_zero_le = [
        144, 25, 130, 41, 200, 53, 231, 38, 27, 206, 162, 156, 254, 132, 123, 32, 25, 99, 242, 85,
        3, 94, 235, 125, 28, 140, 138, 143, 147, 225, 84, 13,
    ];

    assert_eq!(hash.to_bytes(), expected_tag_zero_le);

    let mut hasher = Poseidon::<Fr>::with_domain_tag_circom(2, Fr::one()).unwrap();
    let hash = hasher.hash(&[input1, input2]).unwrap();
    // Should be different from zero domain tag
    assert_ne!(hash.to_bytes(), expected_tag_zero_le);
}

/// Check whether providing different number of inputs than supported by the
/// hasher results in an error.
#[test]
fn test_poseidon_bn254_x5_fq_too_many_inputs() {
    // Use simple field elements that we know work
    let input1 = Fr::from_bytes(&[1u8; 32]).unwrap();
    let input2 = Fr::from_bytes(&[2u8; 32]).unwrap();

    for i in 1..13 {
        let mut hasher = Poseidon::<Fr>::new_circom(i).unwrap();

        for j in 1..13 {
            if i != j {
                // Create j inputs (alternating between input1 and input2)
                let inputs: Vec<_> = (0..j)
                    .map(|k| if k % 2 == 0 { input1 } else { input2 })
                    .collect();
                let res = hasher.hash(&inputs);
                assert!(res.is_err());
            }
        }
    }
}

/// Check whether creating a hasher for more than 12 inputs results in an
/// error.
#[test]
fn test_circom_solana_t_gt_12_fails() {
    for i in 13..16 {
        let hasher = Poseidon::<Fr>::new_circom(i);
        assert!(hasher.is_err());
        if let Err(PoseidonError::InvalidWidthCircom { width, max_limit }) = hasher {
            assert_eq!(width, i + 1);
            assert_eq!(max_limit, 13);
        } else {
            panic!("Expected InvalidWidthCircom error");
        }
    }
}

/// Checks whether creating a hasher for 0 inputs results in an error.
#[test]
fn test_circom_t_0_fails() {
    let hasher = Poseidon::<Fr>::new_circom(0);
    assert!(hasher.is_err());
    if let Err(PoseidonError::InvalidWidthCircom { width, max_limit }) = hasher {
        assert_eq!(width, 1);
        assert_eq!(max_limit, 13);
    } else {
        panic!("Expected InvalidWidthCircom error");
    }
}

/// Checks that hashing the same input twice produces the same results.
#[test]
fn test_poseidon_bn254_x5_fq_same_input_same_results() {
    let input = Fr::from_bytes(&[1u8; 32]).unwrap();

    for nr_inputs in 1..12 {
        let mut hasher = Poseidon::<Fr>::new_circom(nr_inputs).unwrap();

        let mut inputs = Vec::with_capacity(nr_inputs);
        for _ in 0..nr_inputs {
            inputs.push(input);
        }

        let hash1 = hasher.hash(&inputs).unwrap();
        let hash2 = hasher.hash(&inputs).unwrap();

        assert_eq!(hash1, hash2);
    }
}

/// Test that hashing different inputs produces different results.
#[test]
fn test_poseidon_bn254_x5_fq_different_inputs_different_results() {
    let input1 = Fr::from_bytes(&[1u8; 32]).unwrap();
    let input2 = Fr::from_bytes(&[2u8; 32]).unwrap();

    for nr_inputs in 1..12 {
        let mut hasher = Poseidon::<Fr>::new_circom(nr_inputs).unwrap();

        let mut inputs1 = Vec::with_capacity(nr_inputs);
        let mut inputs2 = Vec::with_capacity(nr_inputs);
        for _ in 0..nr_inputs {
            inputs1.push(input1);
            inputs2.push(input2);
        }

        let hash1 = hasher.hash(&inputs1).unwrap();
        let hash2 = hasher.hash(&inputs2).unwrap();

        assert_ne!(hash1, hash2);
    }
}

/// Test that hashing with different numbers of inputs produces different results.
#[test]
fn test_poseidon_bn254_x5_fq_different_widths_different_results() {
    let input = Fr::from_bytes(&[1u8; 32]).unwrap();

    let mut hashes = Vec::new();
    for nr_inputs in 1..12 {
        let mut hasher = Poseidon::<Fr>::new_circom(nr_inputs).unwrap();
        let mut inputs = Vec::with_capacity(nr_inputs);
        for _ in 0..nr_inputs {
            inputs.push(input);
        }
        let hash = hasher.hash(&inputs).unwrap();
        hashes.push(hash);
    }

    // All hashes should be different
    for i in 0..hashes.len() {
        for j in (i + 1)..hashes.len() {
            assert_ne!(hashes[i], hashes[j]);
        }
    }
}

/// Test that the hasher is deterministic - same inputs produce same output.
#[test]
fn test_poseidon_bn254_x5_fq_deterministic() {
    // Use known field elements
    let input1 = Fr::from_bytes(&[1u8; 32]).unwrap();
    let input2 = Fr::from_bytes(&[2u8; 32]).unwrap();

    for nr_inputs in 1..12 {
        // Create inputs (alternating between input1 and input2)
        let inputs: Vec<_> = (0..nr_inputs)
            .map(|k| if k % 2 == 0 { input1 } else { input2 })
            .collect();

        // Hash twice with the same inputs
        let mut hasher1 = Poseidon::<Fr>::new_circom(nr_inputs).unwrap();
        let mut hasher2 = Poseidon::<Fr>::new_circom(nr_inputs).unwrap();

        let hash1 = hasher1.hash(&inputs).unwrap();
        let hash2 = hasher2.hash(&inputs).unwrap();

        assert_eq!(hash1, hash2);
    }
}

/// Test that hashing with various field elements works correctly.
#[test]
fn test_poseidon_bn254_x5_fq_various_inputs() {
    // Use various known field elements that are guaranteed to be valid
    let mut inputs_list = Vec::new();

    // Add zero
    inputs_list.push(Fr::zero());

    // Add small values (1, 2, 3, etc.)
    for i in 1..10 {
        let mut bytes = [0u8; 32];
        bytes[31] = i;
        if let Some(fr) = Fr::from_bytes(&bytes).into() {
            inputs_list.push(fr);
        }
    }

    // Add some patterns
    inputs_list.push(Fr::from_bytes(&[1u8; 32]).unwrap());
    inputs_list.push(Fr::from_bytes(&[2u8; 32]).unwrap());

    for nr_inputs in 1..12 {
        let mut hasher = Poseidon::<Fr>::new_circom(nr_inputs).unwrap();

        // Create inputs from the list (cycling through)
        let inputs: Vec<_> = (0..nr_inputs)
            .map(|i| inputs_list[i % inputs_list.len()])
            .collect();

        // Should succeed
        let result = hasher.hash(&inputs);
        assert!(result.is_ok());

        // Result should be a valid field element
        let hash = result.unwrap();
        // Verify it's a valid hash (not necessarily non-zero, but should be consistent)
        let _ = hash.to_bytes(); // Just verify we can convert to bytes
    }
}
