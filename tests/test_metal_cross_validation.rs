use puzzle71_solver::crypto::address::privkey_u128_to_address;
use puzzle71_solver::metal_engine::metal_solver::MetalSolver;
use puzzle71_solver::search::rng::get_secure_uniform_u128;

#[test]
fn test_metal_gpu_vs_cpu_cross_validation_10000_keys() {
    println!("Initializing Metal GPU Solver for 10,000-key Cross-Validation...");
    let solver = MetalSolver::new().expect("Failed to initialize Metal Solver");

    // Perform 10 independent batches of 1,024 keys = 10,240 keys tested
    let batch_count = 10;
    let threads_per_batch = 64;
    let steps_per_thread = 16;
    let keys_per_batch = (threads_per_batch * steps_per_thread) as u128; // 1,024

    let mut total_tested = 0u64;

    for batch in 0..batch_count {
        // Pick a random base key in the 70-bit range [2^70, 2^71 - 1]
        let base_key =
            (1u128 << 70) + get_secure_uniform_u128((1u128 << 69) - keys_per_batch).unwrap();

        // Choose a secret target index within this batch
        let secret_offset = get_secure_uniform_u128(keys_per_batch - 1).unwrap();
        let target_key = base_key + secret_offset;

        // Compute ground-truth HASH160 and address via CPU reference
        let (cpu_addr, cpu_h160, _) = privkey_u128_to_address(target_key);

        // Run Metal GPU solver across the batch
        let gpu_result = solver
            .dispatch_block(
                base_key,
                threads_per_batch,
                steps_per_thread as u32,
                &cpu_h160,
            )
            .expect("Metal dispatch failed");

        match gpu_result {
            Some(found_key) => {
                assert_eq!(
                    found_key, target_key,
                    "GPU found key 0x{:x} does not match ground truth target key 0x{:x}!",
                    found_key, target_key
                );

                // Independent CPU verification of GPU result
                let (ver_addr, ver_h160, _) = privkey_u128_to_address(found_key);
                assert_eq!(ver_addr, cpu_addr);
                assert_eq!(ver_h160, cpu_h160);
            }
            None => {
                panic!(
                    "GPU failed to find known target key in batch {} (base_key: 0x{:x}, target_key: 0x{:x})",
                    batch, base_key, target_key
                );
            }
        }

        // Also test negative verification: Target not in range
        let dummy_h160 = [0xffu8; 20];
        let negative_result = solver
            .dispatch_block(
                base_key,
                threads_per_batch,
                steps_per_thread as u32,
                &dummy_h160,
            )
            .expect("Metal dispatch failed");
        assert!(
            negative_result.is_none(),
            "GPU reported false positive on dummy target!"
        );

        total_tested += keys_per_batch as u64;
    }

    println!(
        "Successfully cross-validated {} keys across CPU & Metal GPU (0 mismatches, 0 false positives).",
        total_tested
    );
}

#[test]
fn test_metal_large_batch_cross_validation_10000() {
    let solver = MetalSolver::new().expect("Failed to initialize Metal Solver");

    // Single large batch of 10,240 keys (1024 threads x 10 steps)
    let threads = 1024;
    let steps: u32 = 10;

    let base_key = (1u128 << 70) + get_secure_uniform_u128(1_000_000_000).unwrap();
    let secret_offset = 7777u128;
    let target_key = base_key + secret_offset;

    let (cpu_addr, cpu_h160, _) = privkey_u128_to_address(target_key);

    let gpu_result = solver
        .dispatch_block(base_key, threads, steps, &cpu_h160)
        .expect("Metal dispatch failed");

    assert_eq!(gpu_result, Some(target_key));
    let (ver_addr, ver_h160, _) = privkey_u128_to_address(gpu_result.unwrap());
    assert_eq!(ver_addr, cpu_addr);
    assert_eq!(ver_h160, cpu_h160);
    println!("Large 10,240-key GPU batch verified successfully!");
}

#[test]
fn test_metal_exact_dispatch_does_not_scan_padding() {
    let solver = MetalSolver::new().expect("Failed to initialize Metal Solver");
    let base_key = (1u128 << 70) + 123_456;
    let threads = 8;
    let steps = 16;
    let valid_key_count = 100usize;

    let inside_key = base_key + 99;
    let (_, inside_hash160, _) = privkey_u128_to_address(inside_key);
    let inside = solver
        .dispatch_exact(base_key, threads, steps, valid_key_count, &inside_hash160)
        .expect("exact Metal dispatch failed");
    assert_eq!(inside.found_key, Some(inside_key));

    let padded_key = base_key + 100;
    let (_, padded_hash160, _) = privkey_u128_to_address(padded_key);
    let padded = solver
        .dispatch_exact(base_key, threads, steps, valid_key_count, &padded_hash160)
        .expect("exact Metal dispatch failed");
    assert_eq!(padded.found_key, None);
}
