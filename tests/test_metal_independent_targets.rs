use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use puzzle71_solver::metal_engine::metal_solver::MetalSolver;
use puzzle71_solver::puzzle_config::{RANGE_MAX, RANGE_MIN};

fn independent_hash(key: u128) -> [u8; 20] {
    let mut scalar = [0u8; 32];
    scalar[16..].copy_from_slice(&key.to_be_bytes());
    let public = SecretKey::from_slice(&scalar)
        .unwrap()
        .public_key(&Secp256k1::signing_only());
    bitcoin::hashes::hash160::Hash::hash(&public.serialize()).to_byte_array()
}

#[test]
fn finds_independent_targets_at_range_and_u64_carry_boundaries() {
    let solver = MetalSolver::new().expect("real Metal device required");
    for key in [
        RANGE_MIN,
        RANGE_MAX,
        RANGE_MIN + (1u128 << 64) - 1,
        RANGE_MIN + (1u128 << 64),
    ] {
        for steps in [1u32, 16, 128, 256] {
            let start = key.saturating_sub(7).max(RANGE_MIN);
            let keys = (RANGE_MAX - start + 1).min(33) as usize;
            let threads = keys.div_ceil(steps as usize);
            let result = solver
                .dispatch_exact(start, threads, steps, keys, &independent_hash(key))
                .unwrap();
            assert_eq!(result.found_key, Some(key), "target={key:x}, steps={steps}");
        }
    }
}

#[test]
fn padding_beyond_upper_puzzle_bound_is_not_searched() {
    let solver = MetalSolver::new().expect("real Metal device required");
    let result = solver
        .dispatch_exact(RANGE_MAX - 1, 4, 128, 2, &independent_hash(RANGE_MAX + 1))
        .unwrap();
    assert_eq!(result.found_key, None);
}

#[test]
fn production_gpu_startup_check_recovers_an_independent_target() {
    MetalSolver::new().unwrap().self_test().unwrap();
}
