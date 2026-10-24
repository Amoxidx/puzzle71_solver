//! Independent target checks using the dispatch profiles consumed by the real search.
use bitcoin::hashes::{Hash, hash160};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use puzzle71_solver::metal_engine::metal_solver::MetalSolver;
use puzzle71_solver::power::controller::PowerMode;
use puzzle71_solver::puzzle_config::{RANGE_MAX, RANGE_MIN};
use puzzle71_solver::search::profile::dispatch_profile;

fn independent_hash(key: u128) -> [u8; 20] {
    let mut bytes = [0u8; 32];
    bytes[16..].copy_from_slice(&key.to_be_bytes());
    let public = SecretKey::from_slice(&bytes)
        .expect("public test scalar is valid")
        .public_key(&Secp256k1::signing_only());
    hash160::Hash::hash(&public.serialize()).to_byte_array()
}

#[test]
fn balanced_and_auto_profiles_recover_independent_targets_at_batch_step_and_carry_edges() {
    let solver = MetalSolver::new().expect("real Metal device required");
    for mode in [PowerMode::Balanced, PowerMode::Auto] {
        let profile = dispatch_profile(mode);
        let keys = profile.batch_keys() as usize;
        let steps = profile.steps as usize;
        let start = RANGE_MIN + (1u128 << 32) - 16;
        for offset in [0, 15, 16, steps - 1, steps, keys - 1] {
            let target = start + offset as u128;
            let outcome = solver
                .dispatch_exact(
                    start,
                    profile.threads,
                    profile.steps,
                    keys,
                    &independent_hash(target),
                )
                .expect("profile dispatch must finish");
            assert_eq!(
                outcome.found_key,
                Some(target),
                "mode={mode:?}, offset={offset}"
            );
        }
        let carry64 = RANGE_MIN + (1u128 << 64) - 16;
        for offset in [15, 16] {
            let target = carry64 + offset;
            let outcome = solver
                .dispatch_exact(
                    carry64,
                    profile.threads,
                    profile.steps,
                    keys,
                    &independent_hash(target),
                )
                .expect("u64 carry dispatch must finish");
            assert_eq!(
                outcome.found_key,
                Some(target),
                "mode={mode:?}, u64 offset={offset}"
            );
        }
    }
}

#[test]
fn balanced_and_auto_profiles_find_the_upper_bound_and_respect_an_exact_partial_tail() {
    let solver = MetalSolver::new().expect("real Metal device required");
    for mode in [PowerMode::Balanced, PowerMode::Auto] {
        let profile = dispatch_profile(mode);
        let keys = profile.batch_keys() as usize;
        let start = RANGE_MAX + 1 - keys as u128;
        let full = solver
            .dispatch_exact(
                start,
                profile.threads,
                profile.steps,
                keys,
                &independent_hash(RANGE_MAX),
            )
            .expect("upper-bound profile dispatch must finish");
        assert_eq!(full.found_key, Some(RANGE_MAX), "mode={mode:?}");
        let valid = keys - 7;
        let inside = start + valid as u128 - 1;
        let partial = solver
            .dispatch_exact(
                start,
                profile.threads,
                profile.steps,
                valid,
                &independent_hash(inside),
            )
            .expect("partial profile dispatch must finish");
        assert_eq!(
            partial.found_key,
            Some(inside),
            "mode={mode:?}, last valid key"
        );
        let excluded = start + valid as u128;
        let padding = solver
            .dispatch_exact(
                start,
                profile.threads,
                profile.steps,
                valid,
                &independent_hash(excluded),
            )
            .expect("excluded profile dispatch must finish");
        assert_eq!(padding.found_key, None, "mode={mode:?}, first padding key");
    }
}
