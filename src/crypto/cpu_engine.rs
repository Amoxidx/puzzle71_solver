//! Incremental CPU Solver Engine and 24-Bit Mini-Puzzle Self-Test.

use crate::crypto::address::privkey_u128_to_address;
use crate::crypto::hash160::hash160_from_pubkey33;
use crate::crypto::secp256k1::{G, scalar_mul_g};
use crate::crypto::u256::U256;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct MiniPuzzleResult {
    pub found_key: u128,
    pub target_address: String,
    pub target_hash160: [u8; 20],
    pub keys_scanned: u64,
    pub elapsed_secs: f64,
    pub keys_per_sec: f64,
    pub verified: bool,
}

/// Run an incremental search over a range [range_start, range_end] on CPU
/// looking for target_hash160.
///
/// Uses efficient incremental point addition:
/// P_0 = range_start * G
/// P_{i+1} = P_i + G (mixed Jacobian + Affine addition)
pub fn cpu_incremental_scan(
    range_start: u128,
    range_end: u128,
    target_hash160: &[u8; 20],
) -> Option<u128> {
    assert!(range_end >= range_start);

    // Initial point P_0 = range_start * G
    let u_start = U256::from_u128(range_start);
    let mut current_jacobian = scalar_mul_g(&u_start).to_jacobian();

    let mut current_key = range_start;
    while current_key <= range_end {
        let affine = current_jacobian.to_affine();
        let comp = affine.to_compressed();
        let h160 = hash160_from_pubkey33(&comp);

        if &h160 == target_hash160 {
            return Some(current_key);
        }

        // Advance to next key: P_{i+1} = P_i + G
        current_jacobian = current_jacobian.add_affine(&G);
        current_key += 1;
    }

    None
}

/// 24-Bit Mini-Puzzle self-test validator.
///
/// Generates a synthetic 24-bit puzzle in range [0x800000, 0x8FFFFF],
/// calculates the target address from a secret test key,
/// feeds ONLY the range and target to the solver,
/// and verifies the found private key and derived address.
pub fn run_mini_puzzle_test() -> Result<MiniPuzzleResult, String> {
    // Secret test key in 24-bit range
    let secret_test_key: u128 = 0x82A7F3; // 8,562,675
    let test_range_start: u128 = 0x800000; // 8,388,608
    let test_range_end: u128 = 0x830000; // 8,585,216

    let (target_addr, target_h160, _) = privkey_u128_to_address(secret_test_key);

    let start_time = Instant::now();
    let found = cpu_incremental_scan(test_range_start, test_range_end, &target_h160);
    let elapsed = start_time.elapsed().as_secs_f64();

    match found {
        Some(found_key) => {
            if found_key != secret_test_key {
                return Err(format!(
                    "Mini-puzzle key mismatch! Found: 0x{:x}, Expected: 0x{:x}",
                    found_key, secret_test_key
                ));
            }

            // Independent verification
            let (verified_addr, verified_h160, _) = privkey_u128_to_address(found_key);
            if verified_addr != target_addr || verified_h160 != target_h160 {
                return Err("Mini-puzzle address verification failed!".to_string());
            }

            let keys_scanned = (found_key - test_range_start + 1) as u64;
            let rate = if elapsed > 0.0 {
                keys_scanned as f64 / elapsed
            } else {
                0.0
            };

            Ok(MiniPuzzleResult {
                found_key,
                target_address: target_addr,
                target_hash160: target_h160,
                keys_scanned,
                elapsed_secs: elapsed,
                keys_per_sec: rate,
                verified: true,
            })
        }
        None => Err("Mini-puzzle solver failed to find secret test key in range!".to_string()),
    }
}
