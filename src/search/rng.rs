//! Cryptographically Secure Random Number Generator using macOS Kernel CSRNG (`getentropy`).
//!
//! Per safety requirements:
//! - No timestamps as RNG seeds.
//! - No weak PRNGs.
//! - Direct kernel entropy via `libc::getentropy`.
//! - Unbiased rejection sampling for uniform distribution over keyspace.

use crate::puzzle_config::{RANGE_MAX, RANGE_MIN, RANGE_SIZE};

/// Read cryptographically secure random bytes directly from the macOS kernel.
pub fn get_secure_random_bytes(buf: &mut [u8]) -> Result<(), &'static str> {
    let mut offset = 0;
    while offset < buf.len() {
        let chunk_len = std::cmp::min(buf.len() - offset, 256);
        let ret = unsafe {
            libc::getentropy(
                buf[offset..offset + chunk_len].as_mut_ptr() as *mut libc::c_void,
                chunk_len,
            )
        };
        if ret != 0 {
            return Err("libc::getentropy failed to provide kernel entropy");
        }
        offset += chunk_len;
    }
    Ok(())
}

/// Generate a cryptographically secure uniform random 128-bit integer in range [0, max_val]
/// using unbiased rejection sampling to prevent modulo bias.
pub fn get_secure_uniform_u128(max_val: u128) -> Result<u128, &'static str> {
    if max_val == 0 {
        return Ok(0);
    }
    if max_val == u128::MAX {
        let mut buf = [0u8; 16];
        get_secure_random_bytes(&mut buf)?;
        return Ok(u128::from_le_bytes(buf));
    }

    // Number of possible outcomes: max_val + 1
    let range = max_val + 1;
    // Compute largest multiple of `range` that fits in u128
    let limit = u128::MAX - (u128::MAX % range);

    let mut buf = [0u8; 16];
    loop {
        get_secure_random_bytes(&mut buf)?;
        let val = u128::from_le_bytes(buf);
        if val < limit {
            return Ok(val % range);
        }
        // Rejection sample if val >= limit to eliminate modulo bias
    }
}

/// Select a random block start key within Bitcoin Puzzle #71 range [2^70, 2^71 - 1]
/// aligned to block_size.
pub fn select_random_block_start(block_size: u128) -> Result<u128, &'static str> {
    if block_size == 0 || block_size > RANGE_SIZE {
        return Err("Invalid block size");
    }

    let total_blocks = RANGE_SIZE / block_size;
    let block_index = get_secure_uniform_u128(total_blocks - 1)?;
    let start_key = RANGE_MIN + block_index * block_size;

    assert!(start_key >= RANGE_MIN);
    assert!(start_key + block_size - 1 <= RANGE_MAX);

    Ok(start_key)
}
