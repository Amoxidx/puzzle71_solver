//! Hardcoded immutable parameters for Bitcoin Puzzle #71.
//!
//! Per safety requirements, target address and search bounds are fixed at compile-time.
//! No CLI options are provided to modify these parameters.

pub const PUZZLE_NUMBER: u32 = 71;
pub const TARGET_ADDRESS: &str = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU";
pub const TARGET_REWARD_BTC: f64 = 7.10;

/// Exact 20-byte RIPEMD-160(SHA-256(compressed_pubkey)) corresponding to `1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU`.
pub const TARGET_HASH160: [u8; 20] = [
    0xf6, 0xf5, 0x43, 0x1d, 0x25, 0xbb, 0xf7, 0xb1, 0x2e, 0x8a, 0xdd, 0x9a, 0xf5, 0xe3, 0x47, 0x5c,
    0x44, 0xa0, 0xa5, 0xb8,
];

/// Minimum private key for Puzzle #71: 2^70 = 0x400000000000000000
pub const RANGE_MIN: u128 = 1u128 << 70; // 0x400000000000000000 = 1,180,591,620,717,411,303,424

/// Maximum private key for Puzzle #71: 2^71 - 1 = 0x7FFFFFFFFFFFFFFFFF
pub const RANGE_MAX: u128 = (1u128 << 71) - 1; // 0x7FFFFFFFFFFFFFFFFF = 2,361,183,241,434,822,606,847

/// Total size of the search range in keys (2^70)
pub const RANGE_SIZE: u128 = 1u128 << 70;
