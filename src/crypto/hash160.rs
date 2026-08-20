//! Bitcoin HASH160: RIPEMD-160(SHA-256(data)).

use crate::crypto::ripemd160::{ripemd160, ripemd160_32};
use crate::crypto::sha256::{sha256, sha256_33};

/// Standard HASH160 for arbitrary byte slice
pub fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = sha256(data);
    ripemd160(&sha)
}

/// Ultra-fast specialized HASH160 for a 33-byte compressed public key
#[inline(always)]
pub fn hash160_from_pubkey33(pubkey: &[u8; 33]) -> [u8; 20] {
    let sha = sha256_33(pubkey);
    ripemd160_32(&sha)
}
