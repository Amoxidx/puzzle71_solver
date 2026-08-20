//! Bitcoin P2PKH address derivation from secp256k1 private / public keys.

use crate::crypto::base58::b58check_encode;
use crate::crypto::hash160::hash160_from_pubkey33;
use crate::crypto::secp256k1::{AffinePoint, scalar_mul_g};
use crate::crypto::u256::U256;

/// Mainnet P2PKH address version byte (0x00)
pub const P2PKH_MAINNET_VERSION: u8 = 0x00;

/// Derive Bitcoin P2PKH address, 20-byte HASH160, and 33-byte compressed pubkey from a U256 private key
pub fn privkey_to_address(privkey: &U256) -> (String, [u8; 20], [u8; 33]) {
    let pubkey_point = scalar_mul_g(privkey);
    pubkey_to_address(&pubkey_point)
}

/// Derive Bitcoin P2PKH address from a 128-bit private key integer
pub fn privkey_u128_to_address(privkey: u128) -> (String, [u8; 20], [u8; 33]) {
    let u256 = U256::from_u128(privkey);
    privkey_to_address(&u256)
}

/// Derive Bitcoin P2PKH address from an Affine public key point
pub fn pubkey_to_address(point: &AffinePoint) -> (String, [u8; 20], [u8; 33]) {
    let compressed = point.to_compressed();
    let (addr, h160) = pubkey33_to_address(&compressed);
    (addr, h160, compressed)
}

/// Derive Bitcoin P2PKH address from a 33-byte compressed public key
pub fn pubkey33_to_address(compressed: &[u8; 33]) -> (String, [u8; 20]) {
    let h160 = hash160_from_pubkey33(compressed);
    let addr = b58check_encode(P2PKH_MAINNET_VERSION, &h160);
    (addr, h160)
}
