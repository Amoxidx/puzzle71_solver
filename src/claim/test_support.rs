//! Shared test-only fixtures for `src/claim/`'s unit tests.
//!
//! Compiled only under `#[cfg(test)]` (see the `mod` declaration in `src/claim/mod.rs`) — never
//! part of the product binary. `.unwrap()`/`.expect()` are fine here; the "no unwrap/expect in
//! product code" rule in `phase1-claim-core.md` "Verbote" applies to `src/claim/`'s product
//! code, and this module is test-only fixture code, exactly the carve-out that rule states
//! ("in Tests erlaubt").

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, absolute, consensus,
    transaction,
};

use crate::claim::key::ClaimKey;
use crate::claim::prevout::{VerifiedPrevout, p2pkh_script_for_hash160, verify_prevout};

/// A fixed, arbitrary test scalar shared across `claim` unit tests. Its only relevant property
/// is being a valid secp256k1 scalar (`0 < scalar < curve order`); it is not derived from, or
/// related to, the real puzzle private key.
pub(crate) const TEST_SCALAR: u128 = 0x82A7F3;

/// Derives the compressed-pubkey HASH160 for a given test scalar, using the same primitives
/// (`bitcoin`/`secp256k1`) `ClaimKey::from_u128` uses internally — but independently of
/// `ClaimKey`, so tests that need *some* valid (key, hash160) pair are not circularly relying on
/// the very code (`ClaimKey::from_u128`'s hash160 check) that key.rs's own unit tests exercise.
pub(crate) fn derive_hash160(scalar: u128) -> [u8; 20] {
    let mut bytes = [0u8; 32];
    bytes[16..].copy_from_slice(&scalar.to_be_bytes());
    let secret = SecretKey::from_slice(&bytes).expect("test scalar must be a valid secp256k1 key");
    let secp = Secp256k1::signing_only();
    let pubkey = secret.public_key(&secp);
    bitcoin::PublicKey::new(pubkey)
        .pubkey_hash()
        .to_byte_array()
}

/// A [`ClaimKey`] fixture for [`TEST_SCALAR`].
pub(crate) fn test_claim_key() -> ClaimKey {
    let hash160 = derive_hash160(TEST_SCALAR);
    ClaimKey::from_u128(TEST_SCALAR, hash160).expect("self-derived hash160 must match")
}

/// Builds a legacy funding transaction with a single P2PKH output of `value_sat` paying
/// `hash160`, then independently verifies it via the real [`verify_prevout`] to produce a
/// [`VerifiedPrevout`] fixture — exercising the same verification path the real claim flow
/// uses, not a shortcut around it.
pub(crate) fn funded_prevout(hash160: [u8; 20], value_sat: u64) -> VerifiedPrevout {
    let script = p2pkh_script_for_hash160(hash160);
    let tx = Transaction {
        version: transaction::Version::ONE,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value_sat),
            script_pubkey: script.clone(),
        }],
    };
    let raw = consensus::serialize(&tx);
    let expected = OutPoint {
        txid: tx.compute_txid(),
        vout: 0,
    };
    verify_prevout(expected, &raw, &script).expect("freshly built funding tx must verify")
}
