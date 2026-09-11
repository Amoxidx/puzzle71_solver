//! Builds and signs the offline claim transaction, then independently re-verifies it before
//! ever returning it to a caller.

use std::collections::BTreeSet;
use std::fmt;

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::SighashCache;
use bitcoin::{
    Address, Amount, EcdsaSighashType, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    absolute, consensus, ecdsa, script, transaction,
};

use crate::claim::error::ClaimError;
use crate::claim::key::ClaimKey;
use crate::claim::memory::secure_zero;
use crate::claim::policy::{self, MAX_FEE_RATE_SAT_VB, MIN_FEE_RATE_SAT_VB};
use crate::claim::prevout::{VerifiedPrevout, p2pkh_script_for_hash160};
use crate::claim::verify::{ClaimSummary, verify_signed_claim};

/// A fully signed, independently re-verified claim transaction.
///
/// Holds its serialized bytes privately; [`SignedClaim::raw_tx_bytes_for_submission`] is the
/// only way to get them out. Not `Clone`, not `Serialize`, not `Display`. `Debug` always prints
/// `SignedClaim(<redacted>)`. `Drop` overwrites the held bytes with zeros.
pub struct SignedClaim {
    raw: Vec<u8>,
    summary: ClaimSummary,
}

impl fmt::Debug for SignedClaim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SignedClaim(<redacted>)")
    }
}

impl Drop for SignedClaim {
    fn drop(&mut self) {
        secure_zero(&mut self.raw);
    }
}

impl SignedClaim {
    /// The independently verified, non-secret summary of this claim.
    pub fn summary(&self) -> &ClaimSummary {
        &self.summary
    }

    /// Returns the raw, serialized signed transaction bytes.
    ///
    /// This is the only place these bytes are exposed. The serialized transaction contains the
    /// claim's compressed public key. Once these bytes leave this process — most importantly,
    /// once broadcast — that public key becomes visible, and a Kangaroo-style discrete-log
    /// attacker can then race a replacement transaction into the mempool ahead of confirmation
    /// (see `phase1-claim-core.md` "Beleg" for the #66/#69 precedents). Treat these bytes as
    /// exactly as secret as the private key itself until the transaction has confirmed.
    pub fn raw_tx_bytes_for_submission(&self) -> &[u8] {
        &self.raw
    }
}

/// Builds a claim transaction spending the economic prevouts among `prevouts` to `destination`
/// at `fee_rate_sat_vb`, signs every input with `key`, and independently re-verifies the result
/// via [`verify_signed_claim`] before returning it. Non-economic ("dust") prevouts are excluded
/// from the transaction and only counted in the returned summary.
pub fn build_signed_claim(
    key: &ClaimKey,
    prevouts: &[VerifiedPrevout],
    destination: &Address,
    fee_rate_sat_vb: u64,
) -> Result<SignedClaim, ClaimError> {
    if !(MIN_FEE_RATE_SAT_VB..=MAX_FEE_RATE_SAT_VB).contains(&fee_rate_sat_vb) {
        return Err(ClaimError::FeeRateOutOfBounds);
    }

    let mut seen_outpoints = BTreeSet::new();
    for prevout in prevouts {
        if !seen_outpoints.insert((prevout.outpoint.txid, prevout.outpoint.vout)) {
            return Err(ClaimError::DuplicateOutpoint);
        }
    }

    let key_script = p2pkh_script_for_hash160(key.hash160());
    for prevout in prevouts {
        if prevout.txout.script_pubkey.as_script() != key_script.as_script() {
            return Err(ClaimError::ScriptMismatch);
        }
    }

    let mut economic: Vec<&VerifiedPrevout> = Vec::new();
    for prevout in prevouts {
        if policy::is_economic(prevout.txout.value.to_sat(), fee_rate_sat_vb) {
            economic.push(prevout);
        }
    }
    if economic.is_empty() {
        return Err(ClaimError::NoEconomicInputs);
    }

    // Deterministic input order: ascending by (txid bytes, vout), independent of the caller's
    // supplied order — required for `build_signed_claim` to be reproducible byte-for-byte.
    economic.sort_by_key(|prevout| (prevout.outpoint.txid.to_byte_array(), prevout.outpoint.vout));

    let destination_script = destination.script_pubkey();
    // Independent of `destination.rs`'s own puzzle-address check: refuse here too, so a claim
    // can never be built into the puzzle address even if a future caller constructs `Address`
    // some other way that bypasses `parse_destination`.
    if destination_script.as_script() == key_script.as_script() {
        return Err(ClaimError::DestinationIsPuzzleAddress);
    }
    let total_input: u64 = economic.iter().map(|p| p.txout.value.to_sat()).sum();
    let fee = policy::max_vsize(economic.len() as u64, &destination_script) * fee_rate_sat_vb;
    let output_value = total_input
        .checked_sub(fee)
        .ok_or(ClaimError::OutputBelowDust)?;
    if output_value < destination_script.minimal_non_dust().to_sat() {
        return Err(ClaimError::OutputBelowDust);
    }

    let inputs: Vec<TxIn> = economic
        .iter()
        .map(|prevout| TxIn {
            previous_output: prevout.outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        })
        .collect();

    let mut tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: inputs,
        output: vec![TxOut {
            value: Amount::from_sat(output_value),
            script_pubkey: destination_script,
        }],
    };

    let secp = Secp256k1::signing_only();
    let pubkey_bytes = key.compressed_pubkey_bytes();
    for index in 0..economic.len() {
        // Real `bitcoin` API note (see report "Einwände"): `legacy_signature_hash` returns a
        // `Result`, not a bare hash — its only error is an out-of-range input index
        // (bitcoin-0.32.11/src/crypto/sighash.rs:1027-1041), which cannot occur here since
        // `index` always ranges over `tx.input`'s own length. Mapped to `SighashComputation`
        // rather than `unwrap`/`expect`, which are forbidden in this module's product code.
        let sighash = {
            let cache = SighashCache::new(&tx);
            cache
                .legacy_signature_hash(index, &key_script, EcdsaSighashType::All.to_u32())
                .map_err(|_| ClaimError::SighashComputation)?
        };

        let message = Message::from_digest(sighash.to_byte_array());
        let signature = secp.sign_ecdsa_low_r(&message, key.secret_key());
        let bitcoin_signature = ecdsa::Signature::sighash_all(signature);
        let sig_push = script::PushBytesBuf::try_from(bitcoin_signature.to_vec())
            .map_err(|_| ClaimError::SighashComputation)?;

        let script_sig = script::Builder::new()
            .push_slice(sig_push)
            .push_slice(pubkey_bytes)
            .into_script();
        tx.input[index].script_sig = script_sig;
    }

    let raw = consensus::serialize(&tx);
    let summary = verify_signed_claim(&raw, prevouts, destination, fee_rate_sat_vb)?;

    Ok(SignedClaim { raw, summary })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claim::test_support::{self, TEST_SCALAR};
    use bitcoin::PubkeyHash;

    fn test_destination() -> Address {
        // A fixed, unrelated P2PKH address, not the puzzle address and not any real owner
        // address — used only as a valid, non-forbidden destination in these tests.
        Address::p2pkh(
            PubkeyHash::from_byte_array([0x44; 20]),
            bitcoin::NetworkKind::Main,
        )
    }

    #[test]
    fn rejects_fee_rate_just_below_the_minimum() {
        let key = test_support::test_claim_key();
        let hash160 = test_support::derive_hash160(TEST_SCALAR);
        let prevout = test_support::funded_prevout(hash160, 10_000_000);
        let err = build_signed_claim(
            &key,
            &[prevout],
            &test_destination(),
            policy::MIN_FEE_RATE_SAT_VB - 1,
        )
        .unwrap_err();
        assert_eq!(err, ClaimError::FeeRateOutOfBounds);
    }

    #[test]
    fn rejects_fee_rate_just_above_the_maximum() {
        let key = test_support::test_claim_key();
        let hash160 = test_support::derive_hash160(TEST_SCALAR);
        let prevout = test_support::funded_prevout(hash160, 10_000_000);
        let err = build_signed_claim(
            &key,
            &[prevout],
            &test_destination(),
            policy::MAX_FEE_RATE_SAT_VB + 1,
        )
        .unwrap_err();
        assert_eq!(err, ClaimError::FeeRateOutOfBounds);
    }

    #[test]
    fn rejects_when_no_prevout_is_economic() {
        let key = test_support::test_claim_key();
        let hash160 = test_support::derive_hash160(TEST_SCALAR);
        let fee_rate = policy::DEFAULT_FEE_RATE_SAT_VB;
        let dust_value = policy::P2PKH_INPUT_MAX_VSIZE * fee_rate; // exactly break-even, not economic
        let prevout = test_support::funded_prevout(hash160, dust_value);
        let err = build_signed_claim(&key, &[prevout], &test_destination(), fee_rate).unwrap_err();
        assert_eq!(err, ClaimError::NoEconomicInputs);
    }

    #[test]
    fn excludes_dust_prevouts_and_counts_them_in_the_summary() {
        let key = test_support::test_claim_key();
        let hash160 = test_support::derive_hash160(TEST_SCALAR);
        let fee_rate = policy::DEFAULT_FEE_RATE_SAT_VB;
        let dust_value = policy::P2PKH_INPUT_MAX_VSIZE * fee_rate; // break-even: excluded as dust
        let economic_value = dust_value + 1_000_000;
        let dust_prevout = test_support::funded_prevout(hash160, dust_value);
        let economic_prevout = test_support::funded_prevout(hash160, economic_value);

        let claim = build_signed_claim(
            &key,
            &[dust_prevout, economic_prevout],
            &test_destination(),
            fee_rate,
        )
        .unwrap();

        assert_eq!(claim.summary().input_count, 1);
        assert_eq!(claim.summary().excluded_dust_count, 1);
        assert_eq!(claim.summary().excluded_dust_sat, dust_value);
    }

    #[test]
    fn rejects_output_below_dust() {
        let key = test_support::test_claim_key();
        let hash160 = test_support::derive_hash160(TEST_SCALAR);
        let destination = test_destination();
        let fee_rate = policy::MIN_FEE_RATE_SAT_VB;
        let fee = policy::max_vsize(1, &destination.script_pubkey()) * fee_rate;
        let dust_threshold = destination.script_pubkey().minimal_non_dust().to_sat();
        // Chosen so the computed output lands exactly 1 sat below the dust threshold, while the
        // input itself is still economic at this fee rate.
        let value = fee + dust_threshold - 1;
        assert!(
            policy::is_economic(value, fee_rate),
            "test setup: value must be economic"
        );
        let prevout = test_support::funded_prevout(hash160, value);

        let err = build_signed_claim(&key, &[prevout], &destination, fee_rate).unwrap_err();
        assert_eq!(err, ClaimError::OutputBelowDust);
    }

    #[test]
    fn rejects_a_destination_equal_to_the_puzzle_address_itself() {
        let key = test_support::test_claim_key();
        let hash160 = test_support::derive_hash160(TEST_SCALAR);
        let prevout = test_support::funded_prevout(hash160, 10_000_000);
        let puzzle_destination = Address::p2pkh(
            PubkeyHash::from_byte_array(hash160),
            bitcoin::NetworkKind::Main,
        );
        let err = build_signed_claim(
            &key,
            &[prevout],
            &puzzle_destination,
            policy::DEFAULT_FEE_RATE_SAT_VB,
        )
        .unwrap_err();
        assert_eq!(err, ClaimError::DestinationIsPuzzleAddress);
    }

    #[test]
    fn rejects_a_duplicate_outpoint() {
        let key = test_support::test_claim_key();
        let hash160 = test_support::derive_hash160(TEST_SCALAR);
        let prevout = test_support::funded_prevout(hash160, 10_000_000);
        let duplicate = prevout.clone();
        let err = build_signed_claim(
            &key,
            &[prevout, duplicate],
            &test_destination(),
            policy::DEFAULT_FEE_RATE_SAT_VB,
        )
        .unwrap_err();
        assert_eq!(err, ClaimError::DuplicateOutpoint);
    }

    #[test]
    fn rejects_a_prevout_script_that_does_not_match_the_key() {
        let key = test_support::test_claim_key();
        let foreign_hash160 = [0x99; 20];
        let prevout = test_support::funded_prevout(foreign_hash160, 10_000_000);
        let err = build_signed_claim(
            &key,
            &[prevout],
            &test_destination(),
            policy::DEFAULT_FEE_RATE_SAT_VB,
        )
        .unwrap_err();
        assert_eq!(err, ClaimError::ScriptMismatch);
    }

    #[test]
    fn building_the_same_claim_twice_yields_identical_bytes() {
        let key = test_support::test_claim_key();
        let hash160 = test_support::derive_hash160(TEST_SCALAR);
        let prevout = test_support::funded_prevout(hash160, 10_000_000);
        let destination = test_destination();
        let fee_rate = policy::DEFAULT_FEE_RATE_SAT_VB;

        let first = build_signed_claim(&key, &[prevout.clone()], &destination, fee_rate).unwrap();
        let second = build_signed_claim(&key, &[prevout], &destination, fee_rate).unwrap();

        assert_eq!(
            first.raw_tx_bytes_for_submission(),
            second.raw_tx_bytes_for_submission()
        );
    }

    #[test]
    fn redacts_key_material_from_every_observable_representation() {
        let key = test_support::test_claim_key();
        let hash160 = test_support::derive_hash160(TEST_SCALAR);
        let prevout = test_support::funded_prevout(hash160, 10_000_000);
        let destination = test_destination();
        let claim = build_signed_claim(
            &key,
            &[prevout],
            &destination,
            policy::DEFAULT_FEE_RATE_SAT_VB,
        )
        .unwrap();

        let key_debug = format!("{key:?}");
        let claim_debug = format!("{claim:?}");
        let summary_json = serde_json::to_string(claim.summary()).unwrap();

        assert_eq!(key_debug, "ClaimKey(<redacted>)");
        assert_eq!(claim_debug, "SignedClaim(<redacted>)");

        let pubkey_hex = hex_encode(&key.compressed_pubkey_bytes());
        let raw_hex = hex_encode(claim.raw_tx_bytes_for_submission());
        let private_key_hex_64 = format!("{TEST_SCALAR:064x}");
        let private_key_hex_18 = format!("{TEST_SCALAR:018x}");
        for haystack in [&key_debug, &claim_debug, &summary_json] {
            assert!(
                !haystack.contains(&pubkey_hex),
                "leaked pubkey hex in: {haystack}"
            );
            assert!(!haystack.contains(&raw_hex), "leaked tx hex in: {haystack}");
            assert!(
                !haystack.contains(&private_key_hex_64),
                "leaked 64-hex-digit private key in: {haystack}"
            );
            assert!(
                !haystack.contains(&private_key_hex_18),
                "leaked 18-hex-digit (FOUND_KEY.txt-style) private key in: {haystack}"
            );
        }
    }

    fn hex_encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}
