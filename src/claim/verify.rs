//! Independent, from-scratch verification of a signed claim transaction.
//!
//! Deliberately does not reuse any intermediate value computed by [`crate::claim::builder`]: it
//! re-decodes the raw bytes, re-derives which prevouts are economic, recomputes the fee purely
//! from the (already independently verified) prevouts, and re-runs full consensus script
//! verification via `bitcoinconsensus`. [`crate::claim::builder::build_signed_claim`] calls this
//! function itself before ever returning a transaction to the caller.

use std::collections::{BTreeSet, HashMap};

use bitcoin::consensus;
use bitcoin::{Address, Script, Sequence, Transaction, TxOut, Txid, absolute};
use serde::Serialize;

use crate::claim::error::ClaimError;
use crate::claim::policy::{self, MAX_FEE_RATE_SAT_VB, MIN_FEE_RATE_SAT_VB};
use crate::claim::prevout::VerifiedPrevout;

/// Non-secret summary of a built (or re-verified) claim transaction. Never contains key,
/// public key, signature, or transaction-hex material.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ClaimSummary {
    pub network: String,
    pub destination: String,
    pub input_count: usize,
    pub total_input_sat: u64,
    pub output_sat: u64,
    pub fee_sat: u64,
    pub vsize: u64,
    pub effective_fee_rate_sat_vb: f64,
    pub txid: String,
    pub excluded_dust_count: usize,
    pub excluded_dust_sat: u64,
}

/// Reports the coarsest network classification determinable from `address` alone
/// ("bitcoin" or "test"). Bitcoin's legacy (P2PKH/P2SH) address encoding uses the identical
/// version byte for testnet, testnet4, signet, and regtest — see the `is_valid_for_network` doc
/// comment in bitcoin-0.32.11/src/address/mod.rs:699-701, which states this explicitly and is
/// exactly why `Address<NetworkUnchecked>::is_valid_for_network` (the only network-membership
/// check this crate exposes on legacy addresses) cannot tell them apart either. Reporting a more
/// specific network label than that would be actively misleading for a legacy destination.
fn network_label(address: &Address) -> String {
    let unchecked = address.clone().into_unchecked();
    if unchecked.is_valid_for_network(bitcoin::Network::Bitcoin) {
        "bitcoin".to_string()
    } else {
        "test".to_string()
    }
}

/// Recomputes and checks the fee for a claim transaction spending `input_count` legacy P2PKH
/// inputs into `destination_script`, independent of any value the builder computed.
///
/// The claim pipeline always builds the fee as exactly
/// `policy::max_vsize(input_count, destination_script) * fee_rate` — the worst-case size times
/// the requested rate, never a smaller "actual size"-based fee, since the real DER signature
/// length (and hence the real transaction size) is only known after signing. Requiring the fee
/// to equal that worst-case value exactly, plus requiring the transaction's *actual* vsize to
/// never exceed that same worst case, together guarantee the effective fee rate is always at
/// least `fee_rate` — never less, only ever higher by however many bytes the real signatures
/// happened to come in shorter than the worst case.
fn check_fee(
    fee_sat: u64,
    fee_rate: u64,
    input_count: u64,
    destination_script: &Script,
    actual_vsize: u64,
) -> Result<(), ClaimError> {
    let worst_case_vsize = policy::max_vsize(input_count, destination_script);
    let expected_fee = worst_case_vsize
        .checked_mul(fee_rate)
        .ok_or(ClaimError::FeeMismatch)?;
    if fee_sat != expected_fee {
        return Err(ClaimError::FeeMismatch);
    }
    if actual_vsize > worst_case_vsize {
        return Err(ClaimError::FeeMismatch);
    }
    Ok(())
}

/// Independently verifies a signed claim transaction's raw bytes against `prevouts`,
/// `destination`, and `fee_rate_sat_vb`, and returns its [`ClaimSummary`] if valid.
pub fn verify_signed_claim(
    raw: &[u8],
    prevouts: &[VerifiedPrevout],
    destination: &Address,
    fee_rate_sat_vb: u64,
) -> Result<ClaimSummary, ClaimError> {
    if !(MIN_FEE_RATE_SAT_VB..=MAX_FEE_RATE_SAT_VB).contains(&fee_rate_sat_vb) {
        return Err(ClaimError::FeeRateOutOfBounds);
    }

    // Independent of the builder: reject a duplicate outpoint among the supplied prevouts before
    // trusting any of them, rather than relying on the builder to have already checked this.
    let mut seen_prevout_outpoints: BTreeSet<(Txid, u32)> = BTreeSet::new();
    for prevout in prevouts {
        if !seen_prevout_outpoints.insert((prevout.outpoint.txid, prevout.outpoint.vout)) {
            return Err(ClaimError::DuplicateOutpoint);
        }
    }

    let tx: Transaction = consensus::deserialize(raw).map_err(|_| ClaimError::ClaimTxDecode)?;
    if consensus::serialize(&tx) != raw {
        return Err(ClaimError::SerializationMismatch);
    }

    if tx.output.len() != 1 {
        return Err(ClaimError::OutputCount);
    }
    let output = &tx.output[0];
    if output.script_pubkey.as_script() != destination.script_pubkey().as_script() {
        return Err(ClaimError::OutputScriptMismatch);
    }

    // Independent of `destination`: refuse to treat this as a valid claim if its output pays
    // back to any of the prevouts' own scripts (the puzzle address itself) — even if some future
    // caller constructed `destination` in a way that already equals it, so this check does not
    // rely on `destination` alone having been validated correctly upstream.
    for prevout in prevouts {
        if output.script_pubkey.as_script() == prevout.txout.script_pubkey.as_script() {
            return Err(ClaimError::DestinationIsPuzzleAddress);
        }
    }

    if tx.lock_time != absolute::LockTime::ZERO {
        return Err(ClaimError::NonZeroLocktime);
    }

    // The prevouts this transaction is allowed to spend: exactly those independently verified
    // prevouts that are economic at `fee_rate_sat_vb`, recomputed here from scratch rather than
    // trusted from the builder.
    let mut economic_outpoints: BTreeSet<(Txid, u32)> = BTreeSet::new();
    let mut excluded_dust_count = 0usize;
    let mut excluded_dust_sat = 0u64;
    for prevout in prevouts {
        let value = prevout.txout.value.to_sat();
        if policy::is_economic(value, fee_rate_sat_vb) {
            economic_outpoints.insert((prevout.outpoint.txid, prevout.outpoint.vout));
        } else {
            excluded_dust_count += 1;
            excluded_dust_sat += value;
        }
    }
    if economic_outpoints.is_empty() {
        return Err(ClaimError::NoEconomicInputs);
    }

    let mut seen: BTreeSet<(Txid, u32)> = BTreeSet::new();
    for input in &tx.input {
        if input.sequence != Sequence::MAX || !input.witness.is_empty() {
            // This pipeline only ever produces final (Sequence::MAX), witness-free legacy
            // inputs; either condition failing means the input isn't one of ours.
            return Err(ClaimError::NonFinalSequence);
        }
        let key = (input.previous_output.txid, input.previous_output.vout);
        if !seen.insert(key) {
            return Err(ClaimError::InputSetMismatch);
        }
    }
    if seen != economic_outpoints {
        return Err(ClaimError::InputSetMismatch);
    }

    let prevout_by_outpoint: HashMap<(Txid, u32), &TxOut> = prevouts
        .iter()
        .map(|p| ((p.outpoint.txid, p.outpoint.vout), &p.txout))
        .collect();

    let total_input_sat: u64 = tx
        .input
        .iter()
        .map(|input| {
            prevout_by_outpoint
                .get(&(input.previous_output.txid, input.previous_output.vout))
                .map(|txout| txout.value.to_sat())
                .unwrap_or(0)
        })
        .sum();

    let output_sat = output.value.to_sat();
    let fee_sat = total_input_sat
        .checked_sub(output_sat)
        .ok_or(ClaimError::FeeMismatch)?;

    let actual_vsize = tx.vsize() as u64;
    let input_count = tx.input.len() as u64;
    check_fee(
        fee_sat,
        fee_rate_sat_vb,
        input_count,
        destination.script_pubkey().as_script(),
        actual_vsize,
    )?;

    if output_sat < destination.script_pubkey().minimal_non_dust().to_sat() {
        return Err(ClaimError::OutputBelowDust);
    }

    tx.verify(|outpoint| {
        prevout_by_outpoint
            .get(&(outpoint.txid, outpoint.vout))
            .map(|txout| (*txout).clone())
    })
    .map_err(|_| ClaimError::ScriptVerification)?;

    let effective_fee_rate_sat_vb = fee_sat as f64 / actual_vsize as f64;

    Ok(ClaimSummary {
        network: network_label(destination),
        destination: destination.to_string(),
        input_count: tx.input.len(),
        total_input_sat,
        output_sat,
        fee_sat,
        vsize: actual_vsize,
        effective_fee_rate_sat_vb,
        txid: tx.compute_txid().to_string(),
        excluded_dust_count,
        excluded_dust_sat,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claim::builder::build_signed_claim;
    use crate::claim::prevout::p2pkh_script_for_hash160;
    use crate::claim::test_support::{self, TEST_SCALAR};
    use bitcoin::hashes::Hash as _;
    use bitcoin::{Amount, OutPoint, PubkeyHash, ScriptBuf, TxIn, Witness, transaction};

    fn test_destination() -> Address {
        Address::p2pkh(
            PubkeyHash::from_byte_array([0x55; 20]),
            bitcoin::NetworkKind::Main,
        )
    }

    /// Builds one genuinely valid, real claim with a single economic prevout, then
    /// deserializes it back into an owned `Transaction` a mutation test can tamper with before
    /// re-serializing and calling `verify_signed_claim` again directly.
    fn valid_claim_fixture() -> (Transaction, Vec<VerifiedPrevout>, Address, u64) {
        let key = test_support::test_claim_key();
        let hash160 = test_support::derive_hash160(TEST_SCALAR);
        let prevout = test_support::funded_prevout(hash160, 10_000_000);
        let destination = test_destination();
        let fee_rate = policy::DEFAULT_FEE_RATE_SAT_VB;
        let claim = build_signed_claim(&key, &[prevout.clone()], &destination, fee_rate).unwrap();
        let tx: Transaction = consensus::deserialize(claim.raw_tx_bytes_for_submission()).unwrap();
        (tx, vec![prevout], destination, fee_rate)
    }

    /// Same as [`valid_claim_fixture`] but with two economic prevouts, for mutations that need
    /// a removable second input.
    fn valid_claim_fixture_two_inputs() -> (Transaction, Vec<VerifiedPrevout>, Address, u64) {
        let key = test_support::test_claim_key();
        let hash160 = test_support::derive_hash160(TEST_SCALAR);
        let prevout_a = test_support::funded_prevout(hash160, 10_000_000);
        let prevout_b = test_support::funded_prevout(hash160, 20_000_000);
        let destination = test_destination();
        let fee_rate = policy::DEFAULT_FEE_RATE_SAT_VB;
        let claim = build_signed_claim(
            &key,
            &[prevout_a.clone(), prevout_b.clone()],
            &destination,
            fee_rate,
        )
        .unwrap();
        let tx: Transaction = consensus::deserialize(claim.raw_tx_bytes_for_submission()).unwrap();
        (tx, vec![prevout_a, prevout_b], destination, fee_rate)
    }

    #[test]
    fn accepts_a_genuinely_valid_claim() {
        let (tx, prevouts, destination, fee_rate) = valid_claim_fixture();
        let raw = consensus::serialize(&tx);
        let summary = verify_signed_claim(&raw, &prevouts, &destination, fee_rate).unwrap();
        assert_eq!(summary.input_count, 1);
        assert_eq!(summary.txid, tx.compute_txid().to_string());
        assert_eq!(summary.excluded_dust_count, 0);
    }

    #[test]
    fn rejects_an_extra_output() {
        let (mut tx, prevouts, destination, fee_rate) = valid_claim_fixture();
        tx.output.push(tx.output[0].clone());
        let raw = consensus::serialize(&tx);
        let err = verify_signed_claim(&raw, &prevouts, &destination, fee_rate).unwrap_err();
        assert_eq!(err, ClaimError::OutputCount);
    }

    #[test]
    fn rejects_a_different_output_script() {
        let (mut tx, prevouts, destination, fee_rate) = valid_claim_fixture();
        tx.output[0].script_pubkey = p2pkh_script_for_hash160([0x66; 20]);
        let raw = consensus::serialize(&tx);
        let err = verify_signed_claim(&raw, &prevouts, &destination, fee_rate).unwrap_err();
        assert_eq!(err, ClaimError::OutputScriptMismatch);
    }

    #[test]
    fn rejects_duplicate_prevouts_independent_of_the_builder() {
        let (tx, prevouts, destination, fee_rate) = valid_claim_fixture();
        let raw = consensus::serialize(&tx);
        let duplicated = vec![prevouts[0].clone(), prevouts[0].clone()];
        let err = verify_signed_claim(&raw, &duplicated, &destination, fee_rate).unwrap_err();
        assert_eq!(err, ClaimError::DuplicateOutpoint);
    }

    #[test]
    fn rejects_an_extra_input_with_an_outpoint_absent_from_prevouts() {
        let (mut tx, prevouts, destination, fee_rate) = valid_claim_fixture();
        let foreign_outpoint = OutPoint {
            txid: Txid::from_byte_array([0x77; 32]),
            vout: 0,
        };
        tx.input.push(TxIn {
            previous_output: foreign_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        });
        let raw = consensus::serialize(&tx);
        let err = verify_signed_claim(&raw, &prevouts, &destination, fee_rate).unwrap_err();
        assert_eq!(err, ClaimError::InputSetMismatch);
    }

    /// Targets the confirmed mutation-survival gap: replacing `seen != economic_outpoints` with
    /// `!economic_outpoints.is_subset(&seen)` would let a transaction spend an extra input beyond
    /// the economic prevout set, as long as every economic prevout is still present. This test
    /// appends an extra input whose outpoint is a *listed* dust prevout (so it can't be caught by
    /// the "absent from prevouts" test above) and must still be rejected.
    #[test]
    fn rejects_an_extra_input_whose_outpoint_is_a_listed_dust_prevout() {
        let key = test_support::test_claim_key();
        let hash160 = test_support::derive_hash160(TEST_SCALAR);
        let fee_rate = policy::DEFAULT_FEE_RATE_SAT_VB;
        let dust_value = policy::P2PKH_INPUT_MAX_VSIZE * fee_rate; // break-even: excluded as dust
        let economic_prevout = test_support::funded_prevout(hash160, dust_value + 1_000_000);
        let dust_prevout = test_support::funded_prevout(hash160, dust_value);
        let destination = test_destination();
        let claim = build_signed_claim(
            &key,
            &[economic_prevout.clone(), dust_prevout.clone()],
            &destination,
            fee_rate,
        )
        .unwrap();
        let mut tx: Transaction =
            consensus::deserialize(claim.raw_tx_bytes_for_submission()).unwrap();
        assert_eq!(
            tx.input.len(),
            1,
            "test setup: only the economic prevout must be spent"
        );
        tx.input.push(TxIn {
            previous_output: dust_prevout.outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        });
        let raw = consensus::serialize(&tx);
        let prevouts = vec![economic_prevout, dust_prevout];
        let err = verify_signed_claim(&raw, &prevouts, &destination, fee_rate).unwrap_err();
        assert_eq!(err, ClaimError::InputSetMismatch);
    }

    #[test]
    fn rejects_a_transaction_whose_output_pays_a_prevout_script_even_when_destination_matches() {
        // Deliberately does not go through `build_signed_claim` (which has its own, separate
        // `DestinationIsPuzzleAddress` guard) — this proves `verify_signed_claim` catches a
        // claim-to-the-puzzle-address hand-built by some other, future caller, not just a
        // manipulated builder output.
        let hash160 = test_support::derive_hash160(TEST_SCALAR);
        let prevout = test_support::funded_prevout(hash160, 10_000_000);
        let puzzle_destination = Address::p2pkh(
            PubkeyHash::from_byte_array(hash160),
            bitcoin::NetworkKind::Main,
        );
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: prevout.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: puzzle_destination.script_pubkey(),
            }],
        };
        let raw = consensus::serialize(&tx);
        let err = verify_signed_claim(
            &raw,
            &[prevout],
            &puzzle_destination,
            policy::DEFAULT_FEE_RATE_SAT_VB,
        )
        .unwrap_err();
        assert_eq!(err, ClaimError::DestinationIsPuzzleAddress);
    }

    #[test]
    fn rejects_fee_one_sat_above_expected() {
        let (mut tx, prevouts, destination, fee_rate) = valid_claim_fixture();
        let input_count = tx.input.len() as u64;
        let expected_fee =
            policy::max_vsize(input_count, destination.script_pubkey().as_script()) * fee_rate;
        let total_input: u64 = prevouts.iter().map(|p| p.txout.value.to_sat()).sum();
        // Set the output so the implied fee is exactly `expected_fee + 1`, one sat above the
        // single exact value `check_fee` accepts.
        tx.output[0].value = Amount::from_sat(total_input - (expected_fee + 1));
        let raw = consensus::serialize(&tx);
        let err = verify_signed_claim(&raw, &prevouts, &destination, fee_rate).unwrap_err();
        assert_eq!(err, ClaimError::FeeMismatch);
    }

    #[test]
    fn rejects_fee_one_sat_below_expected() {
        let (mut tx, prevouts, destination, fee_rate) = valid_claim_fixture();
        let input_count = tx.input.len() as u64;
        let expected_fee =
            policy::max_vsize(input_count, destination.script_pubkey().as_script()) * fee_rate;
        let total_input: u64 = prevouts.iter().map(|p| p.txout.value.to_sat()).sum();
        // Set the output so the implied fee is exactly `expected_fee - 1`, one sat below the
        // single exact value `check_fee` accepts.
        tx.output[0].value = Amount::from_sat(total_input - (expected_fee - 1));
        let raw = consensus::serialize(&tx);
        let err = verify_signed_claim(&raw, &prevouts, &destination, fee_rate).unwrap_err();
        assert_eq!(err, ClaimError::FeeMismatch);
    }

    #[test]
    fn check_fee_accepts_the_exact_expected_fee_and_rejects_one_sat_either_side() {
        let script = p2pkh_script_for_hash160([0x11; 20]);
        let input_count = 2u64;
        let fee_rate = 2_000u64;
        let vsize = policy::max_vsize(input_count, &script);
        let expected_fee = vsize * fee_rate;

        assert!(check_fee(expected_fee, fee_rate, input_count, &script, vsize).is_ok());
        assert_eq!(
            check_fee(expected_fee + 1, fee_rate, input_count, &script, vsize).unwrap_err(),
            ClaimError::FeeMismatch
        );
        assert_eq!(
            check_fee(expected_fee - 1, fee_rate, input_count, &script, vsize).unwrap_err(),
            ClaimError::FeeMismatch
        );
    }

    /// The scenario that, before F3, would block a claim forever: a real signature comes in
    /// shorter than the 148-byte-per-input worst case (up to 3 bytes shorter per input, per the
    /// fix-round "Beleg"), so `actual_vsize` is below `max_vsize` while the fee, built from
    /// `max_vsize`, stays the same. That must still be accepted.
    #[test]
    fn check_fee_accepts_actual_vsize_up_to_three_bytes_per_input_below_worst_case() {
        let script = p2pkh_script_for_hash160([0x22; 20]);
        let fee_rate = 2_000u64;
        for input_count in [1u64, 3u64] {
            let vsize = policy::max_vsize(input_count, &script);
            let expected_fee = vsize * fee_rate;
            let actual_vsize = vsize - 3 * input_count;
            assert!(
                check_fee(expected_fee, fee_rate, input_count, &script, actual_vsize).is_ok(),
                "input_count={input_count}"
            );
        }
    }

    #[test]
    fn check_fee_rejects_actual_vsize_above_the_worst_case() {
        let script = p2pkh_script_for_hash160([0x33; 20]);
        let input_count = 1u64;
        let fee_rate = 2_000u64;
        let vsize = policy::max_vsize(input_count, &script);
        let expected_fee = vsize * fee_rate;
        let err = check_fee(expected_fee, fee_rate, input_count, &script, vsize + 1).unwrap_err();
        assert_eq!(err, ClaimError::FeeMismatch);
    }

    #[test]
    fn rejects_a_missing_input() {
        let (mut tx, prevouts, destination, fee_rate) = valid_claim_fixture_two_inputs();
        assert_eq!(
            tx.input.len(),
            2,
            "test setup: fixture must have two inputs"
        );
        tx.input.remove(0);
        let raw = consensus::serialize(&tx);
        let err = verify_signed_claim(&raw, &prevouts, &destination, fee_rate).unwrap_err();
        assert_eq!(err, ClaimError::InputSetMismatch);
    }

    #[test]
    fn rejects_a_non_final_sequence() {
        let (mut tx, prevouts, destination, fee_rate) = valid_claim_fixture();
        tx.input[0].sequence = Sequence::ENABLE_RBF_NO_LOCKTIME; // 0xFFFFFFFD
        let raw = consensus::serialize(&tx);
        let err = verify_signed_claim(&raw, &prevouts, &destination, fee_rate).unwrap_err();
        assert_eq!(err, ClaimError::NonFinalSequence);
    }

    #[test]
    fn rejects_an_input_with_a_nonempty_witness() {
        let (mut tx, prevouts, destination, fee_rate) = valid_claim_fixture();
        tx.input[0].witness.push([0u8]);
        let raw = consensus::serialize(&tx);
        let err = verify_signed_claim(&raw, &prevouts, &destination, fee_rate).unwrap_err();
        assert_eq!(err, ClaimError::NonFinalSequence);
    }

    #[test]
    fn rejects_a_nonzero_locktime() {
        let (mut tx, prevouts, destination, fee_rate) = valid_claim_fixture();
        tx.lock_time = absolute::LockTime::from_consensus(1);
        let raw = consensus::serialize(&tx);
        let err = verify_signed_claim(&raw, &prevouts, &destination, fee_rate).unwrap_err();
        assert_eq!(err, ClaimError::NonZeroLocktime);
    }

    #[test]
    fn rejects_a_flipped_signature_byte() {
        let (mut tx, prevouts, destination, fee_rate) = valid_claim_fixture();
        let mut script_sig_bytes = tx.input[0].script_sig.as_bytes().to_vec();
        assert!(
            script_sig_bytes.len() > 20,
            "test setup: scriptSig must be long enough to flip a byte inside the signature"
        );
        script_sig_bytes[10] ^= 0xFF;
        tx.input[0].script_sig = ScriptBuf::from_bytes(script_sig_bytes);
        let raw = consensus::serialize(&tx);
        let err = verify_signed_claim(&raw, &prevouts, &destination, fee_rate).unwrap_err();
        assert_eq!(err, ClaimError::ScriptVerification);
    }

    #[test]
    fn rejects_undecodable_claim_tx_bytes() {
        let (_tx, prevouts, destination, fee_rate) = valid_claim_fixture();
        let err =
            verify_signed_claim(&[0xff, 0x00], &prevouts, &destination, fee_rate).unwrap_err();
        assert_eq!(err, ClaimError::ClaimTxDecode);
    }

    /// Einwand (see implementation report "Einwände"): the fix-round task names this scenario
    /// ("valid claim tx bytes plus one trailing byte") as a `SerializationMismatch` case, but the
    /// real `bitcoin` crate API closes off that path before `SerializationMismatch`'s own check
    /// can ever run. `consensus::deserialize` requires the *entire* input to be consumed
    /// (bitcoin-0.32.11/src/consensus/encode.rs:168-177: `Err(Error::ParseFailed("data not
    /// consumed entirely..."))` otherwise), so this fails at the initial decode step and surfaces
    /// as `ClaimTxDecode`, never reaching a `Transaction` to compare via `SerializationMismatch`.
    #[test]
    fn rejects_valid_claim_tx_bytes_with_a_trailing_extra_byte() {
        let (tx, prevouts, destination, fee_rate) = valid_claim_fixture();
        let mut raw = consensus::serialize(&tx);
        raw.push(0x00);
        let err = verify_signed_claim(&raw, &prevouts, &destination, fee_rate).unwrap_err();
        assert_eq!(err, ClaimError::ClaimTxDecode);
    }
}
