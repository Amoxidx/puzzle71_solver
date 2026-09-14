//! Independent verification of claimed previous outputs.
//!
//! The amount used everywhere downstream (fee computation, output computation, dust checks)
//! comes exclusively from here — from the deserialized raw previous transaction — never from an
//! external API. Legacy (P2PKH) sighashes do not commit to input amounts, so a wrong amount
//! from an untrusted source would silently be donated to the miner as fee without the
//! signature becoming invalid (see `phase1-claim-core.md` "Beleg").

use bitcoin::consensus;
use bitcoin::hashes::Hash;
use bitcoin::{OutPoint, PubkeyHash, Script, ScriptBuf, Transaction, TxOut};

use crate::claim::error::ClaimError;

/// A previous output whose amount and script have been checked against the raw previous
/// transaction bytes and an expected outpoint/script.
///
/// Only constructible via [`verify_prevout`] — the private `_sealed` field prevents struct-
/// literal construction from outside this function, while `outpoint` and `txout` stay `pub`
/// for direct read access.
#[derive(Debug, Clone)]
pub struct VerifiedPrevout {
    pub outpoint: OutPoint,
    pub txout: TxOut,
    _sealed: (),
}

/// Deserializes `raw_prev_tx` (legacy or segwit encoding — `consensus::deserialize` handles
/// both transparently), checks that it really is the funding transaction for `expected` by
/// recomputing its txid, that `expected.vout` exists, and that the output there has exactly
/// `expected_script`. The returned amount comes exclusively from `txout.value` of the
/// deserialized transaction, never from a caller-supplied value.
pub fn verify_prevout(
    expected: OutPoint,
    raw_prev_tx: &[u8],
    expected_script: &Script,
) -> Result<VerifiedPrevout, ClaimError> {
    let tx: Transaction =
        consensus::deserialize(raw_prev_tx).map_err(|_| ClaimError::PrevTxDecode)?;

    if tx.compute_txid() != expected.txid {
        return Err(ClaimError::TxidMismatch);
    }

    let txout = tx
        .output
        .get(expected.vout as usize)
        .ok_or(ClaimError::VoutOutOfRange)?;

    if txout.script_pubkey.as_script() != expected_script {
        return Err(ClaimError::ScriptMismatch);
    }

    Ok(VerifiedPrevout {
        outpoint: expected,
        txout: txout.clone(),
        _sealed: (),
    })
}

/// The standard P2PKH scriptPubkey for a given HASH160:
/// `OP_DUP OP_HASH160 <hash160> OP_EQUALVERIFY OP_CHECKSIG`.
pub fn p2pkh_script_for_hash160(hash160: [u8; 20]) -> ScriptBuf {
    ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array(hash160))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{Amount, Sequence, TxIn, Txid, Witness, absolute, transaction};

    fn test_script() -> ScriptBuf {
        p2pkh_script_for_hash160([0x11; 20])
    }

    /// Builds a funding transaction paying `outputs`. When `segwit` is true, the (otherwise
    /// irrelevant) single input carries a dummy witness element so the transaction is
    /// serialized in the BIP-144 segwit wire format, mirroring the real biggest-UTXO funding
    /// transaction the task's "Beleg" section notes is itself segwit.
    fn funding_tx(outputs: Vec<TxOut>, segwit: bool) -> Transaction {
        let mut witness = Witness::default();
        if segwit {
            witness.push([0u8]);
        }
        Transaction {
            version: transaction::Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness,
            }],
            output: outputs,
        }
    }

    #[test]
    fn decodes_segwit_prevout_and_returns_its_onchain_amount() {
        let tx = funding_tx(
            vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: test_script(),
            }],
            true,
        );
        let raw = consensus::serialize(&tx);
        // Confirm the fixture really is BIP-144 segwit-encoded (marker 0x00, flag 0x01 right
        // after the 4-byte version field), not merely constructed with a witness in memory.
        assert_eq!(
            &raw[4..6],
            &[0x00, 0x01],
            "test setup: fixture must be segwit-encoded"
        );
        let expected = OutPoint {
            txid: tx.compute_txid(),
            vout: 0,
        };

        let verified = verify_prevout(expected, &raw, &test_script()).unwrap();
        assert_eq!(verified.outpoint, expected);
        assert_eq!(verified.txout.value, Amount::from_sat(100_000));
    }

    #[test]
    fn rejects_when_the_output_amount_was_tampered() {
        let tx = funding_tx(
            vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: test_script(),
            }],
            false,
        );
        let expected = OutPoint {
            txid: tx.compute_txid(),
            vout: 0,
        };

        // Changing 100_000 -> 100_001 flips exactly the low byte of the little-endian 8-byte
        // amount field (0x000186A0 -> 0x000186A1); every other serialized byte is unchanged.
        let mut tampered = tx.clone();
        tampered.output[0].value = Amount::from_sat(100_001);
        let raw_tx = consensus::serialize(&tx);
        let raw_tampered = consensus::serialize(&tampered);
        assert_eq!(raw_tx.len(), raw_tampered.len());
        let differing_bytes = raw_tx
            .iter()
            .zip(raw_tampered.iter())
            .filter(|(a, b)| a != b)
            .count();
        assert_eq!(
            differing_bytes, 1,
            "test setup: tamper must change exactly one byte"
        );

        let err = verify_prevout(expected, &raw_tampered, &test_script()).unwrap_err();
        assert_eq!(err, ClaimError::TxidMismatch);
    }

    #[test]
    fn rejects_vout_out_of_range() {
        let tx = funding_tx(
            vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: test_script(),
            }],
            false,
        );
        let raw = consensus::serialize(&tx);
        let expected = OutPoint {
            txid: tx.compute_txid(),
            vout: 5,
        };
        let err = verify_prevout(expected, &raw, &test_script()).unwrap_err();
        assert_eq!(err, ClaimError::VoutOutOfRange);
    }

    #[test]
    fn rejects_a_foreign_script() {
        let tx = funding_tx(
            vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: test_script(),
            }],
            false,
        );
        let raw = consensus::serialize(&tx);
        let expected = OutPoint {
            txid: tx.compute_txid(),
            vout: 0,
        };
        let foreign = p2pkh_script_for_hash160([0x22; 20]);
        let err = verify_prevout(expected, &raw, &foreign).unwrap_err();
        assert_eq!(err, ClaimError::ScriptMismatch);
    }

    #[test]
    fn rejects_undecodable_bytes() {
        let expected = OutPoint {
            txid: Txid::from_byte_array([0u8; 32]),
            vout: 0,
        };
        let err = verify_prevout(expected, &[0xff, 0x00], &test_script()).unwrap_err();
        assert_eq!(err, ClaimError::PrevTxDecode);
    }
}
