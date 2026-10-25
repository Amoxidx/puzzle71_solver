//! Fee and size policy for the offline claim transaction.
//!
//! Every claim transaction is a single-output, legacy-P2PKH-input, witness-free, version-2
//! transaction with `lock_time = 0`. All size math here is a worst-case (upper bound), never an
//! average, because the built fee must always be sufficient regardless of the exact DER
//! signature length produced for a given input.

use bitcoin::Script;
use bitcoin::hashes::Hash;

use crate::claim::error::ClaimError;
use crate::claim::prevout::VerifiedPrevout;

/// Absolute block-weight ceiling, not a public-mempool standardness policy.
pub const MAX_CLAIM_WEIGHT_WU: u64 = 4_000_000;

/// Default fee rate used unless the caller overrides it. Deliberately the same as
/// [`MIN_FEE_RATE_SAT_VB`]: a puzzle claim is a one-shot race against Kangaroo-style discrete-log
/// attackers watching for the public key to appear, not an ordinary fee-market transaction, so
/// the default is the aggressive floor rather than a "normal" market rate.
pub const DEFAULT_FEE_RATE_SAT_VB: u64 = 2_000;

/// Minimum fee rate this pipeline will build or accept, in sat/vB.
pub const MIN_FEE_RATE_SAT_VB: u64 = 2_000;

/// Maximum fee rate this pipeline will build or accept, in sat/vB — a sanity ceiling against a
/// fat-fingered fee-rate input burning the claim.
pub const MAX_FEE_RATE_SAT_VB: u64 = 20_000;

/// Worst-case virtual size, in bytes, of a single legacy P2PKH input:
/// outpoint (36) + scriptSig-length varint (1) + scriptSig (<=107) + sequence (4) = 148.
///
/// ScriptSig = push-opcode (1) + DER signature with low-R (<=71) + sighash-type byte (1)
///           + push-opcode (1) + compressed pubkey (33) = <=107.
///
/// With both low-R and low-S (`sign_ecdsa_low_r` only forces low-R), the DER signature itself is
/// actually at most 70 bytes, making the true worst-case scriptSig 106 bytes and the true
/// worst-case input 147 bytes. 148 is deliberately one byte more generous than that true worst
/// case — a fixed, easy-to-audit upper bound rather than a value tied to the low-S detail — and
/// the constant stays 148.
pub const P2PKH_INPUT_MAX_VSIZE: u64 = 148;

/// Number of bytes needed to encode `n` as a Bitcoin CompactSize (P2P varint).
fn compact_size_len(n: u64) -> u64 {
    match n {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

/// Worst-case, witness-free virtual size for a claim transaction spending `input_count` legacy
/// P2PKH inputs into a single output paying `destination_script`.
///
/// Fixed part: version (4) + input-count varint + output-count varint (always 1, one output) +
/// locktime (4). Plus `input_count` legacy P2PKH inputs at [`P2PKH_INPUT_MAX_VSIZE`] each, plus
/// one output: value (8) + scriptPubkey-length varint + scriptPubkey bytes.
pub fn max_vsize(input_count: u64, destination_script: &Script) -> u64 {
    let base = 4 + compact_size_len(input_count) + 1 + 4;
    let inputs = input_count.saturating_mul(P2PKH_INPUT_MAX_VSIZE);
    let script_len = destination_script.len() as u64;
    let output = 8 + compact_size_len(script_len) + script_len;
    base.saturating_add(inputs).saturating_add(output)
}

/// Whether spending an output worth `value_sat` as a single legacy P2PKH input is economic at
/// `fee_rate` sat/vB: its worst-case marginal cost must be strictly less than its own value,
/// otherwise including it would spend more on fee than it is worth.
pub fn is_economic(value_sat: u64, fee_rate: u64) -> bool {
    value_sat > P2PKH_INPUT_MAX_VSIZE * fee_rate
}

/// Selects the subset with the highest payout at the exact aggregate fee. For a fixed
/// input count, the largest values maximize payout; evaluating every such prefix also
/// accounts for CompactSize jumps and groups which jointly pay that overhead.
pub(crate) fn select_prevouts<'a>(
    prevouts: &'a [VerifiedPrevout],
    destination_script: &Script,
    fee_rate: u64,
) -> Result<Vec<&'a VerifiedPrevout>, ClaimError> {
    let mut candidates: Vec<_> = prevouts
        .iter()
        .filter(|p| is_economic(p.txout().value.to_sat(), fee_rate))
        .collect();
    if candidates.is_empty() {
        return Err(ClaimError::NoEconomicInputs);
    }
    candidates.sort_by_key(|p| {
        (
            std::cmp::Reverse(p.txout().value.to_sat()),
            p.outpoint().txid.to_byte_array(),
            p.outpoint().vout,
        )
    });
    let mut total = 0u64;
    let mut best_payout = None;
    let mut best_count = 0;
    for (index, prevout) in candidates.iter().enumerate() {
        total = total
            .checked_add(prevout.txout().value.to_sat())
            .ok_or(ClaimError::FeeMismatch)?;
        let fee = max_vsize((index + 1) as u64, destination_script)
            .checked_mul(fee_rate)
            .ok_or(ClaimError::FeeMismatch)?;
        if let Some(payout) = total.checked_sub(fee)
            && best_payout.is_none_or(|best| payout > best)
        {
            best_payout = Some(payout);
            best_count = index + 1;
        }
    }
    if best_count == 0 {
        return Err(ClaimError::OutputBelowDust);
    }
    candidates.truncate(best_count);
    Ok(candidates)
}

pub(crate) fn check_max_weight(input_count: u64, script: &Script) -> Result<(), ClaimError> {
    if max_vsize(input_count, script).saturating_mul(4) > MAX_CLAIM_WEIGHT_WU {
        return Err(ClaimError::TransactionTooLarge);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claim::prevout::p2pkh_script_for_hash160;

    fn p2pkh_25_byte_script() -> bitcoin::ScriptBuf {
        p2pkh_script_for_hash160([0xAA; 20])
    }

    #[test]
    fn max_vsize_matches_hand_computation_for_one_p2pkh_input() {
        let script = p2pkh_25_byte_script();
        assert_eq!(script.len(), 25);
        // base 10 + 1*148 + (8 + 1 + 25) = 10 + 148 + 34 = 192
        assert_eq!(max_vsize(1, &script), 192);
    }

    #[test]
    fn max_vsize_scales_linearly_in_input_count_below_the_varint_boundary() {
        let script = p2pkh_25_byte_script();
        let one = max_vsize(1, &script);
        let two = max_vsize(2, &script);
        assert_eq!(two - one, P2PKH_INPUT_MAX_VSIZE);
    }

    #[test]
    fn max_vsize_grows_the_input_count_varint_at_253_inputs() {
        let script = p2pkh_25_byte_script();
        let at_252 = max_vsize(252, &script);
        let at_253 = max_vsize(253, &script);
        // Crossing 252 -> 253 switches the input-count CompactSize from 1 to 3 bytes, on top of
        // the usual per-input cost.
        assert_eq!(at_253 - at_252, P2PKH_INPUT_MAX_VSIZE + 2);
    }

    #[test]
    fn is_economic_is_false_exactly_at_the_break_even_point() {
        let fee_rate = 2_000u64;
        let break_even = P2PKH_INPUT_MAX_VSIZE * fee_rate;
        assert!(!is_economic(break_even, fee_rate));
        assert!(is_economic(break_even + 1, fee_rate));
        assert!(!is_economic(break_even - 1, fee_rate));
    }

    #[test]
    fn wallet_absolute_weight_ceiling_uses_four_million_weight_units() {
        let script = p2pkh_25_byte_script();
        assert!(check_max_weight(6756, &script).is_ok());
        assert_eq!(
            check_max_weight(6757, &script),
            Err(ClaimError::TransactionTooLarge)
        );
        assert_eq!(MAX_CLAIM_WEIGHT_WU, 4_000_000);
        // A private miner path is not constrained to public-mempool standardness here.
        assert!(check_max_weight(1000, &script).is_ok());
    }
}
