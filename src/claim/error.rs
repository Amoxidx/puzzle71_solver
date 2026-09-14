//! Error type for the offline claim pipeline (`src/claim/`).
//!
//! No variant may ever carry key material, a public key, a signature, or transaction hex —
//! only a machine-checkable rejection reason. See `phase1-claim-core.md` "Akzeptanzkriterien" 5.

use std::fmt;

/// All rejection reasons produced by `src/claim/`.
///
/// Every variant documents exactly one reason a claim step refused to proceed. One variant
/// (`SighashComputation`) exists because a real `bitcoin` crate API used here is fallible in a
/// way the task specification's pseudocode did not spell out; see the "Einwände" section of the
/// implementation report for the exact API evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimError {
    /// Destination string could not be parsed as any known Bitcoin address format.
    InvalidAddress,
    /// Destination address is syntactically valid but not for the expected network.
    WrongNetwork,
    /// Destination address type is not one of P2PKH/P2SH/P2WPKH/P2WSH/P2TR.
    UnsupportedAddressType,
    /// Destination resolves to the puzzle address itself (self-send would burn the claim).
    DestinationIsPuzzleAddress,
    /// Raw previous-transaction bytes failed to decode as a `Transaction`.
    PrevTxDecode,
    /// Raw claim-transaction bytes failed to decode as a `Transaction` (as opposed to a
    /// previous transaction, see [`ClaimError::PrevTxDecode`]).
    ClaimTxDecode,
    /// The decoded previous transaction's txid does not match the expected outpoint's txid.
    TxidMismatch,
    /// The expected outpoint's `vout` does not exist in the decoded previous transaction.
    VoutOutOfRange,
    /// The previous transaction's output script does not match the expected script.
    ScriptMismatch,
    /// Two or more supplied prevouts reference the same outpoint.
    DuplicateOutpoint,
    /// The derived public-key hash does not match the expected target HASH160.
    KeyDoesNotMatchTarget,
    /// The `FOUND_KEY.txt`-style key file's permissions are not exactly `0o600`.
    KeyFilePermissions,
    /// The key file is missing the key line, has more than one, or is otherwise malformed.
    KeyFileFormat,
    /// The parsed key value lies outside the expected puzzle range.
    KeyOutOfRange,
    /// The requested fee rate lies outside `[MIN_FEE_RATE_SAT_VB, MAX_FEE_RATE_SAT_VB]`.
    FeeRateOutOfBounds,
    /// None of the supplied prevouts are economic to spend at the given fee rate.
    NoEconomicInputs,
    /// The computed (or claimed) output value falls below the destination script's dust
    /// threshold, or the fee alone would consume the entire input value.
    OutputBelowDust,
    /// The transaction does not have exactly one output.
    OutputCount,
    /// The transaction's single output script does not match the destination's script.
    OutputScriptMismatch,
    /// The transaction's input outpoint set does not equal the set of economic prevouts
    /// (missing input, extra input, or a duplicate).
    InputSetMismatch,
    /// An input's `sequence` is not `Sequence::MAX`, or an input carries a non-empty witness
    /// (this claim pipeline only ever produces final, witness-free legacy inputs).
    NonFinalSequence,
    /// The transaction's `lock_time` is not zero.
    NonZeroLocktime,
    /// The fee implied by inputs minus output does not equal the worst-case-size fee for the
    /// given fee rate, the transaction's actual size exceeds that worst case, its computation
    /// would overflow, or would underflow (output value exceeds total input value).
    FeeMismatch,
    /// `bitcoinconsensus` script verification (VERIFY_ALL) failed for at least one input.
    ScriptVerification,
    /// Re-serializing the decoded transaction did not reproduce the exact input bytes.
    SerializationMismatch,
    /// Computing a legacy sighash for a given input index failed. In this pipeline this can
    /// only happen if the real `bitcoin` crate API is misused; see "Einwände" in the report.
    SighashComputation,
}

impl fmt::Display for ClaimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            ClaimError::InvalidAddress => "destination address could not be parsed",
            ClaimError::WrongNetwork => "destination address is valid for a different network",
            ClaimError::UnsupportedAddressType => "destination address type is not supported",
            ClaimError::DestinationIsPuzzleAddress => {
                "destination equals the puzzle address itself"
            }
            ClaimError::PrevTxDecode => "raw previous transaction failed to decode",
            ClaimError::ClaimTxDecode => "raw claim transaction failed to decode",
            ClaimError::TxidMismatch => {
                "previous transaction txid does not match the expected outpoint"
            }
            ClaimError::VoutOutOfRange => "expected vout does not exist in previous transaction",
            ClaimError::ScriptMismatch => {
                "previous transaction output script does not match expectation"
            }
            ClaimError::DuplicateOutpoint => "duplicate outpoint among prevouts",
            ClaimError::KeyDoesNotMatchTarget => "derived key does not match the expected target",
            ClaimError::KeyFilePermissions => "key file permissions are not 0600",
            ClaimError::KeyFileFormat => "key file is malformed",
            ClaimError::KeyOutOfRange => "key value lies outside the expected range",
            ClaimError::FeeRateOutOfBounds => "fee rate is outside the allowed bounds",
            ClaimError::NoEconomicInputs => "no prevout is economic to spend at this fee rate",
            ClaimError::OutputBelowDust => "output value is below the dust threshold",
            ClaimError::OutputCount => "transaction does not have exactly one output",
            ClaimError::OutputScriptMismatch => "output script does not match destination",
            ClaimError::InputSetMismatch => "input outpoint set does not match economic prevouts",
            ClaimError::NonFinalSequence => "an input is not a final, witness-free legacy input",
            ClaimError::NonZeroLocktime => "lock_time is not zero",
            ClaimError::FeeMismatch => "fee does not match the expected worst-case fee",
            ClaimError::ScriptVerification => "consensus script verification failed",
            ClaimError::SerializationMismatch => "re-serialization did not match input bytes",
            ClaimError::SighashComputation => "legacy sighash computation failed",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for ClaimError {}
