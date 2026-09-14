//! Claim pipeline for Puzzle #71: offline signing core plus the networked prepare/confirm flow.
//!
//! The offline core (`builder`, `verify`, `prevout`, `key`, `destination`, `policy`) builds a
//! single, fully signed, independently re-verified P2PKH-input transaction and never contacts
//! the network. `net`, `code`, and `service` add dual-source UTXO fetch, a Telegram one-time
//! code, and Slipstream-only submission. The dashboard web API and claim panel sit on top.

pub mod builder;
pub mod code;
pub mod destination;
pub mod error;
pub mod key;
mod memory;
pub mod net;
pub mod policy;
pub mod prevout;
pub mod service;
pub mod verify;

#[cfg(test)]
pub(crate) mod test_support;

pub use builder::{SignedClaim, build_signed_claim};
pub use code::{ClaimCode, CodeError};
pub use destination::parse_destination;
pub use error::ClaimError;
pub use key::ClaimKey;
pub use net::{
    ClaimFetchError, CurlTransport, EsploraUtxoSource, HttpResponse, Method, NetError, Notifier,
    SlipstreamSubmitter, SubmitError, SubmitReceipt, Submitter, TelegramNotifier, Transport,
    TxStatus, UtxoSnapshot, UtxoSource, is_allowed,
};
pub use prevout::{VerifiedPrevout, p2pkh_script_for_hash160, verify_prevout};
pub use service::{
    ClaimOps, ClaimService, ClaimState, FoundKeyFile, KeySource, MAX_ALERT_SENDS,
    MAX_FAILED_CODE_ATTEMPTS, MIN_EXPECTED_ECONOMIC_TOTAL_SAT, ServiceError,
    find_verified_found_key,
};
pub use verify::{ClaimSummary, verify_signed_claim};
