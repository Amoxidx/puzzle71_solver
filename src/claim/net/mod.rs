//! Networked claim steps: dual-source UTXOs, Slipstream submit, Telegram alert.
//!
//! Every request goes through [`Transport`] after [`allowlist::is_allowed`]. The only
//! transaction-broadcast URL on the allowlist is `POST https://slipstream.mara.com/api/transactions`.

pub mod allowlist;
pub mod error;
pub mod esplora;
pub mod http;
pub mod slipstream;
pub mod telegram;

pub use allowlist::{Method, is_allowed};
pub use error::NetError;
pub use esplora::{ClaimFetchError, EsploraUtxoSource, UtxoSnapshot, UtxoSource};
pub use http::{CurlTransport, HttpResponse, Transport};
pub use slipstream::{SlipstreamSubmitter, SubmitError, SubmitReceipt, Submitter, TxStatus};
pub use telegram::{Notifier, TelegramNotifier};
