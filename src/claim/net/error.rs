//! Network-layer errors for the claim pipeline.
//!
//! No variant's `Debug` or `Display` output contains a token, URL, transaction hex, or public
//! key — only a machine-checkable reason (and, for [`NetError::Rejected`], a sanitised
//! printable-ASCII message with long hex runs already replaced).

use std::fmt;

/// All rejection and transport-failure reasons produced by `src/claim/net/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetError {
    /// The requested method/URL pair is not on the allowlist.
    NotAllowed,
    /// A caller-supplied value was unusable (control characters, `@`-prefixed body, bad txid).
    InvalidInput,
    /// The transport process could not be started or its pipes could not be opened.
    Spawn,
    /// The transport process exited non-zero. `exit_code` is `None` if the process was killed
    /// by a signal or if writing the request failed before a wait.
    Transport { exit_code: Option<i32> },
    /// The peer responded with an unexpected HTTP status.
    HttpStatus(u16),
    /// The response body was missing, not JSON of the expected shape, or otherwise unusable.
    BadResponse,
    /// The two independent UTXO sources did not report the same confirmed `(txid, vout, value)` set.
    SourcesDisagree,
    /// A confirmed UTXO's API-reported value did not match the value in the raw previous transaction.
    SourceValueMismatch,
    /// Slipstream rejected the submission with a sanitised error message.
    Rejected(String),
    /// Slipstream reported success but named a different transaction than the one submitted.
    SubmitTxidMismatch,
    /// The Telegram configuration file's permissions were not exactly `0o600`.
    ConfigPermissions,
    /// The Telegram configuration file was missing, malformed, or used a forbidden chat id.
    ConfigFormat,
}

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetError::NotAllowed => f.write_str("request is not on the allowlist"),
            NetError::InvalidInput => f.write_str("invalid input"),
            NetError::Spawn => f.write_str("failed to start transport"),
            NetError::Transport { exit_code } => match exit_code {
                Some(code) => write!(f, "transport exited with status {code}"),
                None => f.write_str("transport failed"),
            },
            NetError::HttpStatus(status) => write!(f, "unexpected HTTP status {status}"),
            NetError::BadResponse => f.write_str("unusable HTTP response"),
            NetError::SourcesDisagree => f.write_str("UTXO sources disagree"),
            NetError::SourceValueMismatch => {
                f.write_str("UTXO API value does not match previous transaction")
            }
            NetError::Rejected(_) => f.write_str("submission rejected"),
            NetError::SubmitTxidMismatch => f.write_str("submission txid mismatch"),
            NetError::ConfigPermissions => f.write_str("configuration permissions"),
            NetError::ConfigFormat => f.write_str("configuration format"),
        }
    }
}

impl std::error::Error for NetError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_and_debug_do_not_embed_a_token_url_or_hex() {
        let token = "12345:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let url = "https://api.telegram.org/bot";
        let hex = "aa".repeat(32);
        let variants = [
            NetError::NotAllowed,
            NetError::InvalidInput,
            NetError::Spawn,
            NetError::Transport { exit_code: Some(1) },
            NetError::Transport { exit_code: None },
            NetError::HttpStatus(500),
            NetError::BadResponse,
            NetError::SourcesDisagree,
            NetError::SourceValueMismatch,
            NetError::Rejected("<hex>".to_string()),
            NetError::SubmitTxidMismatch,
            NetError::ConfigPermissions,
            NetError::ConfigFormat,
        ];
        for err in variants {
            let shown = format!("{err:?}{err}");
            assert!(!shown.contains(token), "{shown}");
            assert!(!shown.contains(url), "{shown}");
            assert!(!shown.contains(&hex), "{shown}");
        }
    }
}
