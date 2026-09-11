//! Exact-match allowlist for every network request the claim pipeline may make.
//!
//! URLs are parsed by hand. Prefix comparison is deliberately not used: a host such as
//! `slipstream.mara.com.evil.example` must not inherit permission from `slipstream.mara.com`.

use crate::puzzle_config::TARGET_ADDRESS;

/// HTTP methods the claim pipeline is willing to issue. `PostJson` is a POST with a JSON body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    PostJson,
}

const MEMPOOL: &str = "mempool.space";
const BLOCKSTREAM: &str = "blockstream.info";
const SLIPSTREAM: &str = "slipstream.mara.com";
const TELEGRAM: &str = "api.telegram.org";

/// Returns whether `(method, url)` is one of the exact permitted forms.
///
/// Anything else is `false`, including `http://`, a non-default port, userinfo, a fragment,
/// extra query parameters, percent-encoding, glob characters, `..`, or an uppercase host.
pub fn is_allowed(method: Method, url: &str) -> bool {
    if !url.is_ascii() {
        return false;
    }
    if url.as_bytes().iter().any(|b| {
        matches!(
            *b,
            b'{' | b'}' | b'[' | b']' | b'%' | b'#' | b'\0'..=b'\x1f' | b'\x7f'
        )
    }) {
        return false;
    }
    if url.contains("..") {
        return false;
    }
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let Some(slash) = rest.find('/') else {
        return false;
    };
    let host = &rest[..slash];
    let path_and_query = &rest[slash..];
    if host.contains('@') || host.contains(':') {
        return false;
    }
    if host.bytes().any(|b| b.is_ascii_uppercase()) {
        return false;
    }

    match method {
        Method::Get => {
            is_utxo_get(host, path_and_query)
                || is_tx_hex_get(host, path_and_query)
                || is_rates_get(host, path_and_query)
                || is_status_get(host, path_and_query)
        }
        Method::PostJson => {
            is_slipstream_submit(host, path_and_query) || is_telegram_send(host, path_and_query)
        }
    }
}

fn is_esplora_host(host: &str) -> bool {
    host == MEMPOOL || host == BLOCKSTREAM
}

fn is_utxo_get(host: &str, path_and_query: &str) -> bool {
    if !is_esplora_host(host) {
        return false;
    }
    let expected = format!("/api/address/{TARGET_ADDRESS}/utxo");
    path_and_query == expected
}

fn is_tx_hex_get(host: &str, path_and_query: &str) -> bool {
    if !is_esplora_host(host) {
        return false;
    }
    let Some(txid) = path_and_query
        .strip_prefix("/api/tx/")
        .and_then(|rest| rest.strip_suffix("/hex"))
    else {
        return false;
    };
    is_64_lower_hex(txid)
}

fn is_rates_get(host: &str, path_and_query: &str) -> bool {
    host == SLIPSTREAM && path_and_query == "/api/rates"
}

fn is_status_get(host: &str, path_and_query: &str) -> bool {
    if host != SLIPSTREAM {
        return false;
    }
    let Some(txid) = path_and_query.strip_prefix("/api/transactions/status?tx_id=") else {
        return false;
    };
    is_64_lower_hex(txid)
}

fn is_slipstream_submit(host: &str, path_and_query: &str) -> bool {
    host == SLIPSTREAM && path_and_query == "/api/transactions"
}

fn is_telegram_send(host: &str, path_and_query: &str) -> bool {
    if host != TELEGRAM {
        return false;
    }
    let Some(token) = path_and_query
        .strip_prefix("/bot")
        .and_then(|rest| rest.strip_suffix("/sendMessage"))
    else {
        return false;
    };
    is_bot_token(token)
}

pub(crate) fn is_64_lower_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub(crate) fn is_bot_token(s: &str) -> bool {
    let Some((id, secret)) = s.split_once(':') else {
        return false;
    };
    (5..=15).contains(&id.len())
        && id.bytes().all(|b| b.is_ascii_digit())
        && (30..=50).contains(&secret.len())
        && secret
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

pub(crate) fn is_private_chat_id(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() > 20 {
        return false;
    }
    bytes[0] >= b'1' && bytes[0] <= b'9' && bytes[1..].iter().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::{BLOCKSTREAM, MEMPOOL, Method, is_allowed, is_bot_token};
    use crate::puzzle_config::TARGET_ADDRESS;

    const TXID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const TOKEN: &str = "12345:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn utxo(host: &str) -> String {
        format!("https://{host}/api/address/{TARGET_ADDRESS}/utxo")
    }

    fn tx_hex(host: &str, txid: &str) -> String {
        format!("https://{host}/api/tx/{txid}/hex")
    }

    #[test]
    fn accepts_every_permitted_form() {
        let allowed = [
            (Method::Get, utxo(MEMPOOL)),
            (Method::Get, utxo(BLOCKSTREAM)),
            (Method::Get, tx_hex(MEMPOOL, TXID)),
            (Method::Get, tx_hex(BLOCKSTREAM, TXID)),
            (
                Method::Get,
                "https://slipstream.mara.com/api/rates".to_string(),
            ),
            (
                Method::Get,
                format!("https://slipstream.mara.com/api/transactions/status?tx_id={TXID}"),
            ),
            (
                Method::PostJson,
                "https://slipstream.mara.com/api/transactions".to_string(),
            ),
            (
                Method::PostJson,
                format!("https://api.telegram.org/bot{TOKEN}/sendMessage"),
            ),
        ];
        for (method, url) in allowed {
            assert!(is_allowed(method, &url), "expected allow: {url}");
        }
    }

    #[test]
    fn rejects_public_broadcast_and_lookalike_urls() {
        let rejected: &[(Method, &str)] = &[
            (Method::PostJson, "https://mempool.space/api/tx"),
            (Method::PostJson, "https://blockstream.info/api/tx"),
            (
                Method::PostJson,
                "http://slipstream.mara.com/api/transactions",
            ),
            (
                Method::PostJson,
                "https://slipstream.mara.com.evil.example/api/transactions",
            ),
            (Method::Get, "https://slipstream.mara.com:444/api/rates"),
            (Method::Get, "https://user@slipstream.mara.com/api/rates"),
            (
                Method::PostJson,
                "https://slipstream.mara.com/api/transactions?skip_mempool_submission=true",
            ),
            (
                Method::Get,
                "https://mempool.space/api/tx/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/hex",
            ),
            (
                Method::Get,
                "https://mempool.space/api/tx/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/hex",
            ),
            (
                Method::Get,
                "https://mempool.space/api/address/1DifferentAddressXXXXXXXXXXXXXXXXxxx/utxo",
            ),
            (
                Method::Get,
                "https://MEMPOOL.SPACE/api/address/1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU/utxo",
            ),
            (Method::Get, "https://mempool.space/api/tx/%2e%2e/hex"),
            (Method::Get, "https://slipstream.mara.com/api/{rates}"),
            (
                Method::PostJson,
                "https://api.telegram.org/bot12345:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/getMe",
            ),
            (
                Method::Get,
                "https://api.telegram.org/bot12345:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/sendMessage",
            ),
        ];
        for (method, url) in rejected {
            assert!(!is_allowed(*method, url), "expected deny: {url}");
        }
    }

    #[test]
    fn rejects_suffix_lookalike_hosts() {
        let rejected = [
            (
                Method::Get,
                format!("https://evilmempool.space/api/address/{TARGET_ADDRESS}/utxo"),
            ),
            (Method::Get, tx_hex("xblockstream.info", TXID)),
            (
                Method::PostJson,
                "https://evilslipstream.mara.com/api/transactions".to_string(),
            ),
            (
                Method::PostJson,
                format!("https://evilapi.telegram.org/bot{TOKEN}/sendMessage"),
            ),
        ];
        for (method, url) in &rejected {
            assert!(!is_allowed(*method, url), "expected deny: {url}");
        }
    }

    #[test]
    fn rejects_foreign_puzzle_address_on_the_utxo_path() {
        let url = format!("https://mempool.space/api/address/{TARGET_ADDRESS}x/utxo");
        assert!(!is_allowed(Method::Get, &url));
        let prefix = format!(
            "https://mempool.space/api/address/{}/utxo",
            &TARGET_ADDRESS[..10]
        );
        assert!(!is_allowed(Method::Get, &prefix));
    }

    #[test]
    fn bot_token_bounds() {
        assert!(is_bot_token(TOKEN));
        assert!(!is_bot_token("1234:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
        assert!(!is_bot_token("12345:AAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
        assert!(!is_bot_token("12345:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/"));
    }
}
