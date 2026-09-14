//! MARA Slipstream private-mempool submission and status.

use bitcoin::hex::DisplayHex;
use serde::Serialize;
use serde_json::Value;

use crate::claim::builder::SignedClaim;
use crate::claim::memory::secure_zero;
use crate::claim::net::allowlist::{self, Method};
use crate::claim::net::error::NetError;
use crate::claim::net::http::Transport;

const RATES_URL: &str = "https://slipstream.mara.com/api/rates";
const SUBMIT_URL: &str = "https://slipstream.mara.com/api/transactions";
const STATUS_URL_PREFIX: &str = "https://slipstream.mara.com/api/transactions/status?tx_id=";
const TIMEOUT_SECS: u64 = 60;
const RATES_TIMEOUT_SECS: u64 = 30;

/// Result of a Slipstream submit call that the service treats as definitive success.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubmitReceipt {
    pub txid: String,
}

/// Outcome of a submit attempt: a definitive rejection versus anything ambiguous.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitError {
    /// HTTP 400 with `status == "error"` or `is_success == false`: Slipstream refused the
    /// transaction.
    Rejected(String),
    /// Transport failure, timeout, unexpected status, malformed 200, or a success naming a
    /// different txid. The marker must stay `pending`.
    Ambiguous(NetError),
}

/// Confirmation status of a previously submitted transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxStatus {
    NotFound,
    Pending,
    Confirmed { block_height: u64 },
}

/// Submits a signed claim exclusively to Slipstream and tracks its confirmation.
pub trait Submitter {
    fn fee_floor_sat_vb(&self) -> Result<u64, NetError>;
    fn submit(&self, claim: &SignedClaim) -> Result<SubmitReceipt, SubmitError>;
    fn status(&self, txid: &str) -> Result<TxStatus, NetError>;
}

/// Production Slipstream client over an injected [`Transport`].
pub struct SlipstreamSubmitter<T: Transport> {
    transport: T,
}

impl<T: Transport> SlipstreamSubmitter<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }
}

#[derive(Serialize)]
struct SubmitBody {
    tx_hex: String,
}

impl<T: Transport> Submitter for SlipstreamSubmitter<T> {
    fn fee_floor_sat_vb(&self) -> Result<u64, NetError> {
        let response = self
            .transport
            .execute(Method::Get, RATES_URL, None, RATES_TIMEOUT_SECS)?;
        if response.status != 200 {
            return Err(NetError::HttpStatus(response.status));
        }
        let value: Value =
            serde_json::from_str(&response.body).map_err(|_| NetError::BadResponse)?;
        let mut floor: Option<u64> = None;
        for key in ["effective_rate", "slipstream_rate", "submit_fee_rate"] {
            if let Some(rate) = json_rate_optional(&value, key)? {
                floor = Some(floor.map_or(rate, |current| current.max(rate)));
            }
        }
        floor.ok_or(NetError::BadResponse)
    }

    fn submit(&self, claim: &SignedClaim) -> Result<SubmitReceipt, SubmitError> {
        let expected_txid = claim.summary().txid.clone();
        let mut hex = claim.raw_tx_bytes_for_submission().to_lower_hex_string();
        let mut body_obj = SubmitBody {
            tx_hex: hex.clone(),
        };
        let mut json = serde_json::to_string(&body_obj)
            .map_err(|_| SubmitError::Ambiguous(NetError::InvalidInput))?;

        let result =
            self.transport
                .execute(Method::PostJson, SUBMIT_URL, Some(&json), TIMEOUT_SECS);

        let mut hex_bytes = std::mem::take(&mut hex).into_bytes();
        secure_zero(&mut hex_bytes);
        let mut tx_hex_copy = std::mem::take(&mut body_obj.tx_hex).into_bytes();
        secure_zero(&mut tx_hex_copy);
        let mut json_bytes = std::mem::take(&mut json).into_bytes();
        secure_zero(&mut json_bytes);

        let response = match result {
            Ok(response) => response,
            Err(err) => return Err(SubmitError::Ambiguous(err)),
        };

        match response.status {
            200 => parse_submit_success(&response.body, &expected_txid),
            400 => parse_submit_rejection(&response.body),
            other => Err(SubmitError::Ambiguous(NetError::HttpStatus(other))),
        }
    }

    fn status(&self, txid: &str) -> Result<TxStatus, NetError> {
        if !allowlist::is_64_lower_hex(txid) {
            return Err(NetError::InvalidInput);
        }
        let url = format!("{STATUS_URL_PREFIX}{txid}");
        let response = self
            .transport
            .execute(Method::Get, &url, None, RATES_TIMEOUT_SECS)?;
        match response.status {
            200 => parse_status_ok(&response.body),
            400 => parse_status_not_found(&response.body),
            other => Err(NetError::HttpStatus(other)),
        }
    }
}

fn json_rate_optional(value: &Value, key: &str) -> Result<Option<u64>, NetError> {
    let Some(raw) = value.get(key) else {
        return Ok(None);
    };
    let number = raw.as_f64().ok_or(NetError::BadResponse)?;
    if !number.is_finite() || number < 0.0 {
        return Err(NetError::BadResponse);
    }
    let ceiled = number.ceil();
    if ceiled > u64::MAX as f64 {
        return Err(NetError::BadResponse);
    }
    Ok(Some(ceiled as u64))
}

fn parse_submit_success(body: &str, expected_txid: &str) -> Result<SubmitReceipt, SubmitError> {
    let value: Value =
        serde_json::from_str(body).map_err(|_| SubmitError::Ambiguous(NetError::BadResponse))?;
    let status = value.get("status").and_then(Value::as_str);
    let message = value.get("message").and_then(Value::as_str);
    match (status, message) {
        (Some("success"), Some(txid)) if txid == expected_txid => Ok(SubmitReceipt {
            txid: txid.to_string(),
        }),
        (Some("success"), Some(_)) => Err(SubmitError::Ambiguous(NetError::SubmitTxidMismatch)),
        _ => Err(SubmitError::Ambiguous(NetError::BadResponse)),
    }
}

fn parse_submit_rejection(body: &str) -> Result<SubmitReceipt, SubmitError> {
    let value: Value =
        serde_json::from_str(body).map_err(|_| SubmitError::Ambiguous(NetError::BadResponse))?;
    let status_error = value.get("status").and_then(Value::as_str) == Some("error");
    let success_false = value.get("is_success").and_then(Value::as_bool) == Some(false);
    if !status_error && !success_false {
        return Err(SubmitError::Ambiguous(NetError::BadResponse));
    }
    let raw = value.get("message").and_then(Value::as_str).unwrap_or("");
    Err(SubmitError::Rejected(sanitize_reject_message(raw)))
}

fn parse_status_ok(body: &str) -> Result<TxStatus, NetError> {
    let value: Value = serde_json::from_str(body).map_err(|_| NetError::BadResponse)?;
    let confirmed = value
        .pointer("/transaction/status/confirmed")
        .and_then(Value::as_bool)
        .ok_or(NetError::BadResponse)?;
    if confirmed {
        let block_height = value
            .pointer("/transaction/status/block_height")
            .and_then(Value::as_u64)
            .ok_or(NetError::BadResponse)?;
        Ok(TxStatus::Confirmed { block_height })
    } else {
        Ok(TxStatus::Pending)
    }
}

fn parse_status_not_found(body: &str) -> Result<TxStatus, NetError> {
    let value: Value = serde_json::from_str(body).map_err(|_| NetError::BadResponse)?;
    if value.get("message").and_then(Value::as_str) == Some("Transaction not found") {
        Ok(TxStatus::NotFound)
    } else {
        Err(NetError::BadResponse)
    }
}

fn sanitize_reject_message(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        if is_hex_digit(bytes[i]) {
            let start = i;
            while i < bytes.len() && is_hex_digit(bytes[i]) {
                i += 1;
            }
            if i - start >= 64 {
                out.push_str("<hex>");
            } else {
                out.push_str(&raw[start..i]);
            }
        } else {
            let ch = raw[i..].chars().next().unwrap_or('\0');
            let len = ch.len_utf8();
            if ch.is_ascii() && !ch.is_ascii_control() {
                out.push(ch);
            }
            i += len;
        }
    }
    if out.len() > 200 {
        out.truncate(200);
    }
    out
}

fn is_hex_digit(b: u8) -> bool {
    matches!(b, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F')
}

#[cfg(test)]
mod tests {
    use super::{
        RATES_URL, STATUS_URL_PREFIX, SUBMIT_URL, SlipstreamSubmitter, SubmitBody, SubmitError,
        Submitter, TxStatus,
    };
    use crate::claim::SignedClaim;
    use crate::claim::net::allowlist::Method;
    use crate::claim::net::error::NetError;
    use crate::claim::net::http::{CurlTransport, HttpResponse, Transport};
    use crate::claim::policy;
    use crate::claim::test_support::{self, TEST_SCALAR};
    use crate::claim::{build_signed_claim, p2pkh_script_for_hash160};
    use bitcoin::address::NetworkUnchecked;
    use bitcoin::hashes::Hash;
    use bitcoin::hex::DisplayHex;
    use bitcoin::{Address, PubkeyHash};
    use std::cell::RefCell;
    use std::str::FromStr;

    struct FakeTransport {
        get: RefCell<Vec<(String, HttpResponse)>>,
        post: RefCell<Option<HttpResponse>>,
        recorded_posts: std::rc::Rc<RefCell<Vec<(String, String)>>>,
    }

    impl FakeTransport {
        fn with_post(response: HttpResponse) -> Self {
            Self {
                get: RefCell::new(Vec::new()),
                post: RefCell::new(Some(response)),
                recorded_posts: std::rc::Rc::new(RefCell::new(Vec::new())),
            }
        }

        fn with_gets(gets: Vec<(String, HttpResponse)>) -> Self {
            Self {
                get: RefCell::new(gets),
                post: RefCell::new(None),
                recorded_posts: std::rc::Rc::new(RefCell::new(Vec::new())),
            }
        }
    }

    impl Transport for FakeTransport {
        fn execute(
            &self,
            method: Method,
            url: &str,
            json_body: Option<&str>,
            _timeout_secs: u64,
        ) -> Result<HttpResponse, NetError> {
            match method {
                Method::Get => {
                    let mut gets = self.get.borrow_mut();
                    if let Some(index) = gets.iter().position(|(u, _)| u == url) {
                        Ok(gets.remove(index).1)
                    } else if let Some((_, response)) = gets.first() {
                        Ok(response.clone())
                    } else {
                        Err(NetError::HttpStatus(404))
                    }
                }
                Method::PostJson => {
                    self.recorded_posts
                        .borrow_mut()
                        .push((url.to_string(), json_body.unwrap_or("").to_string()));
                    self.post
                        .borrow_mut()
                        .take()
                        .ok_or(NetError::HttpStatus(404))
                }
            }
        }
    }

    fn test_claim() -> SignedClaim {
        let key = test_support::test_claim_key();
        let hash160 = test_support::derive_hash160(TEST_SCALAR);
        let prevout = test_support::funded_prevout(hash160, 10_000_000);
        let destination = Address::p2pkh(
            PubkeyHash::from_byte_array([0x44; 20]),
            bitcoin::NetworkKind::Main,
        );
        build_signed_claim(
            &key,
            &[prevout],
            &destination,
            policy::DEFAULT_FEE_RATE_SAT_VB,
        )
        .expect("test claim")
    }

    fn json_ok(body: &str) -> HttpResponse {
        HttpResponse {
            status: 200,
            body: body.to_string(),
        }
    }

    #[test]
    fn submit_body_is_exactly_tx_hex_without_extra_fields() {
        let claim = test_claim();
        let hex = claim.raw_tx_bytes_for_submission().to_lower_hex_string();
        let expected_body = serde_json::to_string(&SubmitBody {
            tx_hex: hex.clone(),
        })
        .unwrap();
        assert_eq!(expected_body, format!(r#"{{"tx_hex":"{hex}"}}"#));
        assert!(!expected_body.contains("skip_mempool"));
        assert!(!expected_body.contains("client_code"));

        let txid = claim.summary().txid.clone();
        let transport = FakeTransport::with_post(json_ok(&format!(
            r#"{{"status":"success","message":"{txid}"}}"#
        )));
        let recorded = transport.recorded_posts.clone();
        let submitter = SlipstreamSubmitter::new(transport);
        submitter.submit(&claim).expect("success");
        let posts = recorded.borrow();
        assert_eq!(posts.len(), 1);
        assert_eq!(posts[0].0, SUBMIT_URL);
        assert_eq!(posts[0].1, expected_body);
    }

    #[test]
    fn submit_success() {
        let claim = test_claim();
        let txid = claim.summary().txid.clone();
        let submitter = SlipstreamSubmitter::new(FakeTransport::with_post(json_ok(&format!(
            r#"{{"status":"success","message":"{txid}"}}"#
        ))));
        let receipt = submitter.submit(&claim).expect("ok");
        assert_eq!(receipt.txid, txid);
    }

    #[test]
    fn submit_200_with_other_txid_is_ambiguous() {
        let claim = test_claim();
        let other = "bb".repeat(32);
        let submitter = SlipstreamSubmitter::new(FakeTransport::with_post(json_ok(&format!(
            r#"{{"status":"success","message":"{other}"}}"#
        ))));
        let err = submitter.submit(&claim).expect_err("wrong txid");
        assert!(matches!(
            err,
            SubmitError::Ambiguous(NetError::SubmitTxidMismatch)
        ));
    }

    #[test]
    fn submit_400_error_sanitises_long_hex_and_truncates() {
        let claim = test_claim();
        let hex64 = "aa".repeat(32);
        let hex66 = "bb".repeat(33);
        let long = format!("boom {hex64} and {hex66} {}", "x".repeat(250));
        let submitter = SlipstreamSubmitter::new(FakeTransport::with_post(HttpResponse {
            status: 400,
            body: format!(r#"{{"status":"error","message":"{long}"}}"#),
        }));
        let err = submitter.submit(&claim).expect_err("rejected");
        let SubmitError::Rejected(msg) = err else {
            panic!("expected Rejected, got {err:?}");
        };
        assert!(msg.contains("<hex>"), "{msg}");
        assert!(!msg.contains(&hex64), "{msg}");
        assert!(!msg.contains(&hex66), "{msg}");
        assert!(msg.len() <= 200, "{msg}");
    }

    #[test]
    fn submit_400_status_fail_or_invalid_json_is_ambiguous() {
        let claim = test_claim();
        let fail = SlipstreamSubmitter::new(FakeTransport::with_post(HttpResponse {
            status: 400,
            body: r#"{"status":"fail","message":"x"}"#.to_string(),
        }));
        let err = fail.submit(&claim).expect_err("status fail");
        assert!(
            matches!(err, SubmitError::Ambiguous(NetError::BadResponse)),
            "{err:?}"
        );

        let invalid = SlipstreamSubmitter::new(FakeTransport::with_post(HttpResponse {
            status: 400,
            body: "not-json".to_string(),
        }));
        let err = invalid.submit(&claim).expect_err("invalid json");
        assert!(
            matches!(err, SubmitError::Ambiguous(NetError::BadResponse)),
            "{err:?}"
        );
    }

    #[test]
    fn submit_400_is_success_false_is_rejected() {
        let claim = test_claim();
        let submitter = SlipstreamSubmitter::new(FakeTransport::with_post(HttpResponse {
            status: 400,
            body: r#"{"is_success":false,"message":"duplicate"}"#.to_string(),
        }));
        let err = submitter.submit(&claim).expect_err("is_success false");
        let SubmitError::Rejected(msg) = err else {
            panic!("expected Rejected, got {err:?}");
        };
        assert_eq!(msg, "duplicate");
    }

    #[test]
    fn submit_500_is_ambiguous() {
        let claim = test_claim();
        let submitter = SlipstreamSubmitter::new(FakeTransport::with_post(HttpResponse {
            status: 500,
            body: "nope".to_string(),
        }));
        let err = submitter.submit(&claim).expect_err("500");
        assert!(matches!(
            err,
            SubmitError::Ambiguous(NetError::HttpStatus(500))
        ));
    }

    fn rates_submitter(body: &str) -> SlipstreamSubmitter<FakeTransport> {
        SlipstreamSubmitter::new(FakeTransport::with_gets(vec![(
            RATES_URL.to_string(),
            json_ok(body),
        )]))
    }

    #[test]
    fn fee_floor_takes_the_max_of_present_valid_fields() {
        let submitter = rates_submitter(
            r#"{"effective_rate":2.2,"slipstream_rate":1.0,"submit_fee_rate":1.5}"#,
        );
        assert_eq!(submitter.fee_floor_sat_vb().expect("floor"), 3);

        let only_effective = rates_submitter(r#"{"effective_rate":2.2}"#);
        assert_eq!(
            only_effective.fee_floor_sat_vb().expect("effective only"),
            3
        );

        let slipstream_highest = rates_submitter(
            r#"{"effective_rate":1.0,"slipstream_rate":5.5,"submit_fee_rate":2.0}"#,
        );
        assert_eq!(
            slipstream_highest
                .fee_floor_sat_vb()
                .expect("slipstream max"),
            6
        );

        let submit_highest = rates_submitter(
            r#"{"effective_rate":1.0,"slipstream_rate":2.0,"submit_fee_rate":9.1}"#,
        );
        assert_eq!(submit_highest.fee_floor_sat_vb().expect("submit max"), 10);

        let none = rates_submitter(r#"{"market_rate":2.0}"#);
        assert_eq!(
            none.fee_floor_sat_vb().expect_err("none present"),
            NetError::BadResponse
        );

        let negative = rates_submitter(
            r#"{"effective_rate":-1.0,"slipstream_rate":1.0,"submit_fee_rate":1.0}"#,
        );
        assert_eq!(
            negative.fee_floor_sat_vb().expect_err("negative"),
            NetError::BadResponse
        );

        let nan = rates_submitter(
            r#"{"effective_rate":"NaN","slipstream_rate":1.0,"submit_fee_rate":1.0}"#,
        );
        assert_eq!(
            nan.fee_floor_sat_vb().expect_err("NaN"),
            NetError::BadResponse
        );

        let overflow = rates_submitter(
            r#"{"effective_rate":1e400,"slipstream_rate":1.0,"submit_fee_rate":1.0}"#,
        );
        assert_eq!(
            overflow.fee_floor_sat_vb().expect_err("1e400"),
            NetError::BadResponse
        );
    }

    const LIVE_CONFIRMED: &str = r#"{"message":"Transaction confirmed in block 785620","market_rate":3.0,"functional_rate":0.0,"last_24h_odds":"0.00","last_7d_odds":"0.00","is_next_block":false,"transaction":{"txid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":3050,"weight":11873,"fee":1000000,"vsize":2969,"status":{"confirmed":true,"block_height":785620,"block_time":1681626588,"block_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"firstSeen":null,"position":null}}"#;

    #[test]
    fn status_parses_the_live_recorded_confirmed_response() {
        let txid = "aa".repeat(32);
        let url = format!("{STATUS_URL_PREFIX}{txid}");
        let submitter = SlipstreamSubmitter::new(FakeTransport::with_gets(vec![(
            url,
            json_ok(LIVE_CONFIRMED),
        )]));
        assert_eq!(
            submitter.status(&txid).expect("confirmed"),
            TxStatus::Confirmed {
                block_height: 785620
            }
        );
    }

    #[test]
    fn status_pending_when_confirmed_is_false() {
        let txid = "aa".repeat(32);
        let body = LIVE_CONFIRMED.replace("\"confirmed\":true", "\"confirmed\":false");
        let submitter = SlipstreamSubmitter::new(FakeTransport::with_gets(vec![(
            format!("{STATUS_URL_PREFIX}{txid}"),
            json_ok(&body),
        )]));
        assert_eq!(submitter.status(&txid).expect("pending"), TxStatus::Pending);
    }

    #[test]
    fn status_not_found_on_live_400_shape() {
        let txid = "aa".repeat(32);
        let submitter = SlipstreamSubmitter::new(FakeTransport::with_gets(vec![(
            format!("{STATUS_URL_PREFIX}{txid}"),
            HttpResponse {
                status: 400,
                body: r#"{"is_success":false,"message":"Transaction not found"}"#.to_string(),
            },
        )]));
        assert_eq!(
            submitter.status(&txid).expect("not found"),
            TxStatus::NotFound
        );
    }

    #[test]
    fn status_400_rate_limited_is_bad_response_not_not_found() {
        let txid = "aa".repeat(32);
        let submitter = SlipstreamSubmitter::new(FakeTransport::with_gets(vec![(
            format!("{STATUS_URL_PREFIX}{txid}"),
            HttpResponse {
                status: 400,
                body: r#"{"is_success":false,"message":"rate limited"}"#.to_string(),
            },
        )]));
        assert_eq!(
            submitter.status(&txid).expect_err("rate limited"),
            NetError::BadResponse
        );
    }

    #[test]
    fn status_rejects_invalid_txid() {
        let submitter = SlipstreamSubmitter::new(FakeTransport::with_gets(vec![]));
        assert_eq!(
            submitter.status("GGG").expect_err("invalid"),
            NetError::InvalidInput
        );
        assert_eq!(
            submitter.status(&"AA".repeat(32)).expect_err("uppercase"),
            NetError::InvalidInput
        );
    }

    #[test]
    #[ignore = "live network"]
    fn live_slipstream_fee_floor_at_least_one() {
        let submitter = SlipstreamSubmitter::new(CurlTransport);
        let floor = submitter.fee_floor_sat_vb().expect("live GET /api/rates");
        assert!(floor >= 1, "floor was {floor}");
    }

    #[test]
    #[ignore = "live network"]
    fn live_submit_of_an_unspendable_claim_is_rejected() {
        // Safe on mainnet: both inputs come from self-built funding transactions whose
        // txids do not exist there, so this signed transaction can never become valid
        // and can never move real coins.
        let key = test_support::test_claim_key();
        let hash160 = test_support::derive_hash160(TEST_SCALAR);
        let prevouts = [
            test_support::funded_prevout(hash160, 1_000_000),
            test_support::funded_prevout(hash160, 2_000_000),
        ];
        let destination =
            Address::<NetworkUnchecked>::from_str("bc1qvzvkjn4q3nszqxrv3nraga2r822xjty3ykvkuw")
                .expect("fixed mainnet bech32")
                .require_network(bitcoin::Network::Bitcoin)
                .expect("mainnet");
        let claim = build_signed_claim(
            &key,
            &prevouts,
            &destination,
            policy::DEFAULT_FEE_RATE_SAT_VB,
        )
        .expect("unspendable test claim");

        let submitter = SlipstreamSubmitter::new(CurlTransport);
        match submitter.submit(&claim) {
            Err(SubmitError::Rejected(msg)) => {
                println!("rejected: {msg}");
            }
            other => panic!("expected Rejected, got {other:?}"),
        }

        const UNKNOWN_TXID: &str =
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        assert_eq!(
            submitter
                .status(UNKNOWN_TXID)
                .expect("live status of unknown txid"),
            TxStatus::NotFound
        );
    }

    #[test]
    fn puzzle_script_is_not_the_test_destination() {
        // Guard: the fixture destination used above must not equal the puzzle script.
        let puzzle = p2pkh_script_for_hash160(crate::puzzle_config::TARGET_HASH160);
        let dest = Address::p2pkh(
            PubkeyHash::from_byte_array([0x44; 20]),
            bitcoin::NetworkKind::Main,
        );
        assert_ne!(dest.script_pubkey().as_script(), puzzle.as_script());
    }
}
